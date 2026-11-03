//! A bounded stub query against the host's recursive DNS servers. Packet/name
//! parsing belongs to the DNS library; socket deadlines and cancellation stay
//! here instead of entering uncancellable NSS/getaddrinfo worker threads.
use super::{io::Deadline, policy};
use crate::config::invalid;
use ::domain::{
    base::{
        Message, MessageBuilder, Name, Rtype,
        iana::{Class, Rcode},
    },
    rdata::AllRecordData,
};
use rustix::event::PollFlags;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, Read},
    net::{IpAddr, SocketAddr, UdpSocket},
    str::FromStr,
    time::{Duration, Instant},
};

const MAX_PACKET: usize = 16384;

pub fn servers() -> io::Result<Vec<SocketAddr>> {
    let mut text = String::new();
    File::open("/etc/resolv.conf")?
        .take(16385)
        .read_to_string(&mut text)?;
    if text.len() > 16384 {
        return Err(invalid("Resolver configuration exceeds 16 KiB"));
    }
    let mut servers = Vec::new();
    for line in text.lines() {
        let mut words = line
            .split(['#', ';'])
            .next()
            .unwrap_or("")
            .split_whitespace();
        if words.next() == Some("nameserver") {
            let address = words
                .next()
                .and_then(|s| s.parse::<IpAddr>().ok())
                .ok_or_else(|| invalid("Proxy DNS needs literal IPv4/IPv6 nameservers"))?;
            let server = SocketAddr::new(address, 53);
            if !servers.contains(&server) && servers.len() < 3 {
                servers.push(server);
            }
        }
    }
    if servers.is_empty() {
        return Err(invalid("Proxy DNS needs a nameserver in /etc/resolv.conf"));
    }
    Ok(servers)
}

fn query(name: &str, kind: Rtype) -> io::Result<Vec<u8>> {
    let mut message = MessageBuilder::from_target(Vec::new()).map_err(io::Error::other)?;
    let random = sandcrab_core::new_uuid()?;
    message
        .header_mut()
        .set_id(u16::from_str_radix(&random[..4], 16).map_err(io::Error::other)?);
    message.header_mut().set_rd(true);
    let mut question = message.question();
    question
        .push((
            Name::<Vec<u8>>::from_str(&format!("{name}.")).map_err(io::Error::other)?,
            kind,
        ))
        .map_err(io::Error::other)?;
    Ok(question.finish())
}

fn response(packet: &[u8], query: &[u8]) -> io::Result<bool> {
    let query = Message::from_slice(query).map_err(io::Error::other)?;
    let response = Message::from_slice(packet).map_err(io::Error::other)?;
    if !response.is_answer(query) || response.header().opcode() != query.header().opcode() {
        return Err(invalid("PROXY_DNS_MISMATCH"));
    }
    Ok(response.header().tc())
}

fn exchange(server: SocketAddr, query: &[u8], deadline: &Deadline<'_>) -> io::Result<Vec<u8>> {
    let socket = UdpSocket::bind(if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    socket.set_nonblocking(true)?;
    socket.connect(server)?;
    if socket.send(query)? != query.len() {
        return Err(invalid("PROXY_DNS_WRITE"));
    }
    let mut packet = vec![0; MAX_PACKET + 1];
    loop {
        deadline.check()?;
        match socket.recv(&mut packet) {
            Ok(size) => {
                if size > MAX_PACKET {
                    return Err(invalid("PROXY_DNS_TOO_LARGE"));
                }
                packet.truncate(size);
                if response(&packet, query)? {
                    break;
                }
                return Ok(packet);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                deadline.wait(&socket, PollFlags::IN)?
            }
            Err(error) => return Err(error),
        }
    }
    let mut stream = deadline.connect(server)?;
    deadline.write(&mut stream, &(query.len() as u16).to_be_bytes())?;
    deadline.write(&mut stream, query)?;
    let mut length = [0; 2];
    deadline.read(&mut stream, &mut length)?;
    let size = u16::from_be_bytes(length) as usize;
    if !(12..=MAX_PACKET).contains(&size) {
        return Err(invalid("PROXY_DNS_TOO_LARGE"));
    }
    packet.resize(size, 0);
    deadline.read(&mut stream, &mut packet)?;
    if response(&packet, query)? {
        return Err(invalid("PROXY_DNS_TRUNCATED"));
    }
    Ok(packet)
}

fn addresses(packet: &[u8], kind: Rtype) -> io::Result<(String, Vec<IpAddr>)> {
    let message = Message::from_slice(packet).map_err(io::Error::other)?;
    let counts = message.header_counts();
    if u32::from(counts.ancount()) + u32::from(counts.nscount()) + u32::from(counts.arcount()) > 256
    {
        return Err(invalid("PROXY_DNS_TOO_LARGE"));
    }
    if message.header().rcode() == Rcode::NXDOMAIN {
        return Ok((String::new(), Vec::new()));
    }
    if message.header().rcode() != Rcode::NOERROR {
        return Err(invalid("PROXY_DNS_ERROR"));
    }
    let canonical = message
        .canonical_name()
        .ok_or_else(|| invalid("PROXY_DNS_ALIAS"))?;
    let mut addresses = BTreeSet::new();
    for record in message
        .answer()
        .map_err(io::Error::other)?
        .limit_to::<AllRecordData<_, _>>()
    {
        let record = record.map_err(io::Error::other)?;
        if record.class() != Class::IN || record.owner() != &canonical {
            continue;
        }
        let address = match record.data() {
            AllRecordData::A(data) if kind == Rtype::A => Some(IpAddr::V4(data.addr())),
            AllRecordData::Aaaa(data) if kind == Rtype::AAAA => Some(IpAddr::V6(data.addr())),
            _ => None,
        };
        if let Some(address) = address {
            if !policy::public_address(address) {
                return Err(invalid("PROXY_ADDRESS_DENIED"));
            }
            addresses.insert(address);
            if addresses.len() > 16 {
                return Err(invalid("PROXY_DNS_TOO_LARGE"));
            }
        }
    }
    Ok((
        canonical
            .to_string()
            .trim_end_matches('.')
            .to_ascii_lowercase(),
        addresses.into_iter().collect(),
    ))
}

fn resolve_kind(
    servers: &[SocketAddr],
    name: &str,
    kind: Rtype,
    deadline: &Deadline<'_>,
) -> io::Result<Vec<IpAddr>> {
    let mut name = name.to_owned();
    let mut visited = BTreeSet::new();
    for _ in 0..8 {
        deadline.check()?;
        if !visited.insert(name.clone()) {
            return Err(invalid("PROXY_DNS_ALIAS"));
        }
        let query = query(&name, kind)?;
        let mut result = Err(invalid("PROXY_DNS_UNAVAILABLE"));
        for server in servers {
            let attempt = Deadline {
                stopped: deadline.stopped,
                at: deadline.at.min(Instant::now() + Duration::from_secs(1)),
            };
            result = exchange(*server, &query, &attempt);
            if result.is_ok() {
                break;
            }
            deadline.check()?;
        }
        let (canonical, addresses) = addresses(&result?, kind)?;
        if !addresses.is_empty() || canonical.is_empty() || canonical == name {
            return Ok(addresses);
        }
        name = policy::domain(&canonical)?;
    }
    Err(invalid("PROXY_DNS_ALIAS"))
}

pub fn resolve(
    servers: &[SocketAddr],
    name: &str,
    deadline: &Deadline<'_>,
) -> io::Result<Vec<IpAddr>> {
    let mut addresses = resolve_kind(servers, name, Rtype::A, deadline)?;
    addresses.extend(resolve_kind(servers, name, Rtype::AAAA, deadline)?);
    if addresses.is_empty() {
        return Err(invalid("PROXY_DNS_NO_ADDRESS"));
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::domain::rdata::{A, Cname};

    fn reply(address: &str, alias: bool) -> Vec<u8> {
        let mut builder = MessageBuilder::from_target(Vec::new()).unwrap();
        builder.header_mut().set_qr(true);
        let name = Name::<Vec<u8>>::from_str("allowed.example.").unwrap();
        let canonical = Name::<Vec<u8>>::from_str("cdn.example.").unwrap();
        let mut question = builder.question();
        question.push((name.clone(), Rtype::A)).unwrap();
        let mut answer = question.answer();
        if alias {
            answer
                .push((name.clone(), Class::IN, 60, Cname::new(canonical.clone())))
                .unwrap();
        }
        answer
            .push((
                if alias { canonical } else { name },
                Class::IN,
                60,
                A::new(address.parse().unwrap()),
            ))
            .unwrap();
        answer.finish()
    }

    #[test]
    fn dns_answers_follow_bounded_aliases_and_filter_the_resolved_address() {
        for alias in [false, true] {
            assert_eq!(
                addresses(&reply("1.1.1.1", alias), Rtype::A).unwrap().1,
                vec!["1.1.1.1".parse::<IpAddr>().unwrap()]
            );
            assert!(addresses(&reply("169.254.169.254", alias), Rtype::A).is_err());
        }
        let query = query("allowed.example", Rtype::A).unwrap();
        let mut reply = reply("1.1.1.1", false);
        reply[..2].copy_from_slice(&query[..2]);
        assert!(!response(&reply, &query).unwrap());
        reply[0] ^= 1;
        assert!(response(&reply, &query).is_err());
    }
}
