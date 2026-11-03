use super::{io::Deadline, policy};
use crate::config::invalid;
use std::{io, net::TcpStream};

#[derive(Clone, Copy)]
pub enum Protocol {
    Connect,
    Socks5,
}

pub struct Request {
    pub name: String,
    pub port: u16,
}

fn authority(value: &str) -> io::Result<Request> {
    let (name, port) = value
        .rsplit_once(':')
        .ok_or_else(|| invalid("PROXY_INVALID_AUTHORITY"))?;
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("PROXY_INVALID_PORT"));
    }
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| invalid("PROXY_INVALID_PORT"))?;
    Ok(Request {
        name: policy::domain(name)?,
        port,
    })
}

fn http(header: &[u8]) -> io::Result<Request> {
    let header = std::str::from_utf8(header).map_err(|_| invalid("PROXY_INVALID_HEADER"))?;
    let mut lines = header
        .strip_suffix("\r\n\r\n")
        .ok_or_else(|| invalid("PROXY_INVALID_HEADER"))?
        .split("\r\n");
    let first: Vec<_> = lines.next().unwrap_or("").split(' ').collect();
    if first.len() != 3 || first[0] != "CONNECT" || !["HTTP/1.0", "HTTP/1.1"].contains(&first[2]) {
        return Err(invalid("PROXY_CONNECT_REQUIRED"));
    }
    let request = authority(first[1])?;
    let mut host_seen = false;
    let mut length_seen = false;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("PROXY_INVALID_HEADER"))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || value.bytes().any(|b| b < 32 && b != b'\t' || b == 127)
        {
            return Err(invalid("PROXY_INVALID_HEADER"));
        }
        if name.eq_ignore_ascii_case("host") {
            if host_seen {
                return Err(invalid("PROXY_INVALID_HEADER"));
            }
            host_seen = true;
            let host = authority(value.trim())?;
            if host.name != request.name || host.port != request.port {
                return Err(invalid("PROXY_HOST_MISMATCH"));
            }
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(invalid("PROXY_BODY_DENIED"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length_seen || value.trim() != "0" {
                return Err(invalid("PROXY_BODY_DENIED"));
            }
            length_seen = true;
        }
    }
    Ok(request)
}

impl Protocol {
    pub fn name(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Socks5 => "socks5",
        }
    }

    pub fn request(
        self,
        first: u8,
        stream: &mut TcpStream,
        deadline: &Deadline<'_>,
    ) -> io::Result<Request> {
        match self {
            Self::Connect => {
                let mut header = vec![first];
                while !header.ends_with(b"\r\n\r\n") {
                    if header.len() == 8192 {
                        return Err(invalid("PROXY_HEADER_LIMIT"));
                    }
                    let mut byte = [0];
                    deadline.read(stream, &mut byte)?;
                    header.push(byte[0]);
                }
                http(&header)
            }
            Self::Socks5 => {
                let mut count = [0];
                deadline.read(stream, &mut count)?;
                if !(1..=16).contains(&count[0]) {
                    return Err(invalid("PROXY_INVALID_METHODS"));
                }
                let mut methods = [0; 16];
                deadline.read(stream, &mut methods[..count[0] as usize])?;
                if !methods[..count[0] as usize].contains(&0) {
                    deadline.write(stream, &[5, 255])?;
                    return Err(invalid("PROXY_NO_AUTH_METHOD"));
                }
                deadline.write(stream, &[5, 0])?;
                let mut header = [0; 5];
                deadline.read(stream, &mut header[..4])?;
                if header[..4] != [5, 1, 0, 3] {
                    return Err(invalid("PROXY_DOMAIN_CONNECT_REQUIRED"));
                }
                deadline.read(stream, &mut header[4..])?;
                if !(1..=253).contains(&header[4]) {
                    return Err(invalid("PROXY_INVALID_DOMAIN"));
                }
                let mut name = vec![0; header[4] as usize];
                deadline.read(stream, &mut name)?;
                let name = policy::domain(
                    std::str::from_utf8(&name).map_err(|_| invalid("PROXY_INVALID_DOMAIN"))?,
                )?;
                let mut port = [0; 2];
                deadline.read(stream, &mut port)?;
                let port = u16::from_be_bytes(port);
                if port == 0 {
                    return Err(invalid("PROXY_INVALID_PORT"));
                }
                Ok(Request { name, port })
            }
        }
    }

    pub fn respond(
        self,
        stream: &mut TcpStream,
        deadline: &Deadline<'_>,
        status: u16,
    ) -> io::Result<()> {
        match self {
            Self::Connect => {
                let response: &[u8] = if status == 200 {
                    b"HTTP/1.1 200 Connection Established\r\n\r\n"
                } else if status == 403 {
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else if status == 400 {
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else {
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                };
                deadline.write(stream, response)
            }
            Self::Socks5 => deadline.write(
                stream,
                &[
                    5,
                    if status == 200 {
                        0
                    } else if status == 403 {
                        2
                    } else {
                        1
                    },
                    0,
                    1,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_accepts_one_authority_and_refuses_smuggling_and_direct_ips() {
        let parsed = http(b"CONNECT PyPI.org:443 HTTP/1.1\r\nHost: pypi.org:443\r\n\r\n").unwrap();
        assert_eq!((parsed.name.as_str(), parsed.port), ("pypi.org", 443));
        for bad in [
            "CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n",
            "CONNECT pypi.org:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n",
            "CONNECT pypi.org:443 HTTP/1.1\r\nHost: pypi.org:443\r\nHost: pypi.org:443\r\n\r\n",
            "CONNECT pypi.org:443 HTTP/1.1\r\nContent-Length: 2\r\n\r\n",
            "CONNECT pypi.org:443 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "CONNECT pypi.org:443 HTTP/1.1\r\n x: y\r\n\r\n",
            "CONNECT pypi.org:0 HTTP/1.1\r\n\r\n",
            "GET http://pypi.org/ HTTP/1.1\r\n\r\n",
        ] {
            assert!(http(bad.as_bytes()).is_err(), "accepted {bad:?}");
        }
    }
}
