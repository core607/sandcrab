//! A protected one-use Unix channel transfers a private-namespace TCP listener.
//! Only the trusted root launcher uses it, before credential drop and seccomp.
use crate::config::invalid;
use rustix::{
    fd::{AsFd, AsRawFd, OwnedFd},
    fs::{Mode, OFlags, open},
    net::{
        RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
        SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
    },
};
use std::{
    io::{self, IoSlice, IoSliceMut, Read},
    mem::MaybeUninit,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    time::Duration,
};

pub const PORT: u16 = 18080;
const PACKET: &[u8] = b"sandcrab-egress-v1";
pub const SOCKET: &str = "network.sock";

pub fn socket_path(root: &Path) -> io::Result<(OwnedFd, PathBuf)> {
    sandcrab_core::fs::protected_directory(root)?;
    let directory = open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    // sockaddr_un must fit even when the operator's runtime path is long. The
    // descriptor pins this protected directory through bind/connect, then closes.
    let path = PathBuf::from(format!("/proc/self/fd/{}/{SOCKET}", directory.as_raw_fd()));
    Ok((directory, path))
}

pub fn export(root: &Path) -> io::Result<()> {
    let (directory, path) = socket_path(root)?;
    let mut control = UnixStream::connect(path)?;
    drop(directory);
    control.set_read_timeout(Some(Duration::from_secs(5)))?;
    control.set_write_timeout(Some(Duration::from_secs(5)))?;
    if !rustix::net::sockopt::socket_peercred(&control)?
        .uid
        .is_root()
    {
        return Err(invalid("Proxy bridge peer is not root"));
    }
    let original = std::fs::read_link("/proc/self/ns/net")?;
    sandcrab_core::process::private_network_namespace()?;
    if std::fs::read_link("/proc/self/ns/net")? == original {
        return Err(invalid("Proxy network namespace was not isolated"));
    }
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, PORT))?;
    listener.set_nonblocking(true)?;
    let fds = [listener.as_fd()];
    let mut buffer = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut buffer);
    if !ancillary.push(SendAncillaryMessage::ScmRights(&fds)) {
        return Err(invalid("Proxy descriptor buffer is too small"));
    }
    if sendmsg(
        &control,
        &[IoSlice::new(PACKET)],
        &mut ancillary,
        SendFlags::NOSIGNAL,
    )? != PACKET.len()
    {
        return Err(invalid("Incomplete proxy descriptor publication"));
    }
    let mut ack = [0];
    control.read_exact(&mut ack)?;
    if ack != *b"x" {
        return Err(invalid("Proxy listener was not acknowledged"));
    }
    // Both descriptors close here. The workload inherits only its network
    // namespace; neither the host channel nor listener reaches untrusted code.
    Ok(())
}

pub fn receive(control: &UnixStream) -> io::Result<TcpListener> {
    if !rustix::net::sockopt::socket_peercred(control)?
        .uid
        .is_root()
    {
        return Err(invalid("Proxy bridge peer is not root"));
    }
    let mut packet = [0; 64];
    let mut buffer = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut buffer);
    let result = recvmsg(
        control,
        &mut [IoSliceMut::new(&mut packet)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )?;
    if result
        .flags
        .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || result.bytes != PACKET.len()
        || &packet[..result.bytes] != PACKET
    {
        return Err(invalid("Invalid proxy listener packet"));
    }
    let mut received = None;
    for message in ancillary.drain() {
        let RecvAncillaryMessage::ScmRights(fds) = message else {
            return Err(invalid("Unexpected proxy control message"));
        };
        for fd in fds {
            if received.replace(fd).is_some() {
                return Err(invalid("Unexpected extra proxy descriptor"));
            }
        }
    }
    let fd = received.ok_or_else(|| invalid("Missing proxy listener descriptor"))?;
    if rustix::net::sockopt::socket_type(&fd)? != rustix::net::SocketType::STREAM
        || !rustix::net::sockopt::socket_acceptconn(&fd)?
    {
        return Err(invalid("Exported proxy descriptor is not a listener"));
    }
    let listener = TcpListener::from(fd);
    if listener.local_addr()? != SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, PORT)) {
        return Err(invalid("Exported proxy listener has the wrong address"));
    }
    listener.set_nonblocking(true)?;
    Ok(listener)
}
