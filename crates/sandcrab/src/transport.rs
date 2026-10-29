//! Native local transports share framing, deadlines and admission. TCP authenticates
//! each request; Unix sockets authenticate the operating-system peer.
use crate::config::invalid;
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    os::unix::net::UnixStream,
    time::Duration,
};

pub fn local_address(text: &str) -> io::Result<SocketAddr> {
    text.parse::<SocketAddr>()
        .ok()
        .filter(|address| address.ip().is_loopback() && address.port() != 0)
        .ok_or_else(|| invalid("TCP requires a literal loopback IP address and a nonzero port"))
}

pub enum Stream {
    Unix(UnixStream),
    Tcp(TcpStream),
}
impl Stream {
    pub fn set_read_timeout(&self, value: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Unix(s) => s.set_read_timeout(value),
            Self::Tcp(s) => s.set_read_timeout(value),
        }
    }
    pub fn set_write_timeout(&self, value: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Unix(s) => s.set_write_timeout(value),
            Self::Tcp(s) => s.set_write_timeout(value),
        }
    }
    pub fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Unix(s) => s.try_clone().map(Self::Unix),
            Self::Tcp(s) => s.try_clone().map(Self::Tcp),
        }
    }
    pub fn tcp(&self) -> bool {
        matches!(self, Self::Tcp(_))
    }
}
impl Read for &Stream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Unix(s) => (&*s).read(bytes),
            Stream::Tcp(s) => (&*s).read(bytes),
        }
    }
}
impl Write for &Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Unix(s) => (&*s).write(bytes),
            Stream::Tcp(s) => (&*s).write(bytes),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Unix(s) => (&*s).flush(),
            Stream::Tcp(s) => (&*s).flush(),
        }
    }
}
impl Read for Stream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        (&*self).read(bytes)
    }
}
impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        (&*self).write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        (&*self).flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_addresses_never_resolve_dns_or_bind_other_interfaces() {
        for value in ["127.0.0.1:8123", "[::1]:8123"] {
            assert!(local_address(value).is_ok());
        }
        for value in [
            "0.0.0.0:8123",
            "[::]:8123",
            "[::ffff:127.0.0.1]:8123",
            "192.0.2.1:8123",
            "localhost:8123",
            "127.0.0.1:0",
            "http://127.0.0.1:8123",
            "127.0.0.1:8123/path",
        ] {
            assert!(local_address(value).is_err(), "{value}");
        }
    }
}
