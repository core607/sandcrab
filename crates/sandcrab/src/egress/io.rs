use crate::config::invalid;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use std::{
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    os::fd::AsFd,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

pub const TICK: Duration = Duration::from_millis(50);

pub struct Deadline<'a> {
    pub stopped: &'a AtomicBool,
    pub at: Instant,
}
impl Deadline<'_> {
    pub fn check(&self) -> io::Result<()> {
        if self.stopped.load(Ordering::SeqCst) {
            return Err(invalid("PROXY_CANCELLED"));
        }
        if Instant::now() >= self.at {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "PROXY_TIMEOUT"));
        }
        Ok(())
    }

    pub fn wait(&self, fd: &impl AsFd, flags: PollFlags) -> io::Result<()> {
        self.check()?;
        let wait = TICK.min(self.at.saturating_duration_since(Instant::now()));
        let timeout = Timespec::try_from(wait).map_err(io::Error::other)?;
        match poll(&mut [PollFd::new(fd, flags)], Some(&timeout)) {
            Err(error) if error == rustix::io::Errno::INTR => Ok(()),
            result => result.map(|_| ()).map_err(Into::into),
        }
    }

    pub fn read(&self, stream: &mut (impl Read + AsFd), mut bytes: &mut [u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            self.check()?;
            match stream.read(bytes) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "PROXY_EOF")),
                Ok(size) => bytes = &mut bytes[size..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait(stream, PollFlags::IN)?
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    pub fn write(&self, stream: &mut (impl Write + AsFd), mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            self.check()?;
            match stream.write(bytes) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "PROXY_WRITE_ZERO")),
                Ok(size) => bytes = &bytes[size..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait(stream, PollFlags::OUT)?
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    pub fn connect(&self, address: SocketAddr) -> io::Result<TcpStream> {
        self.check()?;
        let socket = rustix::net::socket_with(
            if address.is_ipv4() {
                rustix::net::AddressFamily::INET
            } else {
                rustix::net::AddressFamily::INET6
            },
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
            None,
        )?;
        let result = rustix::net::connect(&socket, &address);
        if let Err(error) = result
            && error != rustix::io::Errno::INPROGRESS
        {
            return Err(error.into());
        }
        let stream = TcpStream::from(socket);
        loop {
            self.check()?;
            if let Some(error) = stream.take_error()? {
                return Err(error);
            }
            if stream.peer_addr().is_ok() {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            self.wait(&stream, PollFlags::OUT)?;
        }
    }
}

struct Buffer {
    bytes: [u8; 16384],
    start: usize,
    end: usize,
    eof: bool,
    shut: bool,
}
impl Buffer {
    fn new() -> Self {
        Self {
            bytes: [0; 16384],
            start: 0,
            end: 0,
            eof: false,
            shut: false,
        }
    }

    fn transfer(
        &mut self,
        source: &mut TcpStream,
        destination: &mut TcpStream,
    ) -> io::Result<bool> {
        let mut progress = false;
        if self.start == self.end && !self.eof {
            match source.read(&mut self.bytes) {
                Ok(size) => {
                    self.start = 0;
                    self.end = size;
                    self.eof = size == 0;
                    progress = true;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        if self.start < self.end {
            match destination.write(&self.bytes[self.start..self.end]) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "PROXY_WRITE_ZERO")),
                Ok(size) => {
                    self.start += size;
                    progress = true;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        if self.eof && self.start == self.end && !self.shut {
            destination.shutdown(Shutdown::Write)?;
            self.shut = true;
        }
        Ok(progress)
    }

    fn read_flags(&self) -> PollFlags {
        if !self.eof && self.start == self.end {
            PollFlags::IN
        } else {
            PollFlags::empty()
        }
    }

    fn write_flags(&self) -> PollFlags {
        if self.start < self.end {
            PollFlags::OUT
        } else {
            PollFlags::empty()
        }
    }
}

pub fn relay(mut client: TcpStream, mut remote: TcpStream, stopped: &AtomicBool) -> io::Result<()> {
    client.set_nonblocking(true)?;
    remote.set_nonblocking(true)?;
    let (mut outbound, mut inbound) = (Buffer::new(), Buffer::new());
    let mut deadline = Deadline {
        stopped,
        at: Instant::now() + Duration::from_secs(60),
    };
    loop {
        deadline.check()?;
        let progress = outbound.transfer(&mut client, &mut remote)?
            | inbound.transfer(&mut remote, &mut client)?;
        if outbound.shut && inbound.shut {
            return Ok(());
        }
        if progress {
            deadline.at = Instant::now() + Duration::from_secs(60);
        }
        let mut polls = Vec::with_capacity(2);
        let client_flags = outbound.read_flags() | inbound.write_flags();
        let remote_flags = inbound.read_flags() | outbound.write_flags();
        if !client_flags.is_empty() {
            polls.push(PollFd::new(&client, client_flags));
        }
        if !remote_flags.is_empty() {
            polls.push(PollFd::new(&remote, remote_flags));
        }
        match poll(&mut polls, Some(&Timespec::try_from(TICK).unwrap())) {
            Err(error) if error != rustix::io::Errno::INTR => return Err(error.into()),
            _ => (),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpListener, sync::Arc, thread};

    #[test]
    fn cancellation_interrupts_an_idle_relay_and_closes_both_peers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let source = listener.accept().unwrap().0;
        let destination = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let mut remote = listener.accept().unwrap().0;
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        let worker = thread::spawn(move || relay(source, destination, &stop));
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        remote
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(b"live").unwrap();
        let mut bytes = [0; 4];
        remote.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"live");
        stopped.store(true, Ordering::SeqCst);
        assert!(worker.join().unwrap().is_err());
        assert_eq!(client.read(&mut bytes).unwrap(), 0);
        assert_eq!(remote.read(&mut bytes).unwrap(), 0);
    }

    #[test]
    fn partial_input_cannot_extend_the_absolute_handshake_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let mut source = listener.accept().unwrap().0;
        source.set_nonblocking(true).unwrap();
        client.write_all(b"x").unwrap();
        let stopped = AtomicBool::new(false);
        let deadline = Deadline {
            stopped: &stopped,
            at: Instant::now() + Duration::from_millis(80),
        };
        assert_eq!(
            deadline.read(&mut source, &mut [0; 2]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }
}
