//! Peer-authenticated native HTTP on a protected Unix socket. Runs outlive client connections.
use crate::{
    config::invalid,
    service::{Service, error},
};
use rustix::fs::{Gid, Uid, chown};
use sandcrab_core::http;
use std::{
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

struct Connection(Arc<AtomicUsize>);
impl Drop for Connection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

const REQUEST_LIMIT: usize = 128;
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);

// A socket timeout alone resets with every read/write. One deadline prevents a
// peer from holding admission indefinitely by sending a byte before each timeout.
struct Timed<'a> {
    stream: &'a mut UnixStream,
    deadline: Instant,
}
impl Timed<'_> {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::ErrorKind::TimedOut.into())
    }
}
impl Read for Timed<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}
impl Write for Timed<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn exchange(stream: &mut UnixStream, service: &Arc<Service>) -> io::Result<()> {
    for index in 0..REQUEST_LIMIT {
        if service.stopped.load(Ordering::SeqCst) {
            return Ok(());
        }
        let mut input = Timed {
            stream,
            deadline: Instant::now() + EXCHANGE_TIMEOUT,
        };
        let request = match http::start(&mut input) {
            Ok(Some((head, mut body)))
                if ["GET", "POST"].contains(&head.method.as_str())
                    && head.length <= 65536
                    && (head.method == "POST") == (head.length > 0) =>
            {
                let mut bytes = Vec::with_capacity(head.length as usize);
                body.read_to_end(&mut bytes).ok().map(|_| (head, bytes))
            }
            Ok(None) => return Ok(()),
            _ => None,
        };
        let (status, reply, close) = match request {
            Some((head, body)) => {
                let (status, reply) = service.route(&head.method, &head.path, &body);
                (
                    status,
                    reply,
                    head.close
                        || index + 1 == REQUEST_LIMIT
                        || service.stopped.load(Ordering::SeqCst),
                )
            }
            None => {
                let (status, reply) = error(400, "INVALID_HTTP");
                (status, reply, true)
            }
        };
        let mut output = Timed {
            stream,
            deadline: Instant::now() + EXCHANGE_TIMEOUT,
        };
        http::respond(
            &mut output,
            status,
            "application/json",
            &serde_json::to_vec(&reply)?,
            close,
        )?;
        if close {
            return Ok(());
        }
    }
    Ok(())
}

pub fn serve(service: Arc<Service>) -> io::Result<()> {
    let socket = &service.runtime.config.service.socket;
    match fs::symlink_metadata(socket) {
        Ok(info) if info.file_type().is_socket() && info.uid() == 0 => fs::remove_file(socket)?,
        Ok(_) => {
            return Err(invalid(
                "Socket path already exists and is not a root-owned socket",
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(socket)?;
    chown(
        socket,
        Some(Uid::ROOT),
        Some(Gid::from_raw(service.runtime.config.service.client_gid)),
    )?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o660))?;
    let metadata = fs::symlink_metadata(socket)?;
    listener.set_nonblocking(true)?;
    let active = Arc::new(AtomicUsize::new(0));
    let mut workers: Vec<thread::JoinHandle<()>> = Vec::new();
    println!("{{\"ready\":true,\"apiVersion\":1}}");
    let result = (|| {
        while !service.stopped.load(Ordering::SeqCst) {
            service.registry.lock().unwrap().expire_sessions();
            workers.retain(|worker| !worker.is_finished());
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            stream.set_write_timeout(Some(Duration::from_secs(1)))?;
            if rustix::net::sockopt::socket_peercred(&stream)
                .map(|c| c.uid.as_raw())
                .ok()
                != Some(service.runtime.config.service.client_uid)
            {
                let _ = http::write(&mut stream, 403, br#"{"error":{"code":"PEER_REJECTED"}}"#);
                continue;
            }
            if active
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                    (n < 32).then_some(n + 1)
                })
                .is_err()
            {
                let _ = http::write(
                    &mut stream,
                    429,
                    br#"{"error":{"code":"CONNECTION_CAPACITY"}}"#,
                );
                continue;
            }
            let guard = Connection(active.clone());
            let service = service.clone();
            workers.push(thread::Builder::new().spawn(move || {
                let _guard = guard;
                let _ = exchange(&mut stream, &service);
            })?);
        }
        Ok(())
    })();
    service.stopped.store(true, Ordering::SeqCst);
    drop(listener);
    let shutdown = service.shutdown();
    for worker in workers {
        let _ = worker.join();
    }
    if fs::symlink_metadata(socket)
        .is_ok_and(|info| info.dev() == metadata.dev() && info.ino() == metadata.ino())
    {
        fs::remove_file(socket)?;
    }
    result.and(shutdown)
}
