//! Peer-authenticated native HTTP on a protected Unix socket. Runs outlive client connections.
use crate::{
    config::invalid,
    service::{Service, error},
};
use rustix::fs::{Gid, Uid, chown};
use sandcrab_core::http;
use std::{
    cell::Cell,
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
    stream: &'a UnixStream,
    deadline: &'a Cell<Instant>,
    slice: &'a Cell<Duration>,
    received: &'a Cell<bool>,
}
impl Timed<'_> {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .get()
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::ErrorKind::TimedOut.into())
    }
}
impl Read for Timed<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream
            .set_read_timeout(Some(self.remaining()?.min(self.slice.get())))?;
        let n = self.stream.read(bytes)?;
        if n > 0 {
            self.received.set(true);
        }
        Ok(n)
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
        let deadline = Cell::new(Instant::now() + EXCHANGE_TIMEOUT);
        let slice = Cell::new(EXCHANGE_TIMEOUT);
        let received = Cell::new(false);
        let mut input = Timed {
            stream,
            deadline: &deadline,
            slice: &slice,
            received: &received,
        };
        let (head, mut body) = match http::start(&mut input) {
            Ok(Some(value)) => value,
            Ok(None) => return Ok(()),
            Err(_) if !received.get() => return Ok(()),
            Err(_) => return json_reply(stream, 400, &error(400, "INVALID_HTTP").1, true),
        };
        let expect = head.header("expect");
        if expect.is_some_and(|value| !value.eq_ignore_ascii_case("100-continue")) {
            drop(body);
            return json_reply(stream, 417, &error(417, "EXPECTATION_UNSUPPORTED").1, true);
        }
        if head.method == "PUT"
            && let Some(id) = head
                .path
                .strip_prefix("/v1/uploads/")
                .and_then(|p| p.strip_suffix("/content"))
                .filter(|s| sandcrab_core::uuid(s))
        {
            deadline.set(Instant::now() + Duration::from_secs(30));
            slice.set(Duration::from_millis(200));
            let mut continuation = if expect.is_some() {
                Some(stream.try_clone()?)
            } else {
                None
            };
            let (status, reply) =
                service.receive_upload(id, head.length, &mut body, deadline.get(), || {
                    if let Some(stream) = &mut continuation {
                        stream.set_write_timeout(Some(EXCHANGE_TIMEOUT))?;
                        stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
                        stream.flush()?;
                    }
                    Ok(())
                });
            drop(body);
            return json_reply(stream, status, &reply, true);
        }
        if expect.is_some() {
            drop(body);
            return json_reply(stream, 417, &error(417, "EXPECTATION_UNSUPPORTED").1, true);
        }
        if !["GET", "POST"].contains(&head.method.as_str())
            || head.length > 65536
            || (head.method == "POST") != (head.length > 0)
        {
            drop(body);
            return json_reply(stream, 400, &error(400, "INVALID_HTTP").1, true);
        }
        let mut bytes = Vec::with_capacity(head.length as usize);
        if body.read_to_end(&mut bytes).is_err() {
            drop(body);
            return json_reply(stream, 400, &error(400, "INVALID_HTTP").1, true);
        }
        drop(body);
        let close =
            head.close || index + 1 == REQUEST_LIMIT || service.stopped.load(Ordering::SeqCst);
        if head.method == "GET"
            && let Some(id) = head
                .path
                .strip_prefix("/v1/runs/")
                .and_then(|p| p.strip_suffix("/events"))
                .filter(|s| sandcrab_core::uuid(s))
        {
            match crate::events::subscribe(service, id, head.header("last-event-id")) {
                Ok(subscription) => subscription.write(stream, close)?,
                Err((status, reply)) => json_reply(stream, status, &reply, close)?,
            }
            if close {
                return Ok(());
            }
            continue;
        }
        if head.method == "POST"
            && let Some(id) = head
                .path
                .strip_prefix("/v1/sessions/")
                .and_then(|p| p.strip_suffix("/snapshot"))
                .filter(|s| sandcrab_core::uuid(s))
        {
            return snapshot(stream, service, id, &bytes);
        }
        let (status, reply) = service.route(&head.method, &head.path, &bytes);
        json_reply(stream, status, &reply, close)?;
        if close {
            return Ok(());
        }
    }
    Ok(())
}

fn json_reply(
    stream: &mut UnixStream,
    status: u16,
    reply: &serde_json::Value,
    close: bool,
) -> io::Result<()> {
    let deadline = Cell::new(Instant::now() + EXCHANGE_TIMEOUT);
    let slice = Cell::new(EXCHANGE_TIMEOUT);
    let received = Cell::new(false);
    let mut output = Timed {
        stream,
        deadline: &deadline,
        slice: &slice,
        received: &received,
    };
    http::respond(
        &mut output,
        status,
        "application/json",
        &serde_json::to_vec(reply)?,
        close,
    )
}
struct Download<'a> {
    stream: &'a mut UnixStream,
    cancelled: &'a std::sync::atomic::AtomicBool,
    deadline: Instant,
}
impl Write for Download<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        loop {
            if self.cancelled.load(Ordering::SeqCst) {
                // write_all/copy retry Interrupted; cancellation must end the exchange.
                return Err(io::ErrorKind::ConnectionAborted.into());
            }
            let remaining = self
                .deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(io::ErrorKind::TimedOut)?;
            self.stream
                .set_write_timeout(Some(remaining.min(Duration::from_millis(200))))?;
            match self.stream.write(bytes) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
fn snapshot(stream: &mut UnixStream, service: &Service, id: &str, body: &[u8]) -> io::Result<()> {
    let mut snapshot = match service.capture(id, body) {
        Ok(s) => s,
        Err((status, code)) => return json_reply(stream, status, &error(status, code).1, true),
    };
    let bytes = snapshot.bytes;
    let etag = format!("\"{}\"", snapshot.sha256);
    let content_type = if snapshot.format == crate::file_io::Format::Tar {
        "application/x-tar"
    } else {
        "application/octet-stream"
    };
    let cancelled = snapshot.lease.cancelled.clone();
    let deadline = Instant::now() + Duration::from_secs(30);
    if bytes == 0 {
        if service.release_snapshot(snapshot).is_err() {
            return json_reply(stream, 503, &error(503, "FILE_CLEANUP_UNCONFIRMED").1, true);
        }
        let mut output = Download {
            stream,
            cancelled: &cancelled,
            deadline,
        };
        http::response_head_with(&mut output, 200, content_type, 0, true, &[("ETag", &etag)])?;
        return output.flush();
    }
    let mut tail = [0u8; 1];
    let sent = (|| {
        let mut output = Download {
            stream,
            cancelled: &cancelled,
            deadline,
        };
        http::response_head_with(
            &mut output,
            200,
            content_type,
            bytes,
            true,
            &[("ETag", &etag)],
        )?;
        if io::copy(&mut (&mut snapshot.file).take(bytes - 1), &mut output)? != bytes - 1 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        snapshot.file.read_exact(&mut tail)
    })();
    // Keep the final byte until the snapshot and its ownership are released.
    // A fixed-length reader may act immediately after that byte, without waiting for EOF.
    let cleanup = service.release_snapshot(snapshot);
    sent.and(cleanup)?;
    let mut output = Download {
        stream,
        cancelled: &cancelled,
        deadline,
    };
    output.write_all(&tail)?;
    output.flush()
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
                    (n < service.runtime.config.service.max_connections).then_some(n + 1)
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
            if let Ok(worker) = thread::Builder::new().spawn(move || {
                let _guard = guard;
                let _ = exchange(&mut stream, &service);
            }) {
                workers.push(worker);
            }
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
