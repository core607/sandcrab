//! Peer-authenticated native HTTP on a protected Unix socket. Runs outlive client connections.
use crate::{
    config::invalid,
    service::{Service, error},
    transport::Stream,
};
use rustix::fs::{Gid, Uid, chown};
use sandcrab_core::http;
use std::{
    cell::Cell,
    fs,
    io::{self, Read, Write},
    net::TcpListener,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixListener,
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
    stream: &'a Stream,
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

fn exchange(stream: &mut Stream, service: &Arc<Service>) -> io::Result<()> {
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
        let (head, mut body) = match http::streaming_start(&mut input, |path| {
            service.runtime.config.service.opensandbox
                && crate::sdk_files::upload_path(path).is_some()
        }) {
            Ok(Some(value)) => value,
            Ok(None) => return Ok(()),
            Err(_) if !received.get() => return Ok(()),
            Err(_) => return json_reply(stream, 400, &error(400, "INVALID_HTTP").1, true),
        };
        if service.runtime.config.service.opensandbox && crate::opensandbox::path(&head.path) {
            if !service.sdk_authorized(&head) {
                drop(body);
                let (status, value) = crate::sdk_types::reply((401, "AUTH_REQUIRED"));
                return crate::opensandbox::write(stream, status, &value, true);
            }
            if head.method == "POST"
                && let Some(id) = crate::sdk_files::upload_path(&head.path)
            {
                let boundary = head
                    .header("content-type")
                    .and_then(|v| crate::multipart::boundary(v).ok());
                if head.header("expect").is_some() || boundary.is_none() {
                    drop(body);
                    let (status, value) = crate::sdk_types::reply((400, "INVALID_MULTIPART"));
                    return crate::opensandbox::write(stream, status, &value, true);
                }
                deadline.set(Instant::now() + Duration::from_secs(30));
                slice.set(Duration::from_millis(200));
                let result = service.sdk_upload(
                    id,
                    &boundary.unwrap(),
                    (!head.chunked).then_some(head.length),
                    &mut body,
                    deadline.get(),
                );
                drop(body);
                let (status, value) = match result {
                    Ok(()) => (200, serde_json::Value::Null),
                    Err(error) => crate::sdk_types::reply(error),
                };
                return crate::opensandbox::write(stream, status, &value, true);
            }
            if head.header("expect").is_some()
                || head.length > 65536
                || !["GET", "POST", "DELETE"].contains(&head.method.as_str())
                || (head.method == "POST") != (head.length > 0)
            {
                drop(body);
                let (status, value) = crate::sdk_types::reply((400, "INVALID_HTTP"));
                return crate::opensandbox::write(stream, status, &value, true);
            }
            let mut bytes = Vec::with_capacity(head.length as usize);
            body.read_to_end(&mut bytes)?;
            drop(body);
            if head.method == "GET"
                && let Some((id, query)) = crate::sdk_files::download_path(&head.path)
            {
                if head.header("if-range").is_some() {
                    let (status, value) =
                        crate::sdk_types::reply((400, "CONDITIONAL_RANGE_UNSUPPORTED"));
                    return crate::opensandbox::write(stream, status, &value, true);
                }
                let snapshot = match service.sdk_capture(id, query, head.header("range")) {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        let (status, value) = crate::sdk_types::reply(error);
                        return crate::opensandbox::write(stream, status, &value, true);
                    }
                };
                return send_snapshot(stream, service, snapshot, true);
            }
            let close =
                head.close || index + 1 == REQUEST_LIMIT || service.stopped.load(Ordering::SeqCst);
            service.sdk_exchange(stream, &head, &bytes, close)?;
            if close {
                return Ok(());
            }
            continue;
        }
        if stream.tcp()
            && !service
                .runtime
                .config
                .tcp
                .as_ref()
                .and_then(|tcp| tcp.token.as_ref())
                .is_some_and(|token| token.authorizes(head.header("authorization")))
        {
            // Authenticate before body allocation, upload admission or 100 Continue.
            drop(body);
            return json_reply(stream, 401, &error(401, "AUTH_REQUIRED").1, true);
        }
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
            || head.length
                > if crate::host_calls::reply_path(&head.path) {
                    crate::host_calls::FRAME as u64
                } else {
                    65536
                }
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
                .and_then(|p| p.strip_suffix("/calls/events"))
                .filter(|s| sandcrab_core::uuid(s))
        {
            match crate::call_events::subscribe(service, id, head.header("last-event-id")) {
                Ok(subscription) => subscription.write(stream, close)?,
                Err((status, reply)) => json_reply(stream, status, &reply, close)?,
            }
            if close {
                return Ok(());
            }
            continue;
        }
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
    stream: &mut Stream,
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
    let body = serde_json::to_vec(reply)?;
    let headers = if status == 401 {
        &[("WWW-Authenticate", "Bearer")][..]
    } else {
        &[]
    };
    http::response_head_with(
        &mut output,
        status,
        "application/json",
        body.len() as u64,
        close,
        headers,
    )?;
    output.write_all(&body)?;
    output.flush()
}
struct Download<'a> {
    stream: &'a mut Stream,
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
fn snapshot(stream: &mut Stream, service: &Service, id: &str, body: &[u8]) -> io::Result<()> {
    let snapshot = match service.capture(id, body, None, None) {
        Ok(s) => s,
        Err((status, code)) => return json_reply(stream, status, &error(status, code).1, true),
    };
    send_snapshot(stream, service, snapshot, false)
}
fn send_snapshot(
    stream: &mut Stream,
    service: &Service,
    mut snapshot: crate::files::Snapshot,
    sdk: bool,
) -> io::Result<()> {
    let bytes = snapshot.bytes;
    let etag = format!("\"{}\"", snapshot.sha256);
    let content_type = if snapshot.text {
        "text/plain; charset=utf-8"
    } else if snapshot.format == crate::file_io::Format::Tar {
        "application/x-tar"
    } else {
        "application/octet-stream"
    };
    let range = snapshot.range.as_ref().map(|range| {
        format!(
            "bytes {}-{}/{}",
            range.start,
            range.start + bytes - 1,
            range.total
        )
    });
    let status = if range.is_some() { 206 } else { 200 };
    let mut headers = Vec::new();
    if let Some(range) = &range {
        headers.push(("Content-Range", range.as_str()));
    } else if !snapshot.text {
        headers.push(("ETag", etag.as_str()));
    }
    if sdk && !snapshot.text {
        headers.push(("Accept-Ranges", "bytes"));
    }
    let cancelled = snapshot.lease.cancelled.clone();
    let deadline = Instant::now() + Duration::from_secs(30);
    if bytes == 0 {
        if service.release_snapshot(snapshot).is_err() {
            if sdk {
                let (status, value) = crate::sdk_types::reply((503, "FILE_CLEANUP_UNCONFIRMED"));
                return crate::opensandbox::write(stream, status, &value, true);
            }
            return json_reply(stream, 503, &error(503, "FILE_CLEANUP_UNCONFIRMED").1, true);
        }
        let mut output = Download {
            stream,
            cancelled: &cancelled,
            deadline,
        };
        http::response_head_with(&mut output, status, content_type, 0, true, &headers)?;
        return output.flush();
    }
    let mut tail = [0u8; 1];
    let sent = (|| {
        let mut output = Download {
            stream,
            cancelled: &cancelled,
            deadline,
        };
        http::response_head_with(&mut output, status, content_type, bytes, true, &headers)?;
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

fn accept(
    unix: &UnixListener,
    tcp: Option<&TcpListener>,
    tcp_first: bool,
) -> io::Result<Option<Stream>> {
    for use_tcp in [tcp_first, !tcp_first] {
        let accepted = if use_tcp {
            let Some(listener) = tcp else {
                continue;
            };
            listener.accept().and_then(|(stream, peer)| {
                if !peer.ip().is_loopback() {
                    return Ok(None);
                }
                stream.set_nodelay(true)?;
                Ok(Some(Stream::Tcp(stream)))
            })
        } else {
            unix.accept().map(|(stream, _)| Some(Stream::Unix(stream)))
        };
        match accepted {
            Ok(Some(stream)) => return Ok(Some(stream)),
            Ok(None) => (),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                        | io::ErrorKind::ConnectionAborted
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

pub fn serve(service: Arc<Service>) -> io::Result<()> {
    let tcp = service
        .runtime
        .config
        .tcp
        .as_ref()
        .map(|config| {
            if config.token.is_none() {
                return Err(invalid("TCP credentials were not loaded"));
            }
            let listener = TcpListener::bind(crate::transport::local_address(&config.listen)?)?;
            listener.set_nonblocking(true)?;
            Ok(listener)
        })
        .transpose()?;
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
    let mut tcp_first = false;
    let mut sdk_reap = Instant::now();
    println!("{{\"ready\":true,\"apiVersion\":1}}");
    let result = (|| {
        while !service.stopped.load(Ordering::SeqCst) {
            service.registry.lock().unwrap().expire_sessions();
            if service.runtime.config.service.opensandbox && Instant::now() >= sdk_reap {
                service.sdk_reap();
                sdk_reap = Instant::now() + Duration::from_secs(1);
            }
            workers.retain(|worker| !worker.is_finished());
            let mut stream = match accept(&listener, tcp.as_ref(), tcp_first) {
                Ok(Some(stream)) => stream,
                Ok(None) => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(e) => return Err(e),
            };
            tcp_first = !stream.tcp();
            stream.set_write_timeout(Some(Duration::from_secs(1)))?;
            if let Stream::Unix(socket) = &stream
                && rustix::net::sockopt::socket_peercred(socket)
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
    drop(tcp);
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
