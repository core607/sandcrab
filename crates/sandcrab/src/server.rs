//! Peer-authenticated native HTTP on a protected Unix socket. Runs outlive client connections.
use crate::{
    config::invalid,
    service::{Service, error},
};
use rustix::fs::{Gid, Uid, chown};
use sandcrab_daemon::http;
use std::{
    fs, io,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

struct Connection(Arc<AtomicUsize>);
impl Drop for Connection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn exchange(stream: &mut UnixStream, service: &Arc<Service>) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let (status, reply) = match http::read(stream, 65536) {
        Ok(request) => service.route(&request.method, &request.path, &request.body),
        Err(_) => error(400, "INVALID_HTTP"),
    };
    http::write(stream, status, &serde_json::to_vec(&reply)?)
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
