//! Domain-authorized egress lives in the daemon. Workloads reach only a TCP
//! listener in their otherwise disconnected network namespace.
mod bridge;
mod dns;
mod io;
pub mod policy;
mod protocol;

use self::{
    io::{Deadline, TICK},
    policy::Policy,
    protocol::Protocol,
};
use crate::config::invalid;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use serde_json::json;
use std::{
    fs,
    io::{self as stdio, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixDatagram, UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, SyncSender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub use bridge::export;

#[derive(Default)]
struct State {
    active: usize,
    closed: bool,
    cleanup_failed: bool,
}

struct Group {
    id: String,
    policy: Policy,
    stopped: AtomicBool,
    state: Mutex<State>,
    changed: Condvar,
}

pub struct Lease {
    group: Arc<Group>,
    wake: Arc<UnixDatagram>,
}
impl Lease {
    pub fn finish(&self) -> stdio::Result<()> {
        self.group.stopped.store(true, Ordering::SeqCst);
        let _ = self.wake.send(b"x");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut state = self.group.state.lock().unwrap();
        while !state.closed || state.active != 0 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(invalid("Proxy cleanup remains unconfirmed"));
            }
            state = self.group.changed.wait_timeout(state, remaining).unwrap().0;
        }
        if state.cleanup_failed {
            Err(invalid("Proxy socket ownership changed during cleanup"))
        } else {
            Ok(())
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

struct Bridge {
    group: Arc<Group>,
    path: PathBuf,
    identity: (u64, u64),
    unix: Option<UnixListener>,
    control: Option<UnixStream>,
    listener: Option<TcpListener>,
    deadline: Instant,
}
impl Bridge {
    fn handshake(&mut self) -> stdio::Result<()> {
        if self.listener.is_some() {
            return Ok(());
        }
        if Instant::now() >= self.deadline {
            return Err(invalid("PROXY_BRIDGE_TIMEOUT"));
        }
        if self.control.is_none() {
            match self.unix.as_ref().unwrap().accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(true)?;
                    self.control = Some(stream);
                }
                Err(error) if transient(&error) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        let control = self.control.as_mut().unwrap();
        let listener = match bridge::receive(control) {
            Ok(listener) => listener,
            Err(error) if transient(&error) => return Ok(()),
            Err(error) => return Err(error),
        };
        if self.group.stopped.load(Ordering::SeqCst) {
            return Err(invalid("PROXY_CANCELLED"));
        }
        if control.write(b"x")? != 1 {
            return Err(invalid("PROXY_BRIDGE_ACK"));
        }
        self.listener = Some(listener);
        self.control.take();
        self.unix.take();
        Ok(())
    }

    fn close(mut self) {
        self.group.stopped.store(true, Ordering::SeqCst);
        self.listener.take();
        self.control.take();
        self.unix.take();
        let cleanup = (|| -> stdio::Result<()> {
            let metadata = fs::symlink_metadata(&self.path)?;
            if !metadata.file_type().is_socket()
                || metadata.uid() != 0
                || (metadata.dev(), metadata.ino()) != self.identity
            {
                return Err(invalid("Proxy socket ownership changed"));
            }
            fs::remove_file(&self.path)
        })();
        let mut state = self.group.state.lock().unwrap();
        state.closed = true;
        state.cleanup_failed = cleanup.is_err();
        self.group.changed.notify_all();
    }
}

struct Permit {
    group: Arc<Group>,
    total: Arc<AtomicUsize>,
}
impl Drop for Permit {
    fn drop(&mut self) {
        self.total.fetch_sub(1, Ordering::SeqCst);
        let mut state = self.group.state.lock().unwrap();
        state.active -= 1;
        self.group.changed.notify_all();
    }
}

fn transient(error: &stdio::Error) -> bool {
    matches!(
        error.kind(),
        stdio::ErrorKind::WouldBlock
            | stdio::ErrorKind::Interrupted
            | stdio::ErrorKind::ConnectionAborted
    )
}

fn reason(error: &stdio::Error) -> String {
    let reason = error.to_string();
    if reason.len() <= 64
        && reason.starts_with("PROXY_")
        && reason.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
    {
        reason
    } else if error.kind() == stdio::ErrorKind::TimedOut {
        "PROXY_TIMEOUT".into()
    } else {
        "PROXY_IO_FAILED".into()
    }
}

fn decision(
    group: &Group,
    protocol: Option<Protocol>,
    request: Option<&protocol::Request>,
    allowed: bool,
    code: &str,
    address: Option<SocketAddr>,
) {
    eprintln!(
        "{}",
        json!({"event":"networkDecision","executionId":group.id,
        "protocol":protocol.map(Protocol::name),"domain":request.map(|r|r.name.as_str()),
        "port":request.map(|r|r.port),"allowed":allowed,"reason":code,"address":address.map(|a|a.to_string())})
    );
}

fn serve(mut client: TcpStream, group: &Group, servers: &[SocketAddr]) {
    let deadline = Deadline {
        stopped: &group.stopped,
        at: Instant::now() + Duration::from_secs(5),
    };
    let mut protocol = None;
    let mut request = None;
    let connection = (|| -> stdio::Result<(TcpStream, SocketAddr)> {
        client.set_nonblocking(true)?;
        let mut first = [0];
        deadline.read(&mut client, &mut first)?;
        let selected = if first[0] == 5 {
            Protocol::Socks5
        } else {
            Protocol::Connect
        };
        protocol = Some(selected);
        request = Some(selected.request(first[0], &mut client, &deadline)?);
        let request = request.as_ref().unwrap();
        if !group.policy.permits(&request.name) {
            return Err(invalid("PROXY_DOMAIN_DENIED"));
        }
        let addresses = dns::resolve(servers, &request.name, &deadline)?;
        for address in addresses {
            let address = SocketAddr::new(address, request.port);
            let attempt = Deadline {
                stopped: &group.stopped,
                at: deadline.at.min(Instant::now() + Duration::from_secs(1)),
            };
            if let Ok(stream) = attempt.connect(address) {
                return Ok((stream, address));
            }
            deadline.check()?;
        }
        Err(invalid("PROXY_CONNECT_FAILED"))
    })();
    match connection {
        Ok((remote, address)) => {
            decision(
                group,
                protocol,
                request.as_ref(),
                true,
                "ALLOW",
                Some(address),
            );
            if protocol
                .unwrap()
                .respond(&mut client, &deadline, 200)
                .is_ok()
            {
                let _ = io::relay(client, remote, &group.stopped);
            }
        }
        Err(error) => {
            let code = reason(&error);
            decision(group, protocol, request.as_ref(), false, &code, None);
            if let Some(protocol) = protocol {
                let status = if code.ends_with("_DENIED") {
                    403
                } else if request.is_none() {
                    400
                } else {
                    502
                };
                let response = Deadline {
                    stopped: &group.stopped,
                    at: Instant::now() + Duration::from_millis(100),
                };
                let _ = protocol.respond(&mut client, &response, status);
            }
        }
    }
}

pub struct Hub {
    sender: SyncSender<Bridge>,
    wake: Arc<UnixDatagram>,
    stopped: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl Hub {
    pub fn start(max_sandboxes: usize, max_connections: usize) -> stdio::Result<Self> {
        let servers = dns::servers()?;
        let (sender, receiver) = mpsc::sync_channel::<Bridge>(max_sandboxes);
        let (wake, receive) = UnixDatagram::pair()?;
        wake.set_nonblocking(true)?;
        receive.set_nonblocking(true)?;
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        let worker = thread::Builder::new()
            .name("sandcrab-egress".into())
            .spawn(move || {
                let total = Arc::new(AtomicUsize::new(0));
                let servers = Arc::new(servers);
                let mut bridges: Vec<Bridge> = Vec::new();
                let mut workers: Vec<JoinHandle<()>> = Vec::new();
                loop {
                    while let Ok(bridge) = receiver.try_recv() {
                        bridges.push(bridge);
                    }
                    let mut index = 0;
                    while index < bridges.len() {
                        let bridge = &mut bridges[index];
                        if stop.load(Ordering::SeqCst)
                            || bridge.group.stopped.load(Ordering::SeqCst)
                        {
                            bridges.swap_remove(index).close();
                            continue;
                        }
                        if let Err(error) = bridge.handshake() {
                            decision(&bridge.group, None, None, false, &reason(&error), None);
                            bridges.swap_remove(index).close();
                            continue;
                        }
                        if let Some(listener) = &bridge.listener {
                            // One accept per bridge per pass prevents a busy guest
                            // from starving setup, cancellation or other guests.
                            match listener.accept() {
                                Ok((client, _)) => {
                                    let mut state = bridge.group.state.lock().unwrap();
                                    if total.load(Ordering::SeqCst) >= max_connections
                                        || state.active >= 8
                                    {
                                        decision(
                                            &bridge.group,
                                            None,
                                            None,
                                            false,
                                            "PROXY_CAPACITY",
                                            None,
                                        );
                                    } else {
                                        total.fetch_add(1, Ordering::SeqCst);
                                        state.active += 1;
                                        let permit = Permit {
                                            group: bridge.group.clone(),
                                            total: total.clone(),
                                        };
                                        let servers = servers.clone();
                                        drop(state);
                                        if let Ok(worker) = thread::Builder::new()
                                            .name("sandcrab-proxy".into())
                                            .stack_size(512 * 1024)
                                            .spawn(move || {
                                                serve(client, &permit.group, &servers);
                                                drop(permit);
                                            })
                                        {
                                            workers.push(worker);
                                        } else {
                                            decision(
                                                &bridge.group,
                                                None,
                                                None,
                                                false,
                                                "PROXY_WORKER_UNAVAILABLE",
                                                None,
                                            );
                                        }
                                    }
                                }
                                Err(error) if transient(&error) => (),
                                Err(_) => {
                                    bridge.group.stopped.store(true, Ordering::SeqCst);
                                }
                            }
                        }
                        index += 1;
                    }
                    let mut index = 0;
                    while index < workers.len() {
                        if workers[index].is_finished() {
                            let _ = workers.swap_remove(index).join();
                        } else {
                            index += 1;
                        }
                    }
                    if stop.load(Ordering::SeqCst) {
                        for bridge in receiver.try_iter() {
                            bridge.close();
                        }
                        for worker in workers {
                            let _ = worker.join();
                        }
                        break;
                    }
                    let mut polls = vec![PollFd::new(&receive, PollFlags::IN)];
                    for bridge in &bridges {
                        if let Some(fd) = &bridge.unix {
                            polls.push(PollFd::new(fd, PollFlags::IN));
                        }
                        if let Some(fd) = &bridge.control {
                            polls.push(PollFd::new(fd, PollFlags::IN));
                        }
                        if let Some(fd) = &bridge.listener {
                            polls.push(PollFd::new(fd, PollFlags::IN));
                        }
                    }
                    if let Err(error) = poll(&mut polls, Some(&Timespec::try_from(TICK).unwrap()))
                        && error != rustix::io::Errno::INTR
                    {
                        stop.store(true, Ordering::SeqCst);
                    }
                    let mut bytes = [0; 64];
                    while receive.recv(&mut bytes).is_ok() {}
                }
            })?;
        Ok(Self {
            sender,
            wake: Arc::new(wake),
            stopped,
            worker: Some(worker),
        })
    }

    pub fn register(&self, root: &Path, id: &str, policy: Policy) -> stdio::Result<Lease> {
        if self.stopped.load(Ordering::SeqCst) {
            return Err(invalid("Proxy service is unavailable"));
        }
        sandcrab_core::fs::protected_directory(root)?;
        let path = root.join(bridge::SOCKET);
        let (directory, socket) = bridge::socket_path(root)?;
        let listener = UnixListener::bind(socket)?;
        drop(directory);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let metadata = fs::symlink_metadata(&path)?;
        listener.set_nonblocking(true)?;
        let group = Arc::new(Group {
            id: id.into(),
            policy,
            stopped: AtomicBool::new(false),
            state: Mutex::default(),
            changed: Condvar::new(),
        });
        let bridge = Bridge {
            group: group.clone(),
            path,
            identity: (metadata.dev(), metadata.ino()),
            unix: Some(listener),
            control: None,
            listener: None,
            deadline: Instant::now() + Duration::from_secs(10),
        };
        if let Err(error) = self.sender.try_send(bridge) {
            let (mpsc::TrySendError::Full(bridge) | mpsc::TrySendError::Disconnected(bridge)) =
                error;
            bridge.close();
            return Err(invalid("Proxy bridge capacity unavailable"));
        }
        let _ = self.wake.send(b"x");
        Ok(Lease {
            group,
            wake: self.wake.clone(),
        })
    }
}
impl Drop for Hub {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        let _ = self.wake.send(b"x");
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub fn environment() -> Vec<(String, String)> {
    let http = format!("http://127.0.0.1:{}", bridge::PORT);
    let socks = format!("socks5h://127.0.0.1:{}", bridge::PORT);
    [
        ("http_proxy", &http),
        ("https_proxy", &http),
        ("HTTP_PROXY", &http),
        ("HTTPS_PROXY", &http),
        ("all_proxy", &socks),
        ("ALL_PROXY", &socks),
        ("no_proxy", &String::new()),
        ("NO_PROXY", &String::new()),
    ]
    .into_iter()
    .map(|(name, value)| (name.into(), value.clone()))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_runtime_path_and_cancelled_bridge_release_the_owned_socket() {
        let root = Path::new("/source").join(format!(
            "sandcrab-egress-test-{}",
            sandcrab_core::new_uuid().unwrap()
        ));
        let job = root.join("a".repeat(100));
        fs::create_dir(&root).unwrap();
        fs::create_dir(&job).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&job, fs::Permissions::from_mode(0o755)).unwrap();
        let hub = Hub::start(1, 1).unwrap();
        let policy = serde_json::from_value(json!({"allow":["allowed.example"]})).unwrap();
        let lease = hub.register(&job, "fixture", policy).unwrap();
        assert!(job.join(bridge::SOCKET).exists());
        lease.finish().unwrap();
        assert!(!job.join(bridge::SOCKET).exists());
        drop(lease);
        drop(hub);
        fs::remove_dir(job).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
