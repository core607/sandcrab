//! Native per-lease bridge mailbox. Host authorization remains with the supervisor.
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{CWD, Gid, Mode, OFlags, fchown, mkfifoat},
    io::{read, write},
    pipe::{PipeFlags, pipe_with},
};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::OwnedFd,
        unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::{Mutex, TryLockError},
    thread,
    time::{Duration, Instant},
};

const MAX_FRAME: usize = 512 * 1024;

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
fn drain(fd: &impl std::os::fd::AsFd) -> io::Result<()> {
    let mut bytes = [0_u8; 65536];
    loop {
        match read(fd, &mut bytes) {
            Ok(0) | Err(rustix::io::Errno::AGAIN) => return Ok(()),
            Ok(_) => (),
            Err(error) => return Err(error.into()),
        }
    }
}
#[derive(Default)]
struct State {
    pending: HashMap<String, bool>,
    seen: HashSet<String>,
    closed: bool,
    close_published: bool,
    execution: String,
    resets: usize,
}
#[derive(Default)]
struct Reader {
    input: Option<File>,
    wake: Option<OwnedFd>,
    buffer: Vec<u8>,
    frame_started: Option<Instant>,
}
pub struct Mailbox {
    path: PathBuf,
    operations: &'static [&'static str],
    gid: u32,
    waker: Mutex<Option<OwnedFd>>,
    state: Mutex<State>,
    reader: Mutex<Reader>,
    closer: Mutex<()>,
}
impl Mailbox {
    /// Create the mailbox files; requests naming an operation outside `operations` are refused.
    pub fn create(path: &Path, gid: u32, operations: &'static [&'static str]) -> io::Result<Self> {
        DirBuilder::new().mode(0o750).create(path)?;
        let directory = File::open(path)?;
        fchown(&directory, None, Some(Gid::from_raw(gid)))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o750))?;
        let responses = path.join("responses");
        DirBuilder::new().mode(0o750).create(&responses)?;
        fchown(File::open(&responses)?, None, Some(Gid::from_raw(gid)))?;
        fs::set_permissions(&responses, fs::Permissions::from_mode(0o750))?;
        mkfifoat(CWD, path.join("requests"), Mode::from_raw_mode(0o620))?;
        let input = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(OFlags::NONBLOCK.bits() as i32 | OFlags::NOFOLLOW.bits() as i32)
            .open(path.join("requests"))?;
        fchown(&input, None, Some(Gid::from_raw(gid)))?;
        input.set_permissions(fs::Permissions::from_mode(0o620))?;
        for (name, mode) in [("lock", 0o440), ("state", 0o640)] {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(path.join(name))?;
            fchown(&file, None, Some(Gid::from_raw(gid)))?;
            file.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        let (wake, waker) = pipe_with(PipeFlags::NONBLOCK | PipeFlags::CLOEXEC)?;
        Ok(Self {
            path: path.into(),
            operations,
            gid,
            waker: Mutex::new(Some(waker)),
            state: Mutex::default(),
            reader: Mutex::new(Reader {
                input: Some(input),
                wake: Some(wake),
                ..Reader::default()
            }),
            closer: Mutex::default(),
        })
    }
    fn wake(&self) -> io::Result<()> {
        let waker = self.waker.lock().unwrap();
        let Some(waker) = waker.as_ref() else {
            return Ok(());
        };
        match write(waker, b".") {
            Ok(_) | Err(rustix::io::Errno::AGAIN) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
    fn publish_state(&self, bytes: &[u8]) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .custom_flags(OFlags::NOFOLLOW.bits() as i32)
            .open(self.path.join("state"))?;
        file.write_all(bytes)
    }
    pub fn reset(&self, execution: &str) -> io::Result<()> {
        if !execution.is_empty() && !super::uuid(execution) {
            return Err(invalid("Invalid execution identity"));
        }
        {
            let mut state = self.state.lock().unwrap();
            if state.closed {
                return Ok(());
            }
            state.resets += 1;
            if let Err(error) = self.wake() {
                state.resets -= 1;
                return Err(error);
            }
        }
        let result = (|| {
            let mut reader = self.reader.lock().unwrap();
            let mut state = self.state.lock().unwrap();
            if state.closed {
                return Ok(());
            }
            for request in state.pending.keys() {
                fs::remove_file(self.path.join("responses").join(format!("{request}.json")))
                    .or_else(missing)?;
            }
            state.pending.clear();
            state.seen.clear();
            reader.buffer.clear();
            reader.frame_started = None;
            drain(
                reader
                    .input
                    .as_ref()
                    .ok_or_else(|| invalid("Closed bridge input"))?,
            )?;
            drain(
                reader
                    .wake
                    .as_ref()
                    .ok_or_else(|| invalid("Closed bridge wake"))?,
            )?;
            state.execution = execution.into();
            self.publish_state(execution.as_bytes())
        })();
        self.state.lock().unwrap().resets -= 1;
        result
    }
    fn message(&self, value: Value) -> io::Result<Option<Value>> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid("Invalid bridge object"))?;
        let operation = value["operation"]
            .as_str()
            .ok_or_else(|| invalid("Invalid operation"))?;
        let request = value["requestId"]
            .as_str()
            .filter(|v| super::uuid(v))
            .ok_or_else(|| invalid("Invalid request identity"))?;
        let execution = value["executionId"]
            .as_str()
            .filter(|v| super::uuid(v))
            .ok_or_else(|| invalid("Invalid execution identity"))?;
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return Err(invalid("Closed mailbox"));
        }
        if execution != state.execution || execution.is_empty() {
            return Ok(None);
        }
        if operation == "ack" {
            if object.len() != 3 {
                return Err(invalid("Invalid acknowledgement"));
            }
            if state.pending.get(request) == Some(&true) {
                fs::remove_file(self.path.join("responses").join(format!("{request}.json")))
                    .or_else(missing)?;
                state.pending.remove(request);
            }
            return Ok(None);
        }
        if object.len() != 4
            || !self.operations.contains(&operation)
            || !value["arguments"].is_object()
        {
            return Err(invalid("Invalid bridge request"));
        }
        if state.seen.contains(request) || state.seen.len() >= 256 || state.pending.len() >= 4 {
            return Err(invalid("Bridge replay or capacity limit"));
        }
        state.seen.insert(request.into());
        state.pending.insert(request.into(), false);
        Ok(Some(value))
    }
    pub fn poll(&self, duration: Duration, execution: &str) -> io::Result<Option<Value>> {
        let deadline = Instant::now() + duration.min(Duration::from_secs(2));
        let mut reader = loop {
            match self.reader.try_lock() {
                Ok(value) => break value,
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(1))
                }
                Err(TryLockError::WouldBlock) => return Ok(None),
                Err(TryLockError::Poisoned(_)) => return Err(invalid("Poisoned bridge reader")),
            }
        };
        loop {
            {
                let state = self.state.lock().unwrap();
                if state.closed {
                    return Err(invalid("Closed mailbox"));
                }
                if state.resets != 0 || state.execution != execution {
                    return Ok(None);
                }
            }
            if reader
                .frame_started
                .is_some_and(|time| time.elapsed() > Duration::from_secs(5))
            {
                return Err(invalid("Bridge frame deadline"));
            }
            if reader.buffer.len() >= 4 {
                let size = u32::from_be_bytes(reader.buffer[..4].try_into().unwrap()) as usize;
                if size == 0 || size > MAX_FRAME {
                    return Err(invalid("Invalid bridge frame"));
                }
                if reader.buffer.len() >= size + 4 {
                    let value = super::parse(&reader.buffer[4..size + 4]).map_err(invalid)?;
                    reader.buffer.drain(..size + 4);
                    reader.frame_started = (!reader.buffer.is_empty()).then(Instant::now);
                    if let Some(request) = self.message(value)? {
                        return Ok(Some(request));
                    }
                    continue;
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            let readable = {
                let mut pollers = [
                    PollFd::new(
                        reader
                            .input
                            .as_ref()
                            .ok_or_else(|| invalid("Closed bridge input"))?,
                        PollFlags::IN,
                    ),
                    PollFd::new(
                        reader
                            .wake
                            .as_ref()
                            .ok_or_else(|| invalid("Closed bridge wake"))?,
                        PollFlags::IN,
                    ),
                ];
                let timeout = Timespec::try_from(remaining.min(Duration::from_millis(50)))
                    .map_err(|_| invalid("Invalid timeout"))?;
                poll(&mut pollers, Some(&timeout))?;
                pollers[0].revents().contains(PollFlags::IN)
            };
            if readable {
                if reader.frame_started.is_none() {
                    reader.frame_started = Some(Instant::now());
                }
                let mut bytes = vec![0; 65536.min(MAX_FRAME + 4 - reader.buffer.len())];
                match reader
                    .input
                    .as_ref()
                    .ok_or_else(|| invalid("Closed bridge input"))?
                    .read(&mut bytes)
                {
                    Ok(size) => reader.buffer.extend_from_slice(&bytes[..size]),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => (),
                    Err(error) => return Err(error),
                }
            }
        }
    }
    pub fn complete(&self, request: &str, value: &Value) -> io::Result<()> {
        if !super::uuid(request) {
            return Err(invalid("Invalid request identity"));
        }
        let bytes = serde_json::to_vec(value)?;
        if bytes.is_empty() || bytes.len() > MAX_FRAME {
            return Err(invalid("Bridge response limit"));
        }
        let mut state = self.state.lock().unwrap();
        if state.closed || state.pending.get(request) != Some(&false) {
            return Err(invalid("No pending request"));
        }
        let temporary = self
            .path
            .join("responses")
            .join(format!("{request}.pending"));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o440)
                .custom_flags(OFlags::NOFOLLOW.bits() as i32)
                .open(&temporary)?;
            fchown(&file, None, Some(Gid::from_raw(self.gid)))?;
            file.set_permissions(fs::Permissions::from_mode(0o440))?;
            file.write_all(&bytes)?;
            fs::rename(
                &temporary,
                self.path.join("responses").join(format!("{request}.json")),
            )?;
            state.pending.insert(request.into(), true);
            Ok(())
        })();
        fs::remove_file(&temporary).or_else(missing)?;
        result
    }
    pub fn close(&self) -> io::Result<()> {
        let _closer = self.closer.lock().unwrap();
        {
            let mut state = self.state.lock().unwrap();
            if state.close_published {
                return Ok(());
            }
            state.closed = true;
            self.wake()?;
        }
        let mut reader = self.reader.lock().unwrap();
        let mut state = self.state.lock().unwrap();
        reader.input.take();
        reader.wake.take();
        self.waker.lock().unwrap().take();
        reader.buffer.clear();
        for request in state.pending.keys() {
            fs::remove_file(self.path.join("responses").join(format!("{request}.json")))
                .or_else(missing)?;
        }
        state.pending.clear();
        self.publish_state(b"closed\n")?;
        state.close_published = true;
        Ok(())
    }
}
fn missing(error: io::Error) -> io::Result<()> {
    if error.kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;
    struct Fixture {
        path: PathBuf,
        bridge: Arc<Mailbox>,
    }
    impl Fixture {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("rust-mailbox-{}-{name}", std::process::id()));
            let bridge = Arc::new(
                Mailbox::create(
                    &path,
                    rustix::process::getgid().as_raw(),
                    &["status", "save"],
                )
                .unwrap(),
            );
            Self { path, bridge }
        }
        fn send(&self, value: Value) {
            let bytes = serde_json::to_vec(&value).unwrap();
            let mut input = OpenOptions::new()
                .write(true)
                .open(self.path.join("requests"))
                .unwrap();
            input
                .write_all(&(bytes.len() as u32).to_be_bytes())
                .unwrap();
            input.write_all(&bytes).unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.bridge.close().unwrap();
            fs::remove_dir_all(&self.path).unwrap();
        }
    }
    const EXEC: &str = "11111111-1111-1111-1111-111111111111";
    const REQUEST: &str = "22222222-2222-2222-2222-222222222222";
    #[test]
    fn round_trip_ack_and_replay() {
        let fixture = Fixture::new("roundtrip");
        fixture.bridge.reset(EXEC).unwrap();
        let value =
            json!({"requestId":REQUEST,"executionId":EXEC,"operation":"status","arguments":{}});
        fixture.send(value.clone());
        assert_eq!(
            fixture.bridge.poll(Duration::from_secs(1), EXEC).unwrap(),
            Some(value.clone())
        );
        fixture
            .bridge
            .complete(REQUEST, &json!({"ok":true}))
            .unwrap();
        assert_eq!(
            fs::read(
                fixture
                    .path
                    .join("responses")
                    .join(format!("{REQUEST}.json"))
            )
            .unwrap(),
            br#"{"ok":true}"#
        );
        fixture.send(json!({"requestId":REQUEST,"executionId":EXEC,"operation":"ack"}));
        assert!(
            fixture
                .bridge
                .poll(Duration::from_millis(10), EXEC)
                .unwrap()
                .is_none()
        );
        assert!(fixture.bridge.state.lock().unwrap().pending.is_empty());
        fixture.send(value);
        assert!(fixture.bridge.poll(Duration::from_secs(1), EXEC).is_err());
    }
    #[test]
    fn stale_frames_cannot_enter_the_current_execution() {
        let fixture = Fixture::new("stale");
        fixture.bridge.reset(EXEC).unwrap();
        fixture.send(
            json!({"requestId":REQUEST,"executionId":REQUEST,"operation":"status","arguments":{}}),
        );
        let current =
            json!({"requestId":REQUEST,"executionId":EXEC,"operation":"status","arguments":{}});
        fixture.send(current.clone());
        assert_eq!(
            fixture.bridge.poll(Duration::from_secs(1), EXEC).unwrap(),
            Some(current)
        );
    }
    #[test]
    fn close_wakes_a_poll() {
        let fixture = Fixture::new("close");
        fixture.bridge.reset(EXEC).unwrap();
        let bridge = fixture.bridge.clone();
        let poll = thread::spawn(move || bridge.poll(Duration::from_secs(2), EXEC));
        thread::sleep(Duration::from_millis(20));
        let started = Instant::now();
        fixture.bridge.close().unwrap();
        assert!(poll.join().unwrap().is_err());
        assert!(started.elapsed() < Duration::from_millis(200));
        let reader = fixture.bridge.reader.lock().unwrap();
        assert!(reader.input.is_none() && reader.wake.is_none());
        assert!(fixture.bridge.waker.lock().unwrap().is_none());
    }
    #[test]
    fn a_failed_close_publication_remains_retryable() {
        let fixture = Fixture::new("retry-close");
        fs::remove_file(fixture.path.join("state")).unwrap();
        assert!(fixture.bridge.close().is_err());
        assert!(!fixture.bridge.state.lock().unwrap().close_published);
        File::create(fixture.path.join("state")).unwrap();
        fixture.bridge.close().unwrap();
        assert_eq!(fs::read(fixture.path.join("state")).unwrap(), b"closed\n");
        assert!(fixture.bridge.state.lock().unwrap().close_published);
    }
}
