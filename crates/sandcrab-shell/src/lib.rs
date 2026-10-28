#![forbid(unsafe_code)]
//! Persistent bash driver. The host owns sandboxing, command limits and descendant containment.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{CWD, Mode, OFlags, fcntl_getfl, fcntl_setfl, mkfifoat};
use rustix::io::{Errno, FdFlags, fcntl_setfd, ioctl_fionread};
use rustix::pipe::{PipeFlags, pipe_with};
use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Stdin, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

const MAX_COMMAND: usize = 65_536;
const MAX_INPUT: usize = 6 * MAX_COMMAND + 1024;
const CHUNK: usize = 8192;
const MAX_RETAINED_STREAMS: usize = 128;

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn emit(value: Value) -> io::Result<()> {
    let mut output = io::stdout().lock();
    serde_json::to_writer(&mut output, &value)?;
    output.write_all(b"\n")?;
    output.flush()
}

fn quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&byte))
    {
        value.into()
    } else {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }
}

fn valid_identity(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

struct Directory(PathBuf);

impl Directory {
    fn create() -> io::Result<Self> {
        let mut random = [0_u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut random)?;
        let path = std::env::temp_dir().join(format!(
            "sandcrab-command-{:032x}",
            u128::from_ne_bytes(random)
        ));
        DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Stream {
    reader: File,
    sentinel: Option<File>,
    identity: String,
    name: &'static str,
    path: PathBuf,
}

#[derive(Clone, Copy)]
enum Event {
    Request,
    Reply,
    Output(RawFd),
    Shell,
}

struct ShellLoop {
    directory: Directory,
    execution_variable: String,
    streams: VecDeque<Stream>,
    active: Option<String>,
    requests: Vec<u8>,
    replies: Vec<u8>,
    reply_reader: Option<File>,
    reply_fd: RawFd,
    stdin: Stdin,
    shell: Child,
    pidfd: OwnedFd,
}

impl ShellLoop {
    fn new(directory: &Path, execution_variable: &str) -> io::Result<Self> {
        let streams_directory = Directory::create()?;
        let (reader, writer) = pipe_with(PipeFlags::CLOEXEC)?;
        let reply_fd = writer.as_raw_fd();
        // Only this writer survives bash's exec. Every other driver-owned descriptor has CLOEXEC.
        fcntl_setfd(&writer, FdFlags::empty())?;
        let mut shell = Command::new("/bin/bash")
            .args(["--noprofile", "--norc"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .current_dir(directory)
            .spawn()?;
        drop(writer);
        let pid =
            Pid::from_raw(shell.id() as i32).ok_or_else(|| invalid("Invalid shell process"))?;
        let pidfd = match pidfd_open(pid, PidfdFlags::empty()) {
            Ok(pidfd) => pidfd,
            Err(error) => {
                let _ = shell.kill();
                let _ = shell.wait();
                return Err(error.into());
            }
        };
        let mut driver = Self {
            directory: streams_directory,
            execution_variable: execution_variable.into(),
            streams: VecDeque::new(),
            active: None,
            requests: Vec::new(),
            replies: Vec::new(),
            reply_reader: Some(reader.into()),
            reply_fd,
            stdin: io::stdin(),
            shell,
            pidfd,
        };
        let reader = driver.reply_reader.as_ref().expect("new reply pipe");
        fcntl_setfl(reader, fcntl_getfl(reader)? | OFlags::NONBLOCK)?;
        fcntl_setfl(
            &driver.stdin,
            fcntl_getfl(&driver.stdin)? | OFlags::NONBLOCK,
        )?;
        driver
            .shell
            .stdin
            .as_mut()
            .expect("piped shell stdin")
            .write_all(b"shopt -s expand_aliases\n")?;
        Ok(driver)
    }

    fn begin(&mut self, raw: &[u8]) -> io::Result<()> {
        let request: Value = serde_json::from_slice(raw)?;
        let object = request
            .as_object()
            .ok_or_else(|| invalid("Unexpected command frame"))?;
        if object.len() != 2
            || !object.contains_key("executionId")
            || !object.contains_key("command")
            || self.active.is_some()
        {
            return Err(invalid("Unexpected command frame"));
        }
        let identity = request["executionId"]
            .as_str()
            .filter(|value| valid_identity(value))
            .ok_or_else(|| invalid("Invalid command identity"))?;
        let command = request["command"]
            .as_str()
            .filter(|value| {
                !value.is_empty() && !value.contains('\0') && value.len() <= MAX_COMMAND
            })
            .ok_or_else(|| invalid("Invalid command source"))?;
        while self.streams.len() > MAX_RETAINED_STREAMS - 2 {
            self.release(0)?;
        }
        self.active = Some(identity.into());
        let mut paths = Vec::new();
        for name in ["stdout", "stderr"] {
            let path = self.directory.0.join(format!("{identity}.{name}"));
            mkfifoat(CWD, &path, Mode::RUSR | Mode::WUSR)?;
            let reader = OpenOptions::new()
                .read(true)
                .custom_flags((OFlags::NONBLOCK | OFlags::NOFOLLOW).bits() as i32)
                .open(&path)?;
            // Prevent EOF until bash has opened both writers and emitted START.
            let sentinel = OpenOptions::new()
                .write(true)
                .custom_flags((OFlags::NONBLOCK | OFlags::NOFOLLOW).bits() as i32)
                .open(&path)?;
            self.streams.push_back(Stream {
                reader,
                sentinel: Some(sentinel),
                identity: identity.into(),
                name,
                path: path.clone(),
            });
            paths.push(path);
        }
        let script = format!(
            "{{ builtin printf \"start {identity}\\n\" >&{fd}; export {variable}={id}; \
             builtin eval -- {command}; _sandcrab_command_status=$?; \
             builtin printf \"done {identity} %s\\n\" \"$_sandcrab_command_status\" >&{fd}; \
             }} >{stdout} 2>{stderr} </dev/null\n",
            fd = self.reply_fd,
            variable = self.execution_variable,
            id = quote(identity),
            command = quote(command),
            stdout = quote(&paths[0].to_string_lossy()),
            stderr = quote(&paths[1].to_string_lossy()),
        );
        self.shell
            .stdin
            .as_mut()
            .expect("piped shell stdin")
            .write_all(script.as_bytes())
    }

    fn release(&mut self, index: usize) -> io::Result<()> {
        let stream = self.streams.remove(index).expect("retained stream");
        let path = stream.path.clone();
        drop(stream);
        match fs::remove_file(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }

    fn output(&mut self, descriptor: RawFd, limit: usize) -> io::Result<usize> {
        let Some(index) = self
            .streams
            .iter()
            .position(|stream| stream.reader.as_raw_fd() == descriptor)
        else {
            return Ok(0);
        };
        let stream = &mut self.streams[index];
        let mut data = [0_u8; CHUNK];
        let received = match stream.reader.read(&mut data[..limit.min(CHUNK)]) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(0),
            result => result?,
        };
        if received == 0 {
            self.release(index)?;
        } else if self.active.as_deref() == Some(&stream.identity) {
            emit(json!({"kind": "output", "executionId": stream.identity,
                        "stream": stream.name, "data": STANDARD.encode(&data[..received])}))?;
        }
        // Late background bytes are drained without attributing them to another command.
        Ok(received)
    }

    fn complete(&mut self, status: i32, exited: bool) -> io::Result<()> {
        let Some(identity) = self.active.clone() else {
            return Ok(());
        };
        let descriptors: Vec<_> = self
            .streams
            .iter()
            .filter(|stream| stream.identity == identity)
            .map(|stream| stream.reader.as_raw_fd())
            .collect();
        for descriptor in descriptors {
            if let Some(stream) = self
                .streams
                .iter()
                .find(|stream| stream.reader.as_raw_fd() == descriptor)
            {
                // A finite snapshot bounds completion even when background writers never stop.
                let mut remaining = ioctl_fionread(&stream.reader)? as usize;
                while remaining > 0 {
                    let received = self.output(descriptor, remaining)?;
                    if received == 0 {
                        break;
                    }
                    remaining -= received;
                }
            }
        }
        emit(
            json!({"kind": "complete", "executionId": identity, "exitCode": status, "shellExited": exited}),
        )?;
        self.active = None;
        Ok(())
    }

    fn reply(&mut self, raw: &[u8]) -> io::Result<()> {
        if !raw.is_ascii() {
            return Err(invalid("Invalid shell completion"));
        }
        let text = std::str::from_utf8(raw).map_err(|_| invalid("Invalid shell completion"))?;
        let parts: Vec<_> = text.split(' ').collect();
        if !(2..=3).contains(&parts.len()) || Some(parts[1]) != self.active.as_deref() {
            return Err(invalid("Invalid shell completion"));
        }
        if parts[0] == "start" && parts.len() == 2 {
            for stream in &mut self.streams {
                if Some(stream.identity.as_str()) == self.active.as_deref() {
                    stream.sentinel = None;
                }
            }
            return Ok(());
        }
        if parts[0] != "done"
            || parts.len() != 3
            || parts[2].is_empty()
            || !parts[2].bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(invalid("Invalid shell exit status"));
        }
        let status = parts[2]
            .parse::<u8>()
            .map_err(|_| invalid("Invalid shell exit status"))?;
        self.complete(i32::from(status), false)
    }

    fn events(&self) -> io::Result<Vec<Event>> {
        let mut tags = vec![Event::Request];
        let mut descriptors = vec![PollFd::new(&self.stdin, PollFlags::IN)];
        if let Some(reader) = &self.reply_reader {
            descriptors.push(PollFd::new(reader, PollFlags::IN));
            tags.push(Event::Reply);
        }
        for stream in &self.streams {
            descriptors.push(PollFd::new(&stream.reader, PollFlags::IN));
            tags.push(Event::Output(stream.reader.as_raw_fd()));
        }
        descriptors.push(PollFd::new(&self.pidfd, PollFlags::IN));
        tags.push(Event::Shell);
        rustix::io::retry_on_intr(|| poll(&mut descriptors, None))?;
        Ok(descriptors
            .iter()
            .zip(tags)
            .filter_map(|(fd, event)| {
                if fd.revents().is_empty() {
                    None
                } else {
                    Some(event)
                }
            })
            .collect())
    }

    fn run(&mut self) -> io::Result<()> {
        emit(json!({"kind": "ready"}))?;
        loop {
            for event in self.events()? {
                let mut data = [0_u8; CHUNK];
                let count = match event {
                    Event::Output(descriptor) => {
                        self.output(descriptor, CHUNK)?;
                        continue;
                    }
                    Event::Shell => continue,
                    Event::Request => rustix::io::read(&self.stdin, &mut data),
                    Event::Reply => rustix::io::read(
                        self.reply_reader.as_ref().expect("registered reply pipe"),
                        &mut data,
                    ),
                };
                let count = match count {
                    Err(Errno::AGAIN | Errno::INTR) => continue,
                    result => result?,
                };
                if count == 0 {
                    if matches!(event, Event::Request) {
                        return Ok(());
                    }
                    self.reply_reader = None;
                    continue;
                }
                let request = matches!(event, Event::Request);
                let buffer = if request {
                    &mut self.requests
                } else {
                    &mut self.replies
                };
                buffer.extend_from_slice(&data[..count]);
                if buffer.len() > if request { MAX_INPUT } else { 1024 } {
                    return Err(invalid("Shell channel frame exceeds its bound"));
                }
                loop {
                    let buffer = if request {
                        &mut self.requests
                    } else {
                        &mut self.replies
                    };
                    let Some(end) = buffer.iter().position(|byte| *byte == b'\n') else {
                        break;
                    };
                    let raw: Vec<_> = buffer.drain(..=end).take(end).collect();
                    if request {
                        self.begin(&raw)?;
                    } else {
                        self.reply(&raw)?;
                    }
                }
            }
            if let Some(status) = self.shell.try_wait()? {
                self.complete(
                    status
                        .code()
                        .unwrap_or_else(|| 128 + status.signal().unwrap_or(127)),
                    true,
                )?;
                return Ok(());
            }
        }
    }
}

impl Drop for ShellLoop {
    fn drop(&mut self) {
        if matches!(self.shell.try_wait(), Ok(None)) {
            let _ = pidfd_send_signal(&self.pidfd, Signal::TERM);
            let timeout = Timespec {
                tv_sec: 2,
                tv_nsec: 0,
            };
            if poll(
                &mut [PollFd::new(&self.pidfd, PollFlags::IN)],
                Some(&timeout),
            )
            .unwrap_or(0)
                == 0
            {
                let _ = pidfd_send_signal(&self.pidfd, Signal::KILL);
                let _ = poll(
                    &mut [PollFd::new(&self.pidfd, PollFlags::IN)],
                    Some(&timeout),
                );
            }
            let _ = self.shell.try_wait();
        }
    }
}

/// Serve newline-delimited command frames on stdin and write result frames to stdout.
/// The execution variable is a caller-chosen shell identifier updated before each command;
/// it correlates requests and grants no authority. The caller must enforce time/output limits
/// and contain the entire process tree after cancellation, EOF or any driver failure.
pub fn run(directory: &Path, execution_variable: &str) -> io::Result<()> {
    if !valid_variable(execution_variable) {
        return Err(invalid("Invalid execution variable"));
    }
    ShellLoop::new(directory, execution_variable)?.run()
}

fn valid_variable(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && (value.as_bytes()[0].is_ascii_uppercase() || value.as_bytes()[0] == b'_')
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_variables_cannot_change_the_shell_script() {
        for name in ["SANDBOX_EXECUTION_ID", "REQUEST_ID", "_REQUEST2"] {
            assert!(valid_variable(name));
        }
        for name in [
            "",
            "2REQUEST",
            "BAD; touch /tmp/injected",
            "REQUEST=bad",
            "LOWER_case",
        ] {
            assert!(!valid_variable(name));
        }
        assert!(!valid_variable(&"X".repeat(65)));
    }
    #[test]
    fn identities_are_canonical_and_quotes_preserve_shell_source() {
        assert!(valid_identity("00000000-0000-0000-0000-000000000000"));
        assert!(!valid_identity("00000000-0000-0000-0000-00000000000A"));
        assert_eq!(quote("a b'c"), "'a b'\"'\"'c'");
        assert_eq!(quote("/tmp/a-b"), "/tmp/a-b");
    }
}
