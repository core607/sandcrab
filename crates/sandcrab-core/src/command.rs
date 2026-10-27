//! Bounded native transport for the existing persistent sandbox shell protocol.
use base64::{Engine, engine::general_purpose::STANDARD};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
};
use serde_json::{Value, json};
use std::{
    io::{self, Read, Write},
    os::fd::AsFd,
    process::{Child, ChildStderr, ChildStdin, ChildStdout},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
const MAX_FRAME: usize = 65536;
const MAX_OUTPUT: usize = 4 * 1024 * 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    Cancelled,
    Timeout,
    OutputLimit,
    SandboxFailed,
}
#[derive(Debug)]
pub struct Captured {
    pub output: [Vec<u8>; 2],
    pub truncated: [bool; 2],
}
impl Captured {
    fn new() -> Self {
        Self {
            output: [Vec::new(), Vec::new()],
            truncated: [false, false],
        }
    }
    fn append(&mut self, stream: usize, bytes: &[u8]) -> Result<(), EndReason> {
        let available = MAX_OUTPUT - self.output.iter().map(Vec::len).sum::<usize>();
        self.output[stream].extend_from_slice(&bytes[..available.min(bytes.len())]);
        if bytes.len() > available {
            self.truncated[stream] = true;
            Err(EndReason::OutputLimit)
        } else {
            Ok(())
        }
    }
}
#[derive(Debug)]
pub struct Run {
    pub reason: Option<EndReason>,
    pub exit_code: u8,
    pub shell_exited: bool,
    pub captured: Captured,
    pub ready_ms: u64,
    pub command_ms: Option<u64>,
}
pub struct Channel {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
    diagnostic: ChildStderr,
    buffer: Vec<u8>,
    ready: bool,
    output_open: bool,
    diagnostic_open: bool,
}
fn nonblocking(fd: &impl AsFd) -> io::Result<()> {
    Ok(fcntl_setfl(fd, fcntl_getfl(fd)? | OFlags::NONBLOCK)?)
}
fn invalid() -> io::Error {
    io::Error::other("Invalid shell protocol")
}
enum Event {
    Frame(Value),
    Diagnostic(Vec<u8>),
}
impl Channel {
    pub fn new(mut child: Child) -> io::Result<Self> {
        let input = child.stdin.take().ok_or_else(invalid)?;
        let output = child.stdout.take().ok_or_else(invalid)?;
        let diagnostic = child.stderr.take().ok_or_else(invalid)?;
        nonblocking(&input)?;
        nonblocking(&output)?;
        nonblocking(&diagnostic)?;
        Ok(Self {
            child,
            input,
            output,
            diagnostic,
            buffer: Vec::new(),
            ready: false,
            output_open: true,
            diagnostic_open: true,
        })
    }
    pub fn process(&mut self) -> &mut Child {
        &mut self.child
    }
    pub fn ready(&self) -> bool {
        self.ready
    }
    fn events(&mut self, wait: Duration) -> io::Result<Vec<Event>> {
        if !self.output_open && !self.diagnostic_open {
            return Err(invalid());
        }
        let mut result = Vec::new();
        let (output_ready, diagnostic_ready) = {
            let mut pollers = Vec::new();
            if self.output_open {
                pollers.push(PollFd::new(&self.output, PollFlags::IN));
            }
            if self.diagnostic_open {
                pollers.push(PollFd::new(&self.diagnostic, PollFlags::IN));
            }
            let timeout = Timespec::try_from(wait).map_err(|_| invalid())?;
            poll(&mut pollers, Some(&timeout))?;
            let ready = |value: &PollFd<'_>| {
                value
                    .revents()
                    .intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR)
            };
            (
                self.output_open && ready(&pollers[0]),
                self.diagnostic_open && ready(&pollers[usize::from(self.output_open)]),
            )
        };
        if output_ready {
            let mut bytes = [0; 8192];
            match self.output.read(&mut bytes) {
                Ok(0) => self.output_open = false,
                Ok(size) => self.buffer.extend_from_slice(&bytes[..size]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => (),
                Err(error) => return Err(error),
            }
            while let Some(end) = self.buffer.iter().position(|b| *b == b'\n') {
                if end > MAX_FRAME {
                    return Err(invalid());
                }
                let value = super::parse(&self.buffer[..end]).map_err(|_| invalid())?;
                self.buffer.drain(..end + 1);
                result.push(Event::Frame(value));
            }
            if self.buffer.len() > MAX_FRAME {
                return Err(invalid());
            }
        }
        if diagnostic_ready {
            let mut bytes = [0; 8192];
            match self.diagnostic.read(&mut bytes) {
                Ok(0) => self.diagnostic_open = false,
                Ok(size) => result.push(Event::Diagnostic(bytes[..size].to_vec())),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => (),
                Err(error) => return Err(error),
            }
        }
        if result.is_empty() && !self.output_open && !self.diagnostic_open {
            return Err(invalid());
        }
        Ok(result)
    }
    pub fn execute(
        &mut self,
        execution: &str,
        command: &str,
        timeout: Duration,
        cancelled: &AtomicBool,
        on_ready: impl FnOnce(),
    ) -> Run {
        let started = Instant::now();
        let deadline = started + timeout;
        let mut command_started = self.ready.then(Instant::now);
        let mut captured = Captured::new();
        let check = || {
            if cancelled.load(Ordering::SeqCst) {
                Err(EndReason::Cancelled)
            } else if Instant::now() >= deadline {
                Err(EndReason::Timeout)
            } else {
                Ok(())
            }
        };
        let result = (|| -> Result<(u8, bool), EndReason> {
            while !self.ready {
                check()?;
                for event in self
                    .events(
                        deadline
                            .saturating_duration_since(Instant::now())
                            .min(Duration::from_millis(50)),
                    )
                    .map_err(|_| EndReason::SandboxFailed)?
                {
                    match event {
                        Event::Diagnostic(bytes) => captured.append(1, &bytes)?,
                        Event::Frame(value) if value == json!({"kind":"ready"}) => {
                            self.ready = true;
                            command_started = Some(Instant::now());
                        }
                        Event::Frame(_) => return Err(EndReason::SandboxFailed),
                    }
                }
            }
            on_ready();
            let mut frame = serde_json::to_vec(&json!({"executionId":execution,"command":command}))
                .map_err(|_| EndReason::SandboxFailed)?;
            frame.push(b'\n');
            let mut position = 0;
            while position < frame.len() {
                check()?;
                let mut pollers = [PollFd::new(&self.input, PollFlags::OUT)];
                poll(
                    &mut pollers,
                    Some(&Timespec::try_from(Duration::from_millis(50)).unwrap()),
                )
                .map_err(|_| EndReason::SandboxFailed)?;
                if pollers[0]
                    .revents()
                    .intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL)
                {
                    return Err(EndReason::SandboxFailed);
                }
                if !pollers[0].revents().contains(PollFlags::OUT) {
                    continue;
                }
                match self.input.write(&frame[position..]) {
                    Ok(0) => return Err(EndReason::SandboxFailed),
                    Ok(size) => position += size,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => (),
                    Err(_) => return Err(EndReason::SandboxFailed),
                }
            }
            loop {
                check()?;
                for event in self
                    .events(
                        deadline
                            .saturating_duration_since(Instant::now())
                            .min(Duration::from_millis(50)),
                    )
                    .map_err(|_| EndReason::SandboxFailed)?
                {
                    let value = match event {
                        Event::Diagnostic(bytes) => {
                            captured.append(1, &bytes)?;
                            continue;
                        }
                        Event::Frame(value) => value,
                    };
                    let object = value.as_object().ok_or(EndReason::SandboxFailed)?;
                    if value["executionId"] != execution {
                        return Err(EndReason::SandboxFailed);
                    }
                    match value["kind"].as_str() {
                        Some("output") => {
                            if object.len() != 4 || !object.contains_key("data") {
                                return Err(EndReason::SandboxFailed);
                            }
                            let index = match value["stream"].as_str() {
                                Some("stdout") => 0,
                                Some("stderr") => 1,
                                _ => return Err(EndReason::SandboxFailed),
                            };
                            let bytes = STANDARD
                                .decode(value["data"].as_str().ok_or(EndReason::SandboxFailed)?)
                                .map_err(|_| EndReason::SandboxFailed)?;
                            if bytes.len() > 8192 {
                                return Err(EndReason::SandboxFailed);
                            }
                            captured.append(index, &bytes)?;
                        }
                        Some("complete") => {
                            if object.len() != 4 {
                                return Err(EndReason::SandboxFailed);
                            }
                            let code = value["exitCode"]
                                .as_u64()
                                .filter(|v| *v <= 255)
                                .ok_or(EndReason::SandboxFailed)?;
                            let exited = value["shellExited"]
                                .as_bool()
                                .ok_or(EndReason::SandboxFailed)?;
                            return Ok((code as u8, exited));
                        }
                        _ => return Err(EndReason::SandboxFailed),
                    }
                }
            }
        })();
        let ended = Instant::now();
        let (reason, exit_code, shell_exited) = match result {
            Ok((code, exited)) => (None, code, exited),
            Err(reason) => (
                Some(reason),
                if reason == EndReason::Timeout {
                    124
                } else {
                    137
                },
                true,
            ),
        };
        Run {
            reason,
            exit_code,
            shell_exited,
            captured,
            ready_ms: command_started
                .unwrap_or(ended)
                .duration_since(started)
                .as_millis() as u64,
            command_ms: command_started.map(|time| ended.duration_since(time).as_millis() as u64),
        }
    }
}
impl Drop for Channel {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        process::{Command, Stdio},
        sync::Arc,
        thread,
    };
    const EXEC: &str = "11111111-1111-1111-1111-111111111111";
    fn helper(body: &str) -> Channel {
        let child = Command::new("/bin/sh")
            .args(["-c", body])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        Channel::new(child).unwrap()
    }
    #[test]
    fn completion_captures_output_and_exit_status() {
        let mut channel = helper(
            r#"printf '%s\n' '{"kind":"ready"}'; read -r request; printf '%s\n' '{"kind":"output","executionId":"11111111-1111-1111-1111-111111111111","stream":"stdout","data":"aGVsbG8="}' '{"kind":"complete","executionId":"11111111-1111-1111-1111-111111111111","exitCode":17,"shellExited":false}'; read -r ignored"#,
        );
        let result = channel.execute(
            EXEC,
            "true",
            Duration::from_secs(1),
            &AtomicBool::new(false),
            || {},
        );
        assert_eq!(result.reason, None);
        assert_eq!(result.exit_code, 17);
        assert!(!result.shell_exited);
        assert_eq!(result.captured.output[0], b"hello");
        assert!(!result.captured.truncated[0]);
        assert!(result.ready_ms < 1000 && result.command_ms.is_some());
        assert!(channel.ready());
        assert!(channel.process().try_wait().unwrap().is_none());
    }
    #[test]
    fn a_foreign_execution_frame_fails_closed() {
        let mut channel = helper(
            r#"printf '%s\n' '{"kind":"ready"}'; read -r request; printf '%s\n' '{"kind":"complete","executionId":"wrong","exitCode":0,"shellExited":false}'; read -r ignored"#,
        );
        let result = channel.execute(
            EXEC,
            "true",
            Duration::from_secs(1),
            &AtomicBool::new(false),
            || {},
        );
        assert_eq!(result.reason, Some(EndReason::SandboxFailed));
    }
    #[test]
    fn a_closed_shell_input_does_not_wait_for_the_command_timeout() {
        let mut channel =
            helper(r#"printf '%s\n' '{"kind":"ready"}'; sleep 0.05; exec 0<&-; sleep 2"#);
        // Escaping keeps the command within 64 KiB while its frame fills the Linux pipe.
        let command = "\n".repeat(65536);
        let started = Instant::now();
        let result = channel.execute(
            EXEC,
            &command,
            Duration::from_millis(800),
            &AtomicBool::new(false),
            || {},
        );
        assert_eq!(result.reason, Some(EndReason::SandboxFailed));
        assert!(started.elapsed() < Duration::from_millis(500));
    }
    #[test]
    fn cancellation_and_timeout_interrupt_a_wait() {
        for cancel in [false, true] {
            let mut channel =
                helper(r#"printf '%s\n' '{"kind":"ready"}'; read -r request; read -r ignored"#);
            let flag = Arc::new(AtomicBool::new(false));
            let signaller = flag.clone();
            let update = thread::spawn(move || {
                thread::sleep(Duration::from_millis(20));
                signaller.store(cancel, Ordering::SeqCst);
            });
            let result = channel.execute(EXEC, "true", Duration::from_millis(100), &flag, || {});
            update.join().unwrap();
            assert_eq!(
                result.reason,
                Some(if cancel {
                    EndReason::Cancelled
                } else {
                    EndReason::Timeout
                })
            );
        }
    }
    #[test]
    fn output_never_exceeds_the_combined_bound() {
        let mut capture = Captured::new();
        capture.append(0, &vec![b'x'; MAX_OUTPUT - 2]).unwrap();
        assert_eq!(capture.append(1, b"more"), Err(EndReason::OutputLimit));
        assert_eq!(
            capture.output[0].len() + capture.output[1].len(),
            MAX_OUTPUT
        );
        assert!(capture.truncated[1]);
    }
}
