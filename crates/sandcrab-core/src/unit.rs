//! Transient systemd units, their cgroups and bounded host helper commands.
use serde::Deserialize;
use std::{
    fs, io,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
fn unavailable() -> io::Error {
    io::Error::other("Unit operation unavailable")
}
/// A fixed `systemd-run` command and the unit and cgroup it creates.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Launch {
    pub command: Vec<String>,
    pub unit: String,
    pub cgroup: PathBuf,
}
/// A launched helper unit whose containment must be confirmed before it is forgotten.
pub struct Maintenance {
    pub launch: Launch,
    pub child: Option<std::process::Child>,
}
impl Maintenance {
    pub fn stop(&mut self) -> io::Result<()> {
        let ended = if let Some(child) = &mut self.child {
            child.try_wait()?.is_some()
        } else {
            false
        };
        if !ended || empty_group(&self.launch.cgroup).is_err() {
            stop_launch(&self.launch)?;
        }
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            child.wait()?;
        }
        let _ = checked(
            &[
                "systemctl".into(),
                "reset-failed".into(),
                self.launch.unit.clone(),
            ],
            Duration::from_secs(5),
        );
        Ok(())
    }
}
/// Run a host helper with bounded output and time; any failure kills it.
pub fn checked(args: &[String], timeout: Duration) -> io::Result<Output> {
    use rustix::{
        event::{PollFd, PollFlags, Timespec, poll},
        fs::{OFlags, fcntl_getfl, fcntl_setfl},
    };
    let (program, args) = args.split_first().ok_or_else(unavailable)?;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + timeout;
    let result = (|| {
        let mut out = child.stdout.take().ok_or_else(unavailable)?;
        let mut err = child.stderr.take().ok_or_else(unavailable)?;
        fcntl_setfl(&out, fcntl_getfl(&out)? | OFlags::NONBLOCK)?;
        fcntl_setfl(&err, fcntl_getfl(&err)? | OFlags::NONBLOCK)?;
        let mut open = [true, true];
        let mut bytes = [Vec::new(), Vec::new()];
        loop {
            let status = child.try_wait()?;
            if !open[0]
                && !open[1]
                && let Some(status) = status
            {
                if !status.success() {
                    return Err(unavailable());
                }
                return Ok(Output {
                    status,
                    stdout: std::mem::take(&mut bytes[0]),
                    stderr: std::mem::take(&mut bytes[1]),
                });
            }
            if Instant::now() >= deadline {
                return Err(unavailable());
            }
            let ready = {
                let mut fds = Vec::new();
                if open[0] {
                    fds.push(PollFd::new(&out, PollFlags::IN));
                }
                if open[1] {
                    fds.push(PollFd::new(&err, PollFlags::IN));
                }
                poll(
                    &mut fds,
                    Some(&Timespec::try_from(Duration::from_millis(20)).unwrap()),
                )?;
                let ready = |fd: &PollFd<'_>| {
                    fd.revents()
                        .intersects(PollFlags::IN | PollFlags::ERR | PollFlags::HUP)
                };
                [
                    open[0] && ready(&fds[0]),
                    open[1] && ready(&fds[usize::from(open[0])]),
                ]
            };
            for index in 0..2 {
                if !ready[index] {
                    continue;
                }
                let mut buffer = [0; 8192];
                let part = if index == 0 {
                    out.read(&mut buffer)
                } else {
                    err.read(&mut buffer)
                };
                match part {
                    Ok(0) => open[index] = false,
                    Ok(n) => bytes[index].extend_from_slice(&buffer[..n]),
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(e) => return Err(e),
                }
                if bytes[0].len() + bytes[1].len() > 1_048_576 {
                    return Err(unavailable());
                }
            }
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}
/// Every process has left the cgroup and its descendants.
pub fn empty_group(path: &Path) -> io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    if !fs::read_to_string(path.join("cgroup.procs"))?
        .trim()
        .is_empty()
    {
        return Err(unavailable());
    }
    for entry in fs::read_dir(path)? {
        let path = entry?.path();
        if path.is_dir() {
            empty_group(&path)?;
        }
    }
    Ok(())
}
/// The current process runs inside `pool`, whose memory, task and CPU limits are finite.
pub fn verify_resource_pool(pool: &Path) -> io::Result<()> {
    let current = fs::read_to_string("/proc/self/cgroup")?;
    let actual = current
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(unavailable)?;
    if !Path::new("/sys/fs/cgroup")
        .join(actual.trim_start_matches('/'))
        .starts_with(pool)
    {
        return Err(unavailable());
    }
    for name in ["memory.max", "memory.swap.max", "pids.max"] {
        let number = fs::read_to_string(pool.join(name))?
            .trim()
            .parse::<u64>()
            .map_err(|_| unavailable())?;
        if number == 0 && name != "memory.swap.max" {
            return Err(unavailable());
        }
    }
    let max = fs::read_to_string(pool.join("cpu.max"))?;
    let parts = max
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| unavailable())?;
    if parts.len() != 2 || parts.contains(&0) {
        return Err(unavailable());
    }
    Ok(())
}
/// Stop a unit and confirm that its cgroup is empty.
pub fn stop_launch(launch: &Launch) -> io::Result<()> {
    checked(
        &["systemctl".into(), "stop".into(), launch.unit.clone()],
        Duration::from_secs(15),
    )?;
    empty_group(&launch.cgroup)?;
    Ok(())
}
/// Run `action` while the cgroup is frozen; a failed thaw cancels the caller.
pub fn frozen<T>(
    cgroup: &Path,
    cancelled: &AtomicBool,
    action: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    let freeze = cgroup.join("cgroup.freeze");
    let result = (|| {
        fs::write(&freeze, b"1")?;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if cancelled.load(Ordering::SeqCst) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            if Instant::now() >= deadline {
                return Err(unavailable());
            }
            if fs::read_to_string(cgroup.join("cgroup.events"))?
                .lines()
                .any(|line| line == "frozen 1")
            {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        action()
    })();
    if fs::write(&freeze, b"0").is_err() {
        cancelled.store(true, Ordering::SeqCst);
        return Err(unavailable());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn helper_output_is_drained_beyond_a_pipe_capacity() {
        let output = checked(
            &[
                "/bin/sh".into(),
                "-c".into(),
                "head -c 131072 /dev/zero; head -c 131072 /dev/zero >&2".into(),
            ],
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(output.stdout.len(), 131072);
        assert_eq!(output.stderr.len(), 131072);
    }
    #[test]
    fn helper_failure_output_limit_and_timeout_are_checked() {
        for (command, timeout) in [
            ("exit 1", Duration::from_secs(1)),
            ("head -c 1048577 /dev/zero", Duration::from_secs(2)),
            ("sleep 1", Duration::from_millis(20)),
        ] {
            assert!(checked(&["/bin/sh".into(), "-c".into(), command.into()], timeout).is_err());
        }
    }
}
