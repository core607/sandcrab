//! Finite process execution, bounded output and confirmed unit containment.
//! Admission, identity and authorization belong to the caller.
use crate::unit::{Launch, checked, empty_group};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
};
use std::{
    fs::File,
    io::{self, Read},
    os::fd::OwnedFd,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

/// Why a job's unit ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    Normal,
    Timeout,
    OutputLimit,
    Cancelled,
    ResourceLimit,
}
pub struct Finished {
    pub exit_code: i32,
    /// Standard output and standard error, together at most the job's output limit.
    pub output: [Vec<u8>; 2],
    pub truncated: bool,
    pub end: End,
}
fn unavailable() -> io::Error {
    io::Error::other("Job unit unavailable")
}
fn systemctl(args: &[&str], unit: &str, seconds: u64) -> io::Result<std::process::Output> {
    let mut command = vec!["systemctl".to_string()];
    command.extend(args.iter().map(|v| v.to_string()));
    command.push(unit.into());
    checked(&command, Duration::from_secs(seconds))
}

/// Run `launch` once. The timeout, cancellation or output beyond `limit` bytes over both
/// streams kills the unit. The first result is the job's; the second confirms that the unit
/// stopped and left no process, and is an error whenever that is unknown.
/// The synchronous observer receives retained raw output while the job runs; it must not
/// block or interpret progress as proof of completion or containment.
pub fn run(
    launch: &Launch,
    cancelled: &AtomicBool,
    timeout: Duration,
    limit: usize,
    on_output: impl FnMut(usize, &[u8]),
) -> (io::Result<Finished>, io::Result<()>) {
    run_input(launch, cancelled, timeout, limit, Stdio::null(), on_output)
}

/// The caller owns the input producer and must stop it on cancellation. Passing a
/// pipe lets a bounded unit charge staged file pages to its own cgroup.
pub fn run_input(
    launch: &Launch,
    cancelled: &AtomicBool,
    timeout: Duration,
    limit: usize,
    input: Stdio,
    mut on_output: impl FnMut(usize, &[u8]),
) -> (io::Result<Finished>, io::Result<()>) {
    let (program, args) = match launch.command.split_first() {
        Some(parts) => parts,
        None => return (Err(unavailable()), Ok(())),
    };
    let child = Command::new(program)
        .args(args)
        .stdin(input)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let (finished, mut child) = match child {
        Ok(mut child) => (
            watch(
                launch,
                &mut child,
                cancelled,
                timeout,
                limit,
                &mut on_output,
            ),
            Some(child),
        ),
        Err(error) => (Err(error), None),
    };
    let _ = systemctl(&["stop"], &launch.unit, 15);
    let mut contained = Ok(());
    if let Some(child) = &mut child
        && child.try_wait().ok().flatten().is_none()
    {
        let _ = child.kill();
        contained = child.wait().map(|_| ());
    }
    let contained = contained.and_then(|()| empty_group(&launch.cgroup));
    let _ = systemctl(&["reset-failed"], &launch.unit, 5);
    (finished, contained)
}
fn watch(
    launch: &Launch,
    child: &mut Child,
    cancelled: &AtomicBool,
    timeout: Duration,
    limit: usize,
    on_output: &mut impl FnMut(usize, &[u8]),
) -> io::Result<Finished> {
    let mut streams = [
        File::from(OwnedFd::from(child.stdout.take().ok_or_else(unavailable)?)),
        File::from(OwnedFd::from(child.stderr.take().ok_or_else(unavailable)?)),
    ];
    for stream in &streams {
        fcntl_setfl(stream, fcntl_getfl(stream)? | OFlags::NONBLOCK)?;
    }
    let started = Instant::now();
    let mut open = [true, true];
    let mut output = [Vec::new(), Vec::new()];
    let mut truncated = false;
    let mut end = End::Normal;
    let mut next_kill = started;
    let mut kill = |reason: End, end: &mut End| {
        if *end == End::Normal {
            *end = reason;
        }
        // systemd-run can still be registering the unit. Neither a failed kill nor a
        // successful kill of an activating unit proves its future processes are gone.
        if Instant::now() >= next_kill {
            let _ = systemctl(
                &["kill", "--kill-who=all", "--signal=KILL"],
                &launch.unit,
                5,
            );
            next_kill = Instant::now() + Duration::from_millis(100);
        }
    };
    while open[0] || open[1] {
        if end != End::Normal {
            kill(end, &mut end);
        } else if cancelled.load(Ordering::SeqCst) {
            kill(End::Cancelled, &mut end);
        } else if started.elapsed() > timeout {
            kill(End::Timeout, &mut end);
        }
        // A killed unit closes its pipes promptly; a launcher that does not is abandoned.
        if started.elapsed() > timeout + Duration::from_secs(15) {
            return Err(unavailable());
        }
        let ready = {
            let indices: Vec<usize> = (0..2).filter(|index| open[*index]).collect();
            let mut fds: Vec<_> = indices
                .iter()
                .map(|index| PollFd::new(&streams[*index], PollFlags::IN))
                .collect();
            poll(
                &mut fds,
                Some(&Timespec::try_from(Duration::from_millis(50)).unwrap()),
            )?;
            let mut ready = [false, false];
            for (index, fd) in indices.iter().zip(&fds) {
                ready[*index] = fd
                    .revents()
                    .intersects(PollFlags::IN | PollFlags::ERR | PollFlags::HUP);
            }
            ready
        };
        for index in 0..2 {
            if !ready[index] {
                continue;
            }
            let mut buffer = [0; 8192];
            match streams[index].read(&mut buffer) {
                Ok(0) => open[index] = false,
                Ok(n) => {
                    let available = limit - output[0].len() - output[1].len();
                    output[index].extend_from_slice(&buffer[..n.min(available)]);
                    if available != 0 {
                        on_output(index, &buffer[..n.min(available)]);
                    }
                    if n > available {
                        truncated = true;
                        kill(End::OutputLimit, &mut end);
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
        }
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            return Err(unavailable());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let shown = systemctl(
        &["show", "-p", "Result", "-p", "ExecMainStatus"],
        &launch.unit,
        5,
    )?;
    let shown = String::from_utf8_lossy(&shown.stdout);
    let property = |name: &str| {
        shown
            .lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
    };
    if end == End::Normal {
        match property("Result") {
            Some("timeout") => end = End::Timeout,
            Some("oom-kill") => end = End::ResourceLimit,
            _ => {}
        }
    }
    let mut exit_code = property("ExecMainStatus")
        .and_then(|v| v.parse().ok())
        .or(status.code())
        .unwrap_or(-1);
    if end != End::Normal && exit_code == 0 {
        exit_code = if end == End::Timeout { 124 } else { 137 };
    }
    Ok(Finished {
        exit_code,
        output,
        truncated,
        end,
    })
}
