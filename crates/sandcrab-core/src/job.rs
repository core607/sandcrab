//! Finite process execution, bounded output and confirmed delegated-cgroup containment.
//! Admission, identity and authorization belong to the caller.
use crate::process::{Child, Input, Launch};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
};
use std::{
    io::{self, Read},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

/// Why a bounded job ended.
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
    io::Error::other("Job process unavailable")
}
/// Run `launch` once. The timeout, cancellation or output beyond `limit` bytes over both
/// streams kills the launcher and cgroup. The first result is the job's; the second
/// confirms launcher reaping and descendant containment, failing when either is unknown.
/// The synchronous observer receives retained raw output while the job runs; it must not
/// block or interpret progress as proof of completion or containment.
pub fn run(
    launch: &mut Launch,
    cancelled: &AtomicBool,
    timeout: Duration,
    limit: usize,
    on_output: impl FnMut(usize, &[u8]),
) -> (io::Result<Finished>, io::Result<()>) {
    run_input(launch, cancelled, timeout, limit, Input::Null, on_output)
}

/// The caller owns the input producer and must stop it on cancellation. Passing a
/// pipe lets the helper charge staged file pages to its own cgroup.
pub fn run_input(
    launch: &mut Launch,
    cancelled: &AtomicBool,
    timeout: Duration,
    limit: usize,
    input: Input,
    mut on_output: impl FnMut(usize, &[u8]),
) -> (io::Result<Finished>, io::Result<()>) {
    let child = launch.spawn(input);
    let (mut finished, mut child) = match child {
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
    let contained = launch.finish(child.as_mut(), Duration::from_secs(15));
    if let (Ok(finished), Ok(exit)) = (&mut finished, &contained) {
        if finished.end == End::Normal && exit.oom_kills > 0 {
            finished.end = End::ResourceLimit;
        }
        finished.exit_code = exit.code().unwrap_or(-1);
        if finished.end != End::Normal && finished.exit_code == 0 {
            finished.exit_code = if finished.end == End::Timeout {
                124
            } else {
                137
            };
        }
    }
    (finished, contained.map(|_| ()))
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
        child.stdout.take().ok_or_else(unavailable)?,
        child.stderr.take().ok_or_else(unavailable)?,
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
    let mut kill = |reason: End, end: &mut End, child: &mut Child| {
        if *end == End::Normal {
            *end = reason;
        }
        // Retain direct ownership before and after exec; empty cgroup state
        // cannot substitute for reaping the known launcher.
        if Instant::now() >= next_kill {
            let _ = launch.interrupt(child);
            next_kill = Instant::now() + Duration::from_millis(100);
        }
    };
    while open[0] || open[1] {
        if end != End::Normal {
            kill(end, &mut end, child);
        } else if cancelled.load(Ordering::SeqCst) {
            kill(End::Cancelled, &mut end, child);
        } else if started.elapsed() > timeout {
            kill(End::Timeout, &mut end, child);
        }
        // Failed containment remains an error even when output collection is abandoned.
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
                        kill(End::OutputLimit, &mut end, child);
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
    let exit_code = status.code().unwrap_or(-1);
    Ok(Finished {
        exit_code,
        output,
        truncated,
        end,
    })
}
