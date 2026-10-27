//! Bounded collection for a fixed initialization unit; no untrusted host command runs here.
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
};
use std::{
    io::{self, Read},
    os::fd::AsFd,
    process::Child,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
fn nonblocking(fd: &impl AsFd) -> io::Result<()> {
    Ok(fcntl_setfl(fd, fcntl_getfl(fd)? | OFlags::NONBLOCK)?)
}
pub struct Outcome {
    pub exit_code: Option<i32>,
    pub interrupted: bool,
}
impl Outcome {
    pub fn success(&self) -> bool {
        !self.interrupted && self.exit_code == Some(0)
    }
}
pub fn collect(
    child: &mut Child,
    timeout: Duration,
    cancelled: &AtomicBool,
    mut stop: impl FnMut() -> io::Result<()>,
) -> io::Result<Outcome> {
    let mut output = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("Initialization output unavailable"))?;
    let mut error = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("Initialization output unavailable"))?;
    nonblocking(&output)?;
    nonblocking(&error)?;
    let mut open = [true, true];
    let mut total = 0usize;
    let mut failed = false;
    let deadline = Instant::now() + timeout;
    while open.iter().any(|v| *v) || child.try_wait()?.is_none() {
        if cancelled.load(Ordering::SeqCst) || Instant::now() >= deadline || total > 4 * 1024 * 1024
        {
            failed = true;
            stop()?;
            break;
        }
        let ready = {
            let mut pollers = Vec::new();
            if open[0] {
                pollers.push(PollFd::new(&output, PollFlags::IN));
            }
            if open[1] {
                pollers.push(PollFd::new(&error, PollFlags::IN));
            }
            poll(
                &mut pollers,
                Some(&Timespec::try_from(Duration::from_millis(20)).unwrap()),
            )?;
            let active = |fd: &PollFd<'_>| {
                fd.revents()
                    .intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR)
            };
            [
                open[0] && active(&pollers[0]),
                open[1] && active(&pollers[usize::from(open[0])]),
            ]
        };
        for index in 0..2 {
            if !ready[index] {
                continue;
            }
            let mut bytes = [0; 8192];
            let result = if index == 0 {
                output.read(&mut bytes)
            } else {
                error.read(&mut bytes)
            };
            match result {
                Ok(0) => open[index] = false,
                Ok(size) => total += size,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
                Err(e) => return Err(e),
            }
        }
    }
    drop(output);
    drop(error);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Outcome {
                exit_code: status.code(),
                interrupted: failed,
            });
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Ok(Outcome {
                exit_code: None,
                interrupted: true,
            });
        }
        thread::sleep(Duration::from_millis(2));
    }
}
