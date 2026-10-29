//! Sandbox-side opaque call client. A lost reply never resubmits the request.
use crate::{
    config::invalid,
    host_calls::{BYTES, DIRECTORY, FRAME, decode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::OFlags,
};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, Read, Write},
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    path::Path,
    thread,
    time::{Duration, Instant},
};

pub fn input(path: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    if path == Path::new("-") {
        io::stdin()
            .lock()
            .take(BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
    } else {
        File::open(path)?
            .take(BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
    }
    if bytes.len() > BYTES {
        return Err(invalid("Host-call payload exceeds 65536 bytes"));
    }
    Ok(bytes)
}
fn read(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    let info = file.metadata()?;
    // Host root is unmapped in the guest user namespace. The fixed protected mount,
    // nonsymlink files and non-writable response permissions carry this boundary.
    if !info.is_file() || info.nlink() != 1 || info.mode() & 0o022 != 0 {
        return Err(invalid("Untrusted host-call response"));
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(invalid("Host-call response exceeds its bound"));
    }
    Ok(bytes)
}
fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|v| !v.is_zero())
        .ok_or_else(|| io::ErrorKind::TimedOut.into())
}
fn pause(deadline: Instant) -> io::Result<()> {
    thread::sleep(remaining(deadline)?.min(Duration::from_millis(10)));
    Ok(())
}
fn send(root: &Path, value: &Value, deadline: Instant) -> io::Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > FRAME {
        return Err(invalid("Host-call frame exceeds its bound"));
    }
    let lock = OpenOptions::new()
        .read(true)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(root.join("lock"))?;
    loop {
        match lock.try_lock() {
            Ok(()) => break,
            Err(TryLockError::WouldBlock) => pause(deadline)?,
            Err(TryLockError::Error(error)) => return Err(error),
        }
    }
    let mut pipe = OpenOptions::new()
        .write(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
        .open(root.join("requests"))?;
    let info = pipe.metadata()?;
    if !info.file_type().is_fifo() || info.mode() & 0o7777 != 0o620 {
        return Err(invalid("Invalid host-call channel"));
    }
    let mut frame = (bytes.len() as u32).to_be_bytes().to_vec();
    frame.extend(bytes);
    let mut unsent = frame.as_slice();
    while !unsent.is_empty() {
        let wait = Timespec::try_from(remaining(deadline)?.min(Duration::from_millis(50)))
            .map_err(|_| invalid("Invalid host-call timeout"))?;
        match poll(&mut [PollFd::new(&pipe, PollFlags::OUT)], Some(&wait)) {
            Ok(0) => continue,
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
            _ => (),
        }
        match pipe.write(unsent) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => unsent = &unsent[n..],
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
pub fn call(path: &Path, timeout: u64) -> io::Result<i32> {
    if !(1..=300000).contains(&timeout) {
        return Err(invalid(
            "Host-call timeout must be 1 to 300000 milliseconds",
        ));
    }
    let bytes = input(path)?;
    let root = Path::new(DIRECTORY);
    let info = fs::symlink_metadata(root)?;
    if !info.is_dir() || info.mode() & 0o022 != 0 {
        return Err(invalid("Host calls are unavailable in this sandbox"));
    }
    let execution = std::env::var("SANDBOX_EXECUTION_ID").unwrap_or_default();
    if !sandcrab_core::uuid(&execution) || read(&root.join("state"), 64)? != execution.as_bytes() {
        return Err(invalid("Host calls require the active sandbox command"));
    }
    let id = sandcrab_core::new_uuid()?;
    let deadline = Instant::now() + Duration::from_millis(timeout);
    eprintln!("requestId={id} runId={execution}");
    let result = (|| {
        send(
            root,
            &json!({"requestId":id,"executionId":execution,"operation":"call",
            "arguments":{"base64":STANDARD.encode(bytes)}}),
            deadline,
        )?;
        loop {
            remaining(deadline)?;
            if read(&root.join("state"), 64)? != execution.as_bytes() {
                return Err(invalid("Host-call command ended"));
            }
            let raw = match read(&root.join("responses").join(format!("{id}.json")), FRAME) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    pause(deadline)?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let value =
                sandcrab_core::parse(&raw).map_err(|_| invalid("Invalid host-call response"))?;
            if value.as_object().is_none_or(|v| v.len() != 1) {
                return Err(invalid("Invalid host-call response"));
            }
            let reply = decode(&value["base64"]).map_err(invalid)?;
            // A failed acknowledgement does not erase an already received reply.
            let _ = send(
                root,
                &json!({"requestId":id,"executionId":execution,"operation":"ack"}),
                deadline,
            );
            return Ok(reply);
        }
    })();
    let reply = result.map_err(|_: io::Error| {
        invalid(format!(
            "Request {id} outcome is unknown; inspect this run's call records before any retry"
        ))
    })?;
    io::stdout().lock().write_all(&reply)?;
    Ok(0)
}
