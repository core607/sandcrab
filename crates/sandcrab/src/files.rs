//! Native upload admission, bounded pipe ingestion and request-scoped snapshots.
use crate::{
    config::invalid,
    file_access::{Access, Lease},
    file_io::{Format, Job, digest, valid_path},
    file_records::{Result, Stage, Upload},
    service::{Service, error},
};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
    pipe::{PipeFlags, pipe_with},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

fn freeze() -> bool {
    true
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Capture {
    pub path: String,
    pub format: Format,
    #[serde(default = "freeze")]
    pub freeze: bool,
}
pub struct Snapshot {
    pub file: File,
    pub bytes: u64,
    pub sha256: String,
    pub format: Format,
    pub lease: Lease,
    stage: Stage,
}
struct Active<'a> {
    service: &'a Service,
    id: String,
}
impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.service
            .file_cancellations
            .lock()
            .unwrap()
            .remove(&self.id);
    }
}
fn metadata(result: Result<Value>) -> (u16, Value) {
    match result {
        Ok(value) => (200, value),
        Err((status, code)) => error(status, code),
    }
}
fn code(error: &io::Error) -> String {
    let value = error.to_string();
    if !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
    {
        value
    } else {
        crate::file_io::error_code(error).into()
    }
}
fn stage(id: &str, access: &Access) -> Stage {
    Stage {
        id: id.into(),
        session_id: access.session.clone(),
        volume_id: access.volume.clone(),
        profile: access.profile_name.clone(),
        uid: access.profile.uid,
        gid: access.profile.gid,
    }
}
fn job(action: &str, path: &str, format: Format, access: &Access, stage: &std::path::Path) -> Job {
    Job {
        action: action.into(),
        workspace: access.workspace.clone(),
        stage: stage.into(),
        path: path.into(),
        format,
        bytes: 0,
        sha256: String::new(),
        replace: false,
        mode: if format == Format::Tar { 0o755 } else { 0o644 },
        uid: access.profile.uid,
        gid: access.profile.gid,
        byte_limit: access.profile.transfer_bytes,
        entry_limit: 10000,
    }
}

impl Service {
    fn file_access(&self, id: &str) -> Result<Arc<Access>> {
        if self.stopped.load(Ordering::SeqCst) {
            return Err((503, "STOPPING"));
        }
        if !self.runtime.files.available() {
            return Err((503, "FILE_STATE_UNCERTAIN"));
        }
        let mut registry = self.registry.lock().unwrap();
        registry.expire_sessions();
        let session = registry
            .sessions
            .get(id)
            .ok_or((404, "SESSION_NOT_FOUND"))?;
        if !["ready", "busy"].contains(&session.state.as_str()) {
            return Err((409, "SESSION_NOT_READY"));
        }
        session.files.clone().ok_or((409, "SESSION_NOT_READY"))
    }
    fn file_lease(&self, id: &str) -> Result<Lease> {
        self.file_access(id)?
            .acquire(
                self.file_count.clone(),
                self.runtime.config.service.max_file_transfers,
            )
            .map_err(|code| (if code == "FILE_CAPACITY" { 429 } else { 409 }, code))
    }
    pub fn file_route(&self, method: &str, path: &str, body: &[u8]) -> (u16, Value) {
        let parse = || sandcrab_core::parse(body).ok();
        if method == "POST" && path == "/v1/uploads" {
            let Some(input) = parse().and_then(|v| serde_json::from_value::<Upload>(v).ok()) else {
                return error(400, "INVALID_REQUEST");
            };
            if !input.valid() {
                return error(400, "INVALID_REQUEST");
            }
            match self.runtime.files.existing(&input) {
                Ok(Some(record)) => return (200, record.value()),
                Err((status, code)) => return error(status, code),
                _ => (),
            }
            if input.server_id != self.id {
                return error(409, "SERVER_CHANGED");
            }
            let access = match self.file_access(&input.session_id) {
                Ok(v) => v,
                Err((status, code)) => return error(status, code),
            };
            if input.bytes > access.profile.transfer_bytes {
                return error(413, "FILE_LIMIT");
            }
            return match self.runtime.files.create(
                input,
                access.profile_name.clone(),
                access.volume.clone(),
            ) {
                Ok(record) => (201, record.value()),
                Err((status, code)) => error(status, code),
            };
        }
        if method == "GET" && (path == "/v1/uploads" || path.starts_with("/v1/uploads?")) {
            let after = if path == "/v1/uploads" {
                ""
            } else {
                match path
                    .strip_prefix("/v1/uploads?after=")
                    .filter(|s| sandcrab_core::uuid(s))
                {
                    Some(v) => v,
                    None => return error(400, "INVALID_REQUEST"),
                }
            };
            return (200, self.runtime.files.list(after));
        }
        let Some(path) = path.strip_prefix("/v1/uploads/") else {
            return error(404, "NOT_FOUND");
        };
        let (id, action) = path.split_once('/').unwrap_or((path, ""));
        if !sandcrab_core::uuid(id) {
            return error(404, "UPLOAD_NOT_FOUND");
        }
        if method == "GET" && action.is_empty() {
            return metadata(self.runtime.files.get(id).map(|r| r.value()));
        }
        if method == "POST" && ["cancel", "forget"].contains(&action) {
            if parse() != Some(json!({})) {
                return error(400, "INVALID_REQUEST");
            }
            if action == "forget" {
                return metadata(
                    self.runtime
                        .files
                        .forget(id)
                        .map(|_| json!({"forgotten":true})),
                );
            }
            let record = match self.runtime.files.get(id) {
                Ok(r) => r,
                Err((status, code)) => return error(status, code),
            };
            if record.state == "waiting" {
                return metadata(
                    self.runtime
                        .files
                        .transition(id, &["waiting"], "failed", Some("FILE_CANCELLED"))
                        .map(|r| r.value()),
                );
            }
            if let Some(flag) = self.file_cancellations.lock().unwrap().get(id) {
                flag.store(true, Ordering::SeqCst);
            }
            return (200, record.value());
        }
        error(404, "NOT_FOUND")
    }

    pub fn receive_upload(
        &self,
        id: &str,
        length: u64,
        body: &mut impl Read,
        deadline: Instant,
        accepted: impl FnOnce() -> io::Result<()>,
    ) -> (u16, Value) {
        let record = match self.runtime.files.get(id) {
            Ok(r) => r,
            Err((status, code)) => return error(status, code),
        };
        if record.terminal() {
            return (200, record.value());
        }
        if record.state != "waiting" {
            return error(409, "UPLOAD_ACTIVE");
        }
        if length != record.request.bytes {
            return error(400, "CONTENT_LENGTH_MISMATCH");
        }
        let lease = match self.file_lease(&record.request.session_id) {
            Ok(l) => l,
            Err((status, code)) => return error(status, code),
        };
        if length > lease.access.profile.transfer_bytes {
            lease.finish(true);
            return error(413, "FILE_LIMIT");
        }
        self.file_cancellations
            .lock()
            .unwrap()
            .insert(id.into(), lease.cancelled.clone());
        let _active = Active {
            service: self,
            id: id.into(),
        };
        if let Err((status, code)) =
            self.runtime
                .files
                .transition(id, &["waiting"], "receiving", None)
        {
            lease.finish(true);
            return error(status, code);
        }
        let stage = stage(id, &lease.access);
        let mut contained = true;
        let mut cleaned = false;
        let mut attempted = false;
        let mut confirmed = false;
        let result = (|| -> io::Result<()> {
            let path = self
                .runtime
                .files
                .begin_stage(&stage, &self.runtime.config)?;
            accepted()?;
            let mut job = job(
                "receive",
                &record.request.path,
                record.request.format,
                &lease.access,
                &path,
            );
            job.bytes = length;
            job.sha256 = record.request.sha256.clone();
            job.replace = record.request.replace;
            job.mode = record.request.mode();
            let (received, ended) = self.pipe_upload(&job, &lease, body, deadline);
            contained &= ended;
            received?;
            if !contained {
                return Err(invalid("FILE_CLEANUP_UNCONFIRMED"));
            }
            if lease.cancelled.load(Ordering::SeqCst) {
                return Err(invalid("FILE_CANCELLED"));
            }
            self.runtime
                .files
                .transition(id, &["receiving"], "publishing", None)
                .map_err(|_| invalid("FILE_STATE_UNCERTAIN"))?;
            lease.access.frozen(record.request.freeze, || {
                if lease.cancelled.load(Ordering::SeqCst) {
                    return Err(invalid("FILE_CANCELLED"));
                }
                job.action = "publish".into();
                attempted = true;
                let (published, ended) = self.runtime.file_helper(
                    &job,
                    &lease.access.profile,
                    &lease.cancelled,
                    Stdio::null(),
                );
                contained &= ended;
                published?;
                if !contained {
                    return Err(invalid("FILE_CLEANUP_UNCONFIRMED"));
                }
                confirmed = true;
                self.runtime
                    .files
                    .transition(id, &["publishing"], "published", None)
                    .map_err(|_| invalid("FILE_STATE_UNCERTAIN"))?;
                self.runtime.clean_stage(&stage)?;
                cleaned = true;
                Ok(())
            })
        })();
        if contained && !cleaned {
            cleaned = !self.runtime.files.has_stage(id) || self.runtime.clean_stage(&stage).is_ok();
        }
        contained &= cleaned;
        let response = if !self.runtime.files.available() {
            error(503, "FILE_STATE_UNCERTAIN")
        } else {
            let failure = result.as_ref().err().map(code);
            let (next, reason) = if !contained {
                ("closing", Some("FILE_CLEANUP_UNCONFIRMED"))
            } else if confirmed {
                ("succeeded", None)
            } else if attempted
                && !failure.as_deref().is_some_and(|s| {
                    [
                        "PATH_EXISTS",
                        "NOT_DIRECTORY",
                        "FILE_NOT_FOUND",
                        "INVALID_PATH",
                        "NOT_REGULAR_FILE",
                    ]
                    .contains(&s)
                })
            {
                (
                    "unknown",
                    failure.as_deref().or(Some("PUBLICATION_UNKNOWN")),
                )
            } else {
                ("failed", failure.as_deref().or(Some("FILE_FAILED")))
            };
            metadata(
                self.runtime
                    .files
                    .transition(id, &["receiving", "publishing", "published"], next, reason)
                    .map(|r| r.value()),
            )
        };
        lease.finish(contained);
        response
    }

    fn pipe_upload(
        &self,
        job: &Job,
        lease: &Lease,
        body: &mut impl Read,
        deadline: Instant,
    ) -> (io::Result<Value>, bool) {
        let pipes = pipe_with(PipeFlags::CLOEXEC)
            .map_err(io::Error::from)
            .and_then(|(input, output)| {
                fcntl_setfl(&output, fcntl_getfl(&output)? | OFlags::NONBLOCK)?;
                Ok((File::from(input), File::from(output)))
            });
        let (input, mut output) = match pipes {
            Ok(pair) => pair,
            Err(error) => return (Err(error), true),
        };
        thread::scope(|scope| {
            let worker = match thread::Builder::new().spawn_scoped(scope, || {
                self.runtime.file_helper(
                    job,
                    &lease.access.profile,
                    &lease.cancelled,
                    Stdio::from(input),
                )
            }) {
                Ok(worker) => worker,
                Err(error) => return (Err(error), true),
            };
            let sent = pipe_body(body, &mut output, &lease.cancelled, deadline);
            drop(output);
            if sent
                .as_ref()
                .is_err_and(|e| e.kind() != io::ErrorKind::BrokenPipe)
            {
                lease.cancelled.store(true, Ordering::SeqCst);
            }
            let (received, contained) = worker
                .join()
                .unwrap_or_else(|_| (Err(invalid("FILE_HELPER_FAILED")), false));
            match sent {
                Err(error) if error.kind() != io::ErrorKind::BrokenPipe => (
                    Err(invalid(match error.kind() {
                        io::ErrorKind::Interrupted => "FILE_CANCELLED",
                        io::ErrorKind::TimedOut => "FILE_TIMEOUT",
                        _ => "CONTENT_INCOMPLETE",
                    })),
                    contained,
                ),
                Err(error) => (received.and_then(|_| Err(error)), contained),
                Ok(()) => (received, contained),
            }
        })
    }

    pub fn capture(&self, session: &str, body: &[u8]) -> Result<Snapshot> {
        let request = sandcrab_core::parse(body)
            .ok()
            .and_then(|v| serde_json::from_value::<Capture>(v).ok())
            .ok_or((400, "INVALID_REQUEST"))?;
        if !valid_path(&request.path, request.format == Format::Tar) {
            return Err((400, "INVALID_PATH"));
        }
        let id = sandcrab_core::new_uuid().map_err(|_| (503, "FILE_UNAVAILABLE"))?;
        let lease = self.file_lease(session)?;
        let stage = stage(&id, &lease.access);
        let mut contained = true;
        let result = (|| -> io::Result<(File, u64, String)> {
            let path = self
                .runtime
                .files
                .begin_stage(&stage, &self.runtime.config)?;
            let job = job(
                "snapshot",
                &request.path,
                request.format,
                &lease.access,
                &path,
            );
            let value = lease.access.frozen(request.freeze, || {
                if lease.cancelled.load(Ordering::SeqCst) {
                    return Err(invalid("FILE_CANCELLED"));
                }
                let (result, ended) = self.runtime.file_helper(
                    &job,
                    &lease.access.profile,
                    &lease.cancelled,
                    Stdio::null(),
                );
                contained &= ended;
                result
            })?;
            if !contained {
                return Err(invalid("FILE_CLEANUP_UNCONFIRMED"));
            }
            let bytes = value["bytes"]
                .as_u64()
                .filter(|n| *n <= lease.access.profile.transfer_bytes)
                .ok_or_else(|| invalid("FILE_HELPER_FAILED"))?;
            let sha = value["sha256"]
                .as_str()
                .filter(|s| digest(s))
                .ok_or_else(|| invalid("FILE_HELPER_FAILED"))?
                .to_owned();
            let file = OpenOptions::new()
                .read(true)
                .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
                .open(path.join("content"))?;
            if !file.metadata()?.is_file() || file.metadata()?.len() != bytes {
                return Err(invalid("FILE_HELPER_FAILED"));
            }
            Ok((file, bytes, sha))
        })();
        match result {
            Ok((file, bytes, sha256)) => Ok(Snapshot {
                file,
                bytes,
                sha256,
                format: request.format,
                lease,
                stage,
            }),
            Err(error) => {
                if contained {
                    contained = !self.runtime.files.has_stage(&id)
                        || self.runtime.clean_stage(&stage).is_ok();
                }
                lease.finish(contained);
                Err(if !contained {
                    (503, "FILE_CLEANUP_UNCONFIRMED")
                } else {
                    match code(&error).as_str() {
                        "FILE_NOT_FOUND" => (404, "FILE_NOT_FOUND"),
                        "FILE_LIMIT" => (413, "FILE_LIMIT"),
                        "INVALID_PATH" => (400, "INVALID_PATH"),
                        "INVALID_LINK" => (400, "INVALID_LINK"),
                        "FILE_CAPACITY" => (507, "FILE_CAPACITY"),
                        "FILE_ENTRY_LIMIT" => (413, "FILE_ENTRY_LIMIT"),
                        "FILE_RESOURCE_LIMIT" => (503, "FILE_RESOURCE_LIMIT"),
                        "NOT_REGULAR_FILE" => (400, "NOT_REGULAR_FILE"),
                        "NOT_DIRECTORY" => (400, "NOT_DIRECTORY"),
                        "UNSUPPORTED_FILE_TYPE" => (422, "UNSUPPORTED_FILE_TYPE"),
                        "FILE_CHANGED" => (409, "FILE_CHANGED"),
                        "FILE_CANCELLED" => (409, "FILE_CANCELLED"),
                        _ => (503, "SNAPSHOT_FAILED"),
                    }
                })
            }
        }
    }
    pub fn release_snapshot(&self, snapshot: Snapshot) -> io::Result<()> {
        let Snapshot {
            file, lease, stage, ..
        } = snapshot;
        drop(file);
        let cleanup = self.runtime.clean_stage(&stage);
        lease.finish(cleanup.is_ok());
        cleanup
    }
}
fn pipe_body(
    body: &mut impl Read,
    output: &mut File,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> io::Result<()> {
    let mut buffer = [0u8; 32768];
    loop {
        if cancelled.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let count = match body.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => return Err(e),
        };
        let mut written = 0;
        while written < count {
            if cancelled.load(Ordering::SeqCst) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            match output.write(&buffer[written..count]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => written += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    poll(
                        &mut [PollFd::new(output, PollFlags::OUT)],
                        Some(&Timespec::try_from(Duration::from_millis(50)).unwrap()),
                    )?;
                }
                Err(e) => return Err(e),
            }
        }
    }
}
