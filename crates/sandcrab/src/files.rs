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
use sandcrab_core::process::Input;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Capture {
    pub path: String,
    pub format: Format,
    #[serde(default)]
    pub frozen: bool,
    #[serde(default)]
    pub scope: CaptureScope,
}
#[derive(Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CaptureScope {
    #[default]
    Workspace,
    Filesystem,
}
impl Capture {
    fn valid(&self) -> bool {
        valid_path(&self.path, self.format == Format::Tar)
            && (self.scope == CaptureScope::Workspace
                || (self.frozen && self.path == "." && self.format == Format::Tar))
    }
}
pub struct Snapshot {
    pub file: File,
    pub bytes: u64,
    pub sha256: String,
    pub format: Format,
    pub lease: Lease,
    pub range: Option<crate::sdk_download::Range>,
    pub text: bool,
    pub template_id: Option<String>,
    stage: Stage,
}
struct Captured {
    file: File,
    bytes: u64,
    sha256: String,
    range: Option<crate::sdk_download::Range>,
    template_id: Option<String>,
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
pub(crate) fn code(error: &io::Error) -> String {
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
pub(crate) fn stage(id: &str, access: &Access) -> Stage {
    Stage {
        id: id.into(),
        session_id: access.session.clone(),
        volume_id: access.volume.clone(),
        rootfs: access.rootfs,
        profile: access.profile_name.clone(),
        uid: access.profile.uid,
        gid: access.profile.gid,
    }
}
pub(crate) fn job(
    action: &str,
    path: &str,
    format: Format,
    access: &Access,
    stage: &std::path::Path,
) -> Job {
    Job {
        action: action.into(),
        workspace: access.workspace.clone(),
        stage: stage.into(),
        path: path.into(),
        format,
        bytes: 0,
        sha256: String::new(),
        replace: false,
        parents: false,
        mode: if format == Format::Tar { 0o755 } else { 0o644 },
        uid: access.profile.uid,
        gid: access.profile.gid,
        byte_limit: access.profile.transfer_bytes,
        entry_limit: 10000,
        multipart: None,
        selection: None,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MkdirRequest {
    path: String,
    mode: Option<u32>,
}

fn native_entries(raw: Value) -> Result<Value> {
    let items = raw.as_array().ok_or((503, "FILE_METADATA_UNAVAILABLE"))?;
    let mut entries = Vec::with_capacity(items.len());
    for item in items {
        let raw_path = item["path"]
            .as_str()
            .ok_or((503, "FILE_METADATA_UNAVAILABLE"))?;
        let path = if raw_path == "/workspace" {
            "."
        } else {
            raw_path
                .strip_prefix("/workspace/")
                .ok_or((503, "FILE_METADATA_UNAVAILABLE"))?
        };
        let raw_mode = item["mode"]
            .as_u64()
            .ok_or((503, "FILE_METADATA_UNAVAILABLE"))?;
        let mode = u32::from_str_radix(&raw_mode.to_string(), 8)
            .map_err(|_| (503, "FILE_METADATA_UNAVAILABLE"))?;
        let kind = item["type"]
            .as_str()
            .ok_or((503, "FILE_METADATA_UNAVAILABLE"))?;
        let size = item["size"]
            .as_u64()
            .ok_or((503, "FILE_METADATA_UNAVAILABLE"))?;
        let modified_at = item["modified_at"]
            .as_str()
            .ok_or((503, "FILE_METADATA_UNAVAILABLE"))?;
        let created_at = item["created_at"]
            .as_str()
            .ok_or((503, "FILE_METADATA_UNAVAILABLE"))?;
        entries.push(json!({
            "path": path,
            "type": kind,
            "size": size,
            "mode": mode,
            "modifiedAt": modified_at,
            "createdAt": created_at,
        }));
    }
    Ok(json!({"entries": entries}))
}

impl Service {
    pub(crate) fn session_file_route(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Option<(u16, Value)> {
        let rest = path.strip_prefix("/v1/sessions/")?;
        let (id, tail) = rest.split_once('/')?;
        if !sandcrab_core::uuid(id) {
            return None;
        }
        let outcome = if tail == "files" || tail.starts_with("files?") {
            if method != "DELETE" {
                return None;
            }
            self.remove_file(id, tail.strip_prefix("files?").unwrap_or(""))
        } else if tail == "files/mkdir" {
            if method != "POST" {
                return Some(error(404, "NOT_FOUND"));
            }
            self.mkdir_file(id, body)
        } else if tail == "files/list" || tail.starts_with("files/list?") {
            if method != "GET" {
                return Some(error(404, "NOT_FOUND"));
            }
            self.list_files(id, tail.strip_prefix("files/list?").unwrap_or(""))
        } else if tail == "files/search" || tail.starts_with("files/search?") {
            if method != "GET" {
                return Some(error(404, "NOT_FOUND"));
            }
            self.search_files(id, tail.strip_prefix("files/search?").unwrap_or(""))
        } else {
            return None;
        };
        Some(match outcome {
            Ok(value) => (200, value),
            Err((status, code)) => error(status, code),
        })
    }

    pub(crate) fn mkdir_file(&self, id: &str, body: &[u8]) -> Result<Value> {
        let value = sandcrab_core::parse(body).map_err(|_| (400, "INVALID_REQUEST"))?;
        let request: MkdirRequest =
            serde_json::from_value(value).map_err(|_| (400, "INVALID_REQUEST"))?;
        if !valid_path(&request.path, false) {
            return Err((400, "INVALID_PATH"));
        }
        let mode = request.mode.unwrap_or(0o755);
        if mode > 0o777 {
            return Err((400, "INVALID_FILE_MODE"));
        }
        let op = crate::sdk_fs::Request::Mkdir {
            entries: vec![crate::sdk_fs::Mode {
                path: request.path.clone(),
                mode,
            }],
        };
        op.validate()?;
        self.filesystem(self.file_lease(id, None)?, &op)?;
        Ok(json!({"path": request.path, "created": true}))
    }

    pub(crate) fn list_files(&self, id: &str, query: &str) -> Result<Value> {
        let (mut path, mut depth) = (None, None);
        for (key, value) in crate::sdk_types::query(query)? {
            match key.as_str() {
                "path" if path.is_none() => path = Some(value),
                "depth" if depth.is_none() => {
                    let parsed = (!value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
                        .then(|| value.parse::<usize>().ok())
                        .flatten()
                        .filter(|n| *n <= 64)
                        .ok_or((400, "INVALID_DEPTH"))?;
                    depth = Some(parsed);
                }
                _ => return Err((400, "INVALID_QUERY")),
            }
        }
        let path = path.unwrap_or_else(|| ".".into());
        if !valid_path(&path, true) {
            return Err((400, "INVALID_PATH"));
        }
        let op = crate::sdk_fs::Request::List {
            path,
            depth: depth.unwrap_or(1),
        };
        op.validate()?;
        native_entries(self.filesystem(self.file_lease(id, None)?, &op)?)
    }

    pub(crate) fn search_files(&self, id: &str, query: &str) -> Result<Value> {
        let (mut path, mut pattern) = (None, None);
        for (key, value) in crate::sdk_types::query(query)? {
            match key.as_str() {
                "path" if path.is_none() => path = Some(value),
                "pattern" if pattern.is_none() => pattern = Some(value),
                _ => return Err((400, "INVALID_QUERY")),
            }
        }
        let path = path.unwrap_or_else(|| ".".into());
        if !valid_path(&path, true) {
            return Err((400, "INVALID_PATH"));
        }
        let pattern = pattern.ok_or((400, "INVALID_QUERY"))?;
        let op = crate::sdk_fs::Request::Search { path, pattern };
        op.validate()?;
        native_entries(self.filesystem(self.file_lease(id, None)?, &op)?)
    }

    pub(crate) fn read_file(&self, id: &str, query: &str, range: Option<&str>) -> Result<Snapshot> {
        let mut raw_path = None;
        for (key, value) in crate::sdk_types::query(query)? {
            if key == "path" && raw_path.is_none() {
                raw_path = Some(value);
            }
        }
        let raw_path = raw_path.ok_or((400, "INVALID_PATH"))?;
        if !valid_path(&raw_path, false) {
            return Err((400, "INVALID_PATH"));
        }
        let (path, selection) = crate::sdk_download::request(query, range)?;
        self.capture(
            id,
            &serde_json::to_vec(&json!({"path": path, "format": "raw"})).unwrap(),
            None,
            selection.as_ref(),
            false,
        )
    }

    pub(crate) fn remove_file(&self, id: &str, query: &str) -> Result<Value> {
        let (mut path, mut recursive) = (None, None);
        for (key, value) in crate::sdk_types::query(query)? {
            match key.as_str() {
                "path" if path.is_none() => path = Some(value),
                "recursive"
                    if recursive.is_none() && ["true", "false"].contains(&value.as_str()) =>
                {
                    recursive = Some(value == "true")
                }
                _ => return Err((400, "INVALID_QUERY")),
            }
        }
        let path = path.ok_or((400, "INVALID_PATH"))?;
        if !valid_path(&path, false) {
            return Err((400, "INVALID_PATH"));
        }
        let request = crate::sdk_fs::Request::parse(
            "DELETE",
            if recursive.unwrap_or(false) {
                "directories"
            } else {
                "files"
            },
            &[("path".into(), path)],
            &[],
        )?;
        self.filesystem(self.file_lease(id, None)?, &request)?;
        Ok(json!({"deleted":true}))
    }

    fn file_access(&self, id: &str, incarnation: Option<&str>) -> Result<Arc<Access>> {
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
        if incarnation.is_some_and(|expected| session.incarnation != expected) {
            return Err((409, "SESSION_CHANGED"));
        }
        if !["ready", "busy"].contains(&session.state.as_str()) {
            return Err((409, "SESSION_NOT_READY"));
        }
        session.files.clone().ok_or((409, "SESSION_NOT_READY"))
    }
    pub(crate) fn file_lease(&self, id: &str, incarnation: Option<&str>) -> Result<Lease> {
        self.file_access(id, incarnation)?
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
            let access = match self.file_access(&input.session_id, None) {
                Ok(v) => v,
                Err((status, code)) => return error(status, code),
            };
            if input.bytes > access.profile.transfer_bytes {
                return error(413, "FILE_LIMIT");
            }
            if let Err(code) = access.allow_growth() {
                return error(409, code);
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
        let lease = match self.file_lease(&record.request.session_id, None) {
            Ok(l) => l,
            Err((status, code)) => return error(status, code),
        };
        if let Err(code) = lease.allow_growth() {
            lease.finish(true);
            return error(409, code);
        }
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
            job.parents = record.request.parents;
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
            if lease.cancelled.load(Ordering::SeqCst) {
                return Err(invalid("FILE_CANCELLED"));
            }
            job.action = "publish".into();
            attempted = true;
            let (published, ended) = self.runtime.file_helper(
                &job,
                &lease.access.profile,
                &lease.cancelled,
                Input::Null,
            );
            contained &= ended;
            let receipt: crate::file_io::Publication =
                serde_json::from_value(published?).map_err(|_| invalid("PUBLICATION_UNKNOWN"))?;
            if let crate::file_io::Publication::Rejected { code } = receipt {
                attempted = false;
                return Err(invalid(code));
            }
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
            } else if attempted {
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

    pub(crate) fn pipe_upload(
        &self,
        job: &Job,
        lease: &Lease,
        body: &mut impl Read,
        deadline: Instant,
    ) -> (io::Result<Value>, bool) {
        self.pipe_file(job, &lease.access.profile, &lease.cancelled, body, deadline)
    }

    pub(crate) fn pipe_file(
        &self,
        job: &Job,
        profile: &crate::config::Profile,
        cancelled: &AtomicBool,
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
                self.runtime
                    .file_helper(job, profile, cancelled, Input::File(input))
            }) {
                Ok(worker) => worker,
                Err(error) => return (Err(error), true),
            };
            let sent = pipe_body(body, &mut output, cancelled, deadline);
            drop(output);
            if sent
                .as_ref()
                .is_err_and(|e| e.kind() != io::ErrorKind::BrokenPipe)
            {
                cancelled.store(true, Ordering::SeqCst);
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

    pub fn capture(
        &self,
        session: &str,
        body: &[u8],
        incarnation: Option<&str>,
        selection: Option<&crate::sdk_download::Selection>,
        frozen: bool,
    ) -> Result<Snapshot> {
        let request = sandcrab_core::parse(body)
            .ok()
            .and_then(|v| serde_json::from_value::<Capture>(v).ok())
            .ok_or((400, "INVALID_REQUEST"))?;
        if !request.valid() {
            return Err((400, "INVALID_PATH"));
        }
        if selection.is_some() && request.format != Format::Raw {
            return Err((400, "INVALID_SELECTION"));
        }
        let lease = self.file_lease(session, incarnation)?;
        let frozen = frozen || request.frozen;
        self.capture_file(lease, request, selection, frozen, false)
    }

    pub fn difference(&self, session: &str) -> Result<Snapshot> {
        let lease = self.file_lease(session, None)?;
        if lease.access.template.is_none() {
            lease.finish(true);
            return Err((409, "TEMPLATE_REQUIRED"));
        }
        self.capture_file(
            lease,
            Capture {
                path: ".".into(),
                format: Format::Tar,
                frozen: false,
                scope: CaptureScope::Workspace,
            },
            None,
            false,
            true,
        )
    }

    fn capture_file(
        &self,
        lease: Lease,
        request: Capture,
        selection: Option<&crate::sdk_download::Selection>,
        frozen: bool,
        difference: bool,
    ) -> Result<Snapshot> {
        let id = match sandcrab_core::new_uuid() {
            Ok(id) => id,
            Err(_) => {
                lease.finish(true);
                return Err((503, "FILE_UNAVAILABLE"));
            }
        };
        let stage = stage(&id, &lease.access);
        let mut contained = true;
        let result = (|| -> io::Result<Captured> {
            let path = self
                .runtime
                .files
                .begin_stage(&stage, &self.runtime.config)?;
            let mut job = job(
                if difference {
                    "difference"
                } else if request.scope == CaptureScope::Filesystem {
                    "checkpoint"
                } else {
                    "snapshot"
                },
                &request.path,
                request.format,
                &lease.access,
                &path,
            );
            if request.scope == CaptureScope::Filesystem {
                job.entry_limit = crate::templates::ENTRY_LIMIT;
                if lease.access.rootfs {
                    job.workspace = job
                        .workspace
                        .parent()
                        .ok_or_else(|| invalid("INVALID_PATH"))?
                        .to_owned();
                }
            }
            job.selection = selection.cloned();
            let value = lease.access.frozen(frozen, || {
                if lease.cancelled.load(Ordering::SeqCst) {
                    return Err(invalid("FILE_CANCELLED"));
                }
                let (result, ended) = self.runtime.file_helper(
                    &job,
                    &lease.access.profile,
                    &lease.cancelled,
                    Input::Null,
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
            let template_id = if request.scope == CaptureScope::Filesystem {
                Some(
                    value["templateId"]
                        .as_str()
                        .filter(|id| digest(id))
                        .ok_or_else(|| invalid("FILE_HELPER_FAILED"))?
                        .to_owned(),
                )
            } else {
                None
            };
            let file = OpenOptions::new()
                .read(true)
                .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
                .open(path.join("content"))?;
            if !file.metadata()?.is_file() || file.metadata()?.len() != bytes {
                return Err(invalid("FILE_HELPER_FAILED"));
            }
            let range =
                if let Some(selected @ crate::sdk_download::Selection::Bytes { .. }) = selection {
                    let total = value["sourceBytes"]
                        .as_u64()
                        .ok_or_else(|| invalid("FILE_HELPER_FAILED"))?;
                    let (start, length) = selected.range(total)?;
                    if length != bytes {
                        return Err(invalid("FILE_HELPER_FAILED"));
                    }
                    Some(crate::sdk_download::Range { start, total })
                } else {
                    None
                };
            Ok(Captured {
                file,
                bytes,
                sha256: sha,
                range,
                template_id,
            })
        })();
        match result {
            Ok(Captured {
                file,
                bytes,
                sha256,
                range,
                template_id,
            }) => Ok(Snapshot {
                file,
                bytes,
                sha256,
                format: request.format,
                lease,
                stage,
                range,
                text: selection.is_some_and(crate::sdk_download::Selection::text),
                template_id,
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
                        "RANGE_NOT_SATISFIABLE" => (416, "RANGE_NOT_SATISFIABLE"),
                        "FILE_LIMIT" => (413, "FILE_LIMIT"),
                        "INVALID_PATH" => (400, "INVALID_PATH"),
                        "INVALID_LINK" => (400, "INVALID_LINK"),
                        "FILE_CAPACITY" => (507, "FILE_CAPACITY"),
                        "FILE_ENTRY_LIMIT" => (413, "FILE_ENTRY_LIMIT"),
                        "FILE_RESOURCE_LIMIT" => (503, "FILE_RESOURCE_LIMIT"),
                        "NOT_REGULAR_FILE" => (400, "NOT_REGULAR_FILE"),
                        "NOT_DIRECTORY" => (400, "NOT_DIRECTORY"),
                        "UNSUPPORTED_FILE_TYPE" => (422, "UNSUPPORTED_FILE_TYPE"),
                        "UNSUPPORTED_OVERLAY_METADATA" => (422, "UNSUPPORTED_OVERLAY_METADATA"),
                        "DIFF_NAME_CONFLICT" => (422, "DIFF_NAME_CONFLICT"),
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

#[cfg(test)]
mod capture_tests {
    use super::*;

    #[test]
    fn a_filesystem_capture_requires_a_frozen_whole_tree() {
        let parse = |value: Value| serde_json::from_value::<Capture>(value);
        assert!(parse(json!({"path":".","format":"tar"})).unwrap().valid());
        assert!(
            parse(json!({"path":"file","format":"raw","frozen":true}))
                .unwrap()
                .valid()
        );
        assert!(
            parse(json!({"path":".","format":"tar","scope":"filesystem","frozen":true}))
                .unwrap()
                .valid()
        );
        for value in [
            json!({"path":".","format":"tar","scope":"filesystem"}),
            json!({"path":"file","format":"raw","scope":"filesystem","frozen":true}),
            json!({"path":"subdir","format":"tar","scope":"filesystem","frozen":true}),
            json!({"path":"../outside","format":"tar","frozen":true}),
        ] {
            assert!(!parse(value).unwrap().valid());
        }
        for value in [
            json!({"path":".","format":"tar","scope":"host","frozen":true}),
            json!({"path":".","format":"tar","frozen":"true"}),
            json!({"path":".","format":"tar","root":"/etc"}),
        ] {
            assert!(parse(value).is_err());
        }
    }
}
