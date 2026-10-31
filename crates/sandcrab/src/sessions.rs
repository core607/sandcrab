//! Persistent shell ownership and monotonic expiry. A transport connection owns no lifetime.
use crate::{
    config::Profile,
    service::{Registry, Run, Service, error},
};
use sandcrab_core::job;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Open {
    pub id: String,
    pub server_id: String,
    pub profile: String,
    pub ttl_millis: Option<u64>,
    pub volume_id: Option<String>,
    pub resources: Option<crate::config::Resources>,
}
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OpenShell {
    id: String,
    server_id: String,
}
#[derive(Clone, PartialEq, Eq)]
struct Parent {
    id: String,
    incarnation: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Command {
    pub id: String,
    pub server_id: String,
    pub command: String,
    pub timeout_millis: Option<u64>,
    pub output_limit_bytes: Option<usize>,
}
impl Command {
    fn limits(&self, profile: &Profile) -> Result<(u64, usize), &'static str> {
        if !sandcrab_core::uuid(&self.id)
            || !sandcrab_core::uuid(&self.server_id)
            || self.command.is_empty()
            || self.command.len() > 16384
            || self.command.contains('\0')
        {
            return Err("INVALID_REQUEST");
        }
        let timeout = self.timeout_millis.unwrap_or(profile.timeout_millis);
        let output = self
            .output_limit_bytes
            .unwrap_or(profile.output_limit_bytes);
        if !(1..=profile.timeout_millis).contains(&timeout)
            || !(1..=profile.output_limit_bytes).contains(&output)
        {
            return Err("PROFILE_LIMIT");
        }
        Ok((timeout, output))
    }
    fn identity(&self, session: &str) -> Value {
        let mut value = serde_json::to_value(self).unwrap();
        value["sessionId"] = session.into();
        value
    }
}
struct Work {
    request: Command,
    timeout: u64,
    output: usize,
    cancelled: Arc<AtomicBool>,
}
pub(crate) struct Session {
    pub incarnation: String,
    request: Open,
    pub state: String,
    deadline: Instant,
    pub expires_at: u64,
    cancelled: Arc<AtomicBool>,
    reason: String,
    pending: Option<Work>,
    pub active_run: Option<String>,
    code: Option<String>,
    pub files: Option<Arc<crate::file_access::Access>>,
    parent: Option<Parent>,
}
fn expires_at(ttl: u64) -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
        + ttl
}
fn ttl(value: Option<u64>, profile: &Profile) -> Result<u64, &'static str> {
    let value = value.unwrap_or(profile.session_ttl_millis);
    if !(100..=profile.session_ttl_millis).contains(&value) {
        return Err("PROFILE_LIMIT");
    }
    Ok(value)
}
impl Session {
    pub fn terminal(&self) -> bool {
        ["closed", "expired", "failed"].contains(&self.state.as_str())
    }
    fn value(&self) -> Value {
        json!({"id":self.request.id,"serverId":self.request.server_id,"profile":self.request.profile,
            "state":self.state,"expiresAtMillis":self.expires_at,"activeRunId":self.active_run,
            "volumeId":self.request.volume_id,"code":self.code,
            "parentSessionId":self.parent.as_ref().map(|p| &p.id)})
    }
}
impl Registry {
    pub(crate) fn stop_session(&mut self, id: &str, reason: &str) {
        self.stop_shells(id, reason);
        let Some(session) = self.sessions.get_mut(id) else {
            return;
        };
        if session.terminal() || session.state == "closing" {
            return;
        }
        if session.state != "stopping" {
            session.reason = reason.into();
        }
        session.state = "stopping".into();
        session.cancelled.store(true, Ordering::SeqCst);
        if session.parent.is_none()
            && let Some(files) = &session.files
        {
            files.stop();
        }
        if let Some(run) = session.active_run.as_ref().and_then(|id| self.runs.get(id)) {
            run.cancelled.store(true, Ordering::SeqCst);
        }
    }
    fn stop_shells(&mut self, id: &str, reason: &str) {
        let Some(parent) = self.sessions.get(id) else {
            return;
        };
        if parent.parent.is_some() {
            return;
        }
        let children: Vec<_> = self
            .sessions
            .iter()
            .filter(|(_, s)| {
                s.parent
                    .as_ref()
                    .is_some_and(|p| p.id == id && p.incarnation == parent.incarnation)
            })
            .map(|(id, _)| id.clone())
            .collect();
        for child in children {
            self.stop_session(&child, reason);
        }
    }
    pub(crate) fn expire_sessions(&mut self) {
        let now = Instant::now();
        let expired: Vec<_> = self
            .sessions
            .iter()
            .filter(|(_, s)| {
                // Workspace cleanup failures set cancellation without taking the registry.
                // Propagate that signal to an active command and every child shell.
                (s.deadline <= now || s.cancelled.load(Ordering::SeqCst))
                    && !s.terminal()
                    && s.state != "stopping"
                    && s.state != "closing"
            })
            .map(|(id, s)| {
                (
                    id.clone(),
                    if s.deadline <= now {
                        "expired"
                    } else {
                        "closed"
                    },
                )
            })
            .collect();
        for (id, reason) in expired {
            self.stop_session(&id, reason);
        }
    }
}
impl Service {
    pub(crate) fn session_route(
        self: &Arc<Self>,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> (u16, Value) {
        self.session_route_expected(method, path, body, None)
    }
    pub(crate) fn session_route_expected(
        self: &Arc<Self>,
        method: &str,
        path: &str,
        body: &[u8],
        incarnation: Option<&str>,
    ) -> (u16, Value) {
        let parse = || sandcrab_core::parse(body).ok();
        if path == "/v1/sessions" && method == "POST" {
            return parse()
                .and_then(|v| serde_json::from_value(v).ok())
                .map(|r| self.open_session(r))
                .unwrap_or_else(|| error(400, "INVALID_REQUEST"));
        }
        let Some(path) = path.strip_prefix("/v1/sessions/") else {
            return error(404, "NOT_FOUND");
        };
        let (id, action) = path.split_once('/').unwrap_or((path, ""));
        if !sandcrab_core::uuid(id) {
            return error(404, "SESSION_NOT_FOUND");
        }
        if method == "POST" && action == "commands" {
            return parse()
                .and_then(|v| serde_json::from_value(v).ok())
                .map(|r| self.session_command(id, r, incarnation))
                .unwrap_or_else(|| error(400, "INVALID_REQUEST"));
        }
        if method == "POST" && action == "shells" {
            return parse()
                .and_then(|v| serde_json::from_value(v).ok())
                .map(|request| self.open_child(id, request, incarnation))
                .unwrap_or_else(|| error(400, "INVALID_REQUEST"));
        }
        let mut registry = self.registry.lock().unwrap();
        registry.expire_sessions();
        let Some(session) = registry.sessions.get_mut(id) else {
            return error(404, "SESSION_NOT_FOUND");
        };
        if incarnation.is_some_and(|value| value != session.incarnation) {
            return error(409, "SESSION_CHANGED");
        }
        if method == "GET" && action.is_empty() {
            return (200, session.value());
        }
        if method != "POST" {
            return error(404, "NOT_FOUND");
        }
        if ["close", "forget"].contains(&action) && parse() != Some(json!({})) {
            return error(400, "INVALID_REQUEST");
        }
        match action {
            "close" => {
                registry.stop_session(id, "closed");
                (200, registry.sessions[id].value())
            }
            "forget" => {
                if !session.terminal() {
                    return error(409, "SESSION_ACTIVE");
                }
                registry.sessions.remove(id);
                (200, json!({"forgotten":true}))
            }
            "renew" => {
                if session.parent.is_some() {
                    return error(409, "RENEW_PARENT_SESSION");
                }
                #[derive(Deserialize)]
                #[serde(rename_all = "camelCase", deny_unknown_fields)]
                struct Renew {
                    ttl_millis: u64,
                }
                let Some(request) = parse().and_then(|v| serde_json::from_value::<Renew>(v).ok())
                else {
                    return error(400, "INVALID_REQUEST");
                };
                let profile = &self.runtime.config.profiles[&session.request.profile];
                let value = match ttl(Some(request.ttl_millis), profile) {
                    Ok(v) => v,
                    Err(code) => return error(400, code),
                };
                if session.cancelled.load(Ordering::SeqCst)
                    || session.terminal()
                    || session.state == "closing"
                {
                    return error(409, "SESSION_ENDED");
                }
                session.deadline = Instant::now() + Duration::from_millis(value);
                session.expires_at = expires_at(value);
                let deadline = session.deadline;
                let expires_at = session.expires_at;
                let incarnation = session.incarnation.clone();
                let result = session.value();
                for child in registry.sessions.values_mut().filter(|s| {
                    s.parent
                        .as_ref()
                        .is_some_and(|p| p.id == id && p.incarnation == incarnation)
                }) {
                    if !child.terminal() {
                        child.deadline = deadline;
                        child.expires_at = expires_at;
                    }
                }
                (200, result)
            }
            _ => error(404, "NOT_FOUND"),
        }
    }

    fn open_session(self: &Arc<Self>, request: Open) -> (u16, Value) {
        if request.server_id != self.id {
            return error(409, "SERVER_CHANGED");
        }
        if !sandcrab_core::uuid(&request.id)
            || request
                .volume_id
                .as_ref()
                .is_some_and(|id| !sandcrab_core::uuid(id))
        {
            return error(400, "INVALID_REQUEST");
        }
        let Some(profile) = self.runtime.config.profiles.get(&request.profile).cloned() else {
            return error(400, "PROFILE_NOT_FOUND");
        };
        let profile = match profile.with_resources(request.resources.as_ref()) {
            Ok(profile) => profile,
            Err(code) => return error(400, code),
        };
        let lifetime = match ttl(request.ttl_millis, &profile) {
            Ok(v) => v,
            Err(code) => return error(400, code),
        };
        let id = request.id.clone();
        let mut registry = self.registry.lock().unwrap();
        registry.expire_sessions();
        if let Some(session) = registry.sessions.get(&id) {
            return if session.parent.is_none() && session.request == request {
                (200, session.value())
            } else {
                error(409, "ID_CONFLICT")
            };
        }
        if registry.runs.contains_key(&id) {
            return error(409, "ID_CONFLICT");
        }
        if self.stopped.load(Ordering::SeqCst) {
            return error(503, "STOPPING");
        }
        let limits = &self.runtime.config.service;
        if registry.active >= limits.max_sandboxes {
            return error(429, "SESSION_CAPACITY");
        }
        if registry.sessions.len() + registry.runs.len() >= limits.max_records {
            return error(429, "RESULT_CAPACITY");
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let incarnation = match sandcrab_core::new_uuid() {
            Ok(value) => value,
            Err(_) => return error(503, "SESSION_UNAVAILABLE"),
        };
        let session = Session {
            incarnation,
            request,
            state: "starting".into(),
            deadline: Instant::now() + Duration::from_millis(lifetime),
            expires_at: expires_at(lifetime),
            cancelled: cancelled.clone(),
            reason: "closed".into(),
            pending: None,
            active_run: None,
            code: None,
            files: None,
            parent: None,
        };
        let accepted = session.value();
        registry.sessions.insert(id.clone(), session);
        registry.active += 1;
        let service = self.clone();
        let worker_id = id.clone();
        if thread::Builder::new()
            .spawn(move || service.session_loop(&worker_id, &profile, &cancelled, None))
            .is_err()
        {
            registry.sessions.remove(&id);
            registry.active -= 1;
            return error(503, "SESSION_UNAVAILABLE");
        }
        (202, accepted)
    }

    fn open_child(
        self: &Arc<Self>,
        parent_id: &str,
        request: OpenShell,
        incarnation: Option<&str>,
    ) -> (u16, Value) {
        if request.server_id != self.id {
            return error(409, "SERVER_CHANGED");
        }
        if !sandcrab_core::uuid(&request.id) {
            return error(400, "INVALID_REQUEST");
        }
        let mut registry = self.registry.lock().unwrap();
        registry.expire_sessions();
        let Some(parent) = registry.sessions.get(parent_id) else {
            return error(404, "SESSION_NOT_FOUND");
        };
        if incarnation.is_some_and(|value| value != parent.incarnation) {
            return error(409, "SESSION_CHANGED");
        }
        let owner = Parent {
            id: parent_id.into(),
            incarnation: parent.incarnation.clone(),
        };
        if let Some(session) = registry.sessions.get(&request.id) {
            return if session.parent.as_ref() == Some(&owner) {
                (200, session.value())
            } else {
                error(409, "ID_CONFLICT")
            };
        }
        if registry.runs.contains_key(&request.id) {
            return error(409, "ID_CONFLICT");
        }
        if self.stopped.load(Ordering::SeqCst) {
            return error(503, "STOPPING");
        }
        if parent.parent.is_some() {
            return error(400, "PARENT_SESSION_REQUIRED");
        }
        if !["ready", "busy"].contains(&parent.state.as_str()) {
            return error(409, "SESSION_NOT_READY");
        }
        if registry.sessions.len() + registry.runs.len() >= self.runtime.config.service.max_records
        {
            return error(429, "RESULT_CAPACITY");
        }
        let Some(files) = &parent.files else {
            return error(409, "SESSION_NOT_READY");
        };
        let profile = files.profile.clone();
        let cancelled = Arc::new(AtomicBool::new(false));
        let incarnation = match sandcrab_core::new_uuid() {
            Ok(value) => value,
            Err(_) => return error(503, "SESSION_UNAVAILABLE"),
        };
        let lease = match files.shell(&request.id, cancelled.clone()) {
            Ok(value) => value,
            Err(code) => return error(409, code),
        };
        let mut input = parent.request.clone();
        input.id = request.id.clone();
        let session = Session {
            incarnation,
            request: input,
            state: "starting".into(),
            deadline: parent.deadline,
            expires_at: parent.expires_at,
            cancelled: cancelled.clone(),
            reason: "closed".into(),
            pending: None,
            active_run: None,
            code: None,
            files: None,
            parent: Some(owner),
        };
        let accepted = session.value();
        registry.sessions.insert(request.id.clone(), session);
        // Keep the pin outside the closure so a failed thread spawn can release it safely.
        let lease = Arc::new(Mutex::new(Some(lease)));
        let worker_lease = lease.clone();
        let service = self.clone();
        let id = request.id.clone();
        if thread::Builder::new()
            .spawn(move || {
                let lease = worker_lease.lock().unwrap().take();
                service.session_loop(&id, &profile, &cancelled, lease);
            })
            .is_err()
        {
            registry.sessions.remove(&request.id);
            lease.lock().unwrap().take().unwrap().finish(true);
            return error(503, "SESSION_UNAVAILABLE");
        }
        (202, accepted)
    }

    fn session_command(
        self: &Arc<Self>,
        id: &str,
        request: Command,
        incarnation: Option<&str>,
    ) -> (u16, Value) {
        if request.server_id != self.id {
            return error(409, "SERVER_CHANGED");
        }
        let input = request.identity(id);
        let mut registry = self.registry.lock().unwrap();
        registry.expire_sessions();
        if incarnation.is_some_and(|value| {
            registry
                .sessions
                .get(id)
                .is_none_or(|session| session.incarnation != value)
        }) {
            return error(409, "SESSION_CHANGED");
        }
        // Completed requests remain replayable after the session ends or is forgotten.
        if let Some(run) = registry.runs.get(&request.id) {
            return if run.request == input {
                (200, run.value())
            } else {
                error(409, "ID_CONFLICT")
            };
        }
        if registry.sessions.contains_key(&request.id) {
            return error(409, "ID_CONFLICT");
        }
        if self.stopped.load(Ordering::SeqCst) {
            return error(503, "STOPPING");
        }
        let Some(session) = registry.sessions.get(id) else {
            return error(404, "SESSION_NOT_FOUND");
        };
        let profile_name = session.request.profile.clone();
        let profile = &self.runtime.config.profiles[&profile_name];
        let (timeout, output) = match request.limits(profile) {
            Ok(v) => v,
            Err(code) => return error(400, code),
        };
        if session.state != "ready" {
            return error(409, "SESSION_NOT_READY");
        }
        let limits = &self.runtime.config.service;
        if registry.runs.len() + registry.sessions.len() >= limits.max_records
            || registry.reserved + output > limits.max_output_bytes
        {
            return error(429, "RESULT_CAPACITY");
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let run = match Run::new(
            input,
            profile_name,
            cancelled.clone(),
            output,
            profile.host_calls,
        ) {
            Ok(run) => run,
            Err(_) => return error(503, "RUN_UNAVAILABLE"),
        };
        let accepted = run.value();
        registry.reserved += output;
        registry.runs.insert(request.id.clone(), run);
        let session = registry.sessions.get_mut(id).unwrap();
        session.state = "busy".into();
        session.active_run = Some(request.id.clone());
        session.pending = Some(Work {
            request,
            timeout,
            output,
            cancelled,
        });
        (202, accepted)
    }

    fn session_loop(
        &self,
        id: &str,
        profile: &Profile,
        cancelled: &Arc<AtomicBool>,
        shared: Option<crate::file_access::ShellLease>,
    ) {
        let request = self.registry.lock().unwrap().sessions[id].request.clone();
        let mut shell = match self
            .runtime
            .open_shell(&request, profile, cancelled.clone(), shared)
        {
            Ok(shell) => shell,
            Err(error) => {
                self.end_session(id, "failed", error.contained, Some(error.code));
                return;
            }
        };
        if !shell.ready(cancelled) {
            self.end_session(
                id,
                "failed",
                shell.close().is_ok(),
                Some("SESSION_UNAVAILABLE"),
            );
            return;
        }
        {
            let mut registry = self.registry.lock().unwrap();
            registry.expire_sessions();
            let session = registry.sessions.get_mut(id).unwrap();
            if session.state == "starting" {
                if session.parent.is_none() {
                    session.files = Some(shell.files.clone());
                }
                session.state = "ready".into();
            }
        }
        let mut last: Option<(String, job::Finished)> = None;
        let mut reason = "closed";
        while !cancelled.load(Ordering::SeqCst) {
            let work = {
                let mut registry = self.registry.lock().unwrap();
                registry.expire_sessions();
                registry.sessions.get_mut(id).unwrap().pending.take()
            };
            if let Some(work) = work {
                let calls = self.registry.lock().unwrap().runs[&work.request.id]
                    .calls
                    .clone();
                let (finished, reusable) = shell.execute(
                    &work.request.id,
                    &work.request.command,
                    work.timeout,
                    work.output,
                    crate::runtime::Control {
                        cancelled: &work.cancelled,
                        calls,
                    },
                    |stream, bytes| self.output(&work.request.id, stream, bytes),
                );
                if !reusable || cancelled.load(Ordering::SeqCst) {
                    reason = if finished.end == job::End::Normal && finished.exit_code == 0 {
                        "closed"
                    } else {
                        "failed"
                    };
                    last = Some((work.request.id, finished));
                    break;
                }
                self.complete(&work.request.id, Ok(finished), Ok(()), false);
            } else {
                if !matches!(shell.channel.process().try_wait(), Ok(None)) {
                    reason = "failed";
                    break;
                }
                thread::sleep(Duration::from_millis(25));
            }
        }
        // Block new commands before stopping the unit. Internal shell exits do not turn a
        // successful `exit 0` or a timeout into a caller cancellation.
        {
            let mut registry = self.registry.lock().unwrap();
            registry.stop_shells(id, reason);
            let session = registry.sessions.get_mut(id).unwrap();
            if session.state != "stopping" {
                session.reason = reason.into();
                session.state = "stopping".into();
            }
        }
        let contained = shell.close().is_ok();
        if let Some((run, finished)) = last {
            self.complete(
                &run,
                Ok(finished),
                if contained {
                    Ok(())
                } else {
                    Err(io::Error::other("Containment unconfirmed"))
                },
                false,
            );
        }
        self.end_session(id, reason, contained, None);
    }

    fn end_session(&self, id: &str, fallback: &str, contained: bool, code: Option<&str>) {
        let pending = self
            .registry
            .lock()
            .unwrap()
            .sessions
            .get_mut(id)
            .unwrap()
            .pending
            .take();
        if let Some(work) = pending {
            self.complete(
                &work.request.id,
                Err(io::ErrorKind::Interrupted.into()),
                if contained {
                    Ok(())
                } else {
                    Err(io::Error::other("Containment unconfirmed"))
                },
                false,
            );
        }
        let mut registry = self.registry.lock().unwrap();
        let session = registry.sessions.get_mut(id).unwrap();
        session.code = if contained {
            code.map(str::to_owned)
        } else {
            Some("CONTAINMENT_UNCONFIRMED".into())
        };
        session.state = if !contained {
            "closing".into()
        } else if session.state == "stopping" {
            session.reason.clone()
        } else {
            fallback.into()
        };
        if contained && session.parent.is_none() {
            registry.active -= 1;
        }
    }
}
