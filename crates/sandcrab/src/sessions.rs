//! Persistent shell ownership and monotonic expiry. A transport connection owns no lifetime.
use crate::{
    config::Profile,
    service::{Registry, Run, Service, error},
};
use sandcrab_daemon::job;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io,
    sync::{
        Arc,
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
    request: Open,
    pub state: String,
    deadline: Instant,
    expires_at: u64,
    cancelled: Arc<AtomicBool>,
    reason: String,
    pending: Option<Work>,
    pub active_run: Option<String>,
    code: Option<String>,
    pub files: Option<Arc<crate::file_access::Access>>,
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
            "volumeId":self.request.volume_id,"code":self.code})
    }
}
impl Registry {
    pub(crate) fn stop_session(&mut self, id: &str, reason: &str) {
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
        if let Some(files) = &session.files {
            files.stop();
        }
        if let Some(run) = session.active_run.as_ref().and_then(|id| self.runs.get(id)) {
            run.cancelled.store(true, Ordering::SeqCst);
        }
    }
    pub(crate) fn expire_sessions(&mut self) {
        let expired: Vec<_> = self
            .sessions
            .iter()
            .filter(|(_, s)| {
                s.deadline <= Instant::now()
                    && !s.terminal()
                    && s.state != "stopping"
                    && s.state != "closing"
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            self.stop_session(&id, "expired");
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
                .map(|r| self.session_command(id, r))
                .unwrap_or_else(|| error(400, "INVALID_REQUEST"));
        }
        let mut registry = self.registry.lock().unwrap();
        registry.expire_sessions();
        let Some(session) = registry.sessions.get_mut(id) else {
            return error(404, "SESSION_NOT_FOUND");
        };
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
                (200, session.value())
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
        let lifetime = match ttl(request.ttl_millis, &profile) {
            Ok(v) => v,
            Err(code) => return error(400, code),
        };
        let id = request.id.clone();
        let mut registry = self.registry.lock().unwrap();
        registry.expire_sessions();
        if let Some(session) = registry.sessions.get(&id) {
            return if session.request == request {
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
        let session = Session {
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
        };
        let accepted = session.value();
        registry.sessions.insert(id.clone(), session);
        registry.active += 1;
        let service = self.clone();
        let worker_id = id.clone();
        if thread::Builder::new()
            .spawn(move || service.session_loop(&worker_id, &profile, &cancelled))
            .is_err()
        {
            registry.sessions.remove(&id);
            registry.active -= 1;
            return error(503, "SESSION_UNAVAILABLE");
        }
        (202, accepted)
    }

    fn session_command(self: &Arc<Self>, id: &str, request: Command) -> (u16, Value) {
        if request.server_id != self.id {
            return error(409, "SERVER_CHANGED");
        }
        let input = request.identity(id);
        let mut registry = self.registry.lock().unwrap();
        registry.expire_sessions();
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
        let run = Run {
            request: input,
            profile: profile_name,
            state: "running".into(),
            result: None,
            cancelled: cancelled.clone(),
            reservation: output,
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

    fn session_loop(&self, id: &str, profile: &Profile, cancelled: &Arc<AtomicBool>) {
        let request = self.registry.lock().unwrap().sessions[id].request.clone();
        let mut shell = match self
            .runtime
            .open_shell(&request, profile, cancelled.clone())
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
                session.files = Some(shell.files.clone());
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
                let (finished, reusable) = shell.execute(
                    &work.request.id,
                    &work.request.command,
                    work.timeout,
                    work.output,
                    &work.cancelled,
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
        if contained {
            registry.active -= 1;
        }
    }
}
