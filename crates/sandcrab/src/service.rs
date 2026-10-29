//! Native run admission and outcomes. A server epoch prevents uncertain requests from being
//! silently executed again after restart; explicit forgetting ends a run's replay lifetime.
use crate::{
    config::{Profile, invalid},
    runtime::Runtime,
};
use sandcrab_daemon::job;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
};

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub id: String,
    pub server_id: String,
    pub profile: String,
    pub command: Vec<String>,
    pub timeout_millis: Option<u64>,
    pub output_limit_bytes: Option<usize>,
}
impl Request {
    fn limits(&self, profile: &Profile) -> Result<(u64, usize), &'static str> {
        if !sandcrab_core::uuid(&self.id)
            || !sandcrab_core::uuid(&self.server_id)
            || self.command.is_empty()
            || self.command.len() > 128
            || self.command[0].is_empty()
            || self
                .command
                .iter()
                .any(|s| s.len() > 4096 || s.contains('\0'))
            || self.command.iter().map(String::len).sum::<usize>() > 16384
        {
            return Err("INVALID_REQUEST");
        }
        let timeout = self.timeout_millis.unwrap_or(profile.timeout_millis);
        let limit = self
            .output_limit_bytes
            .unwrap_or(profile.output_limit_bytes);
        if !(1..=profile.timeout_millis).contains(&timeout)
            || !(1..=profile.output_limit_bytes).contains(&limit)
        {
            return Err("PROFILE_LIMIT");
        }
        Ok((timeout, limit))
    }
}

pub(crate) struct Run {
    pub request: Value,
    pub profile: String,
    pub state: String,
    pub result: Option<Value>,
    pub cancelled: Arc<AtomicBool>,
    pub reservation: usize,
}
impl Run {
    pub(crate) fn terminal(&self) -> bool {
        self.state != "running" && self.state != "closing"
    }
    pub(crate) fn value(&self) -> Value {
        let mut value = json!({"id":self.request["id"],"serverId":self.request["serverId"],"profile":self.profile,
            "state":self.state,"result":self.result});
        if let Some(id) = self.request.get("sessionId") {
            value["sessionId"] = id.clone();
        }
        value
    }
}
pub(crate) struct Registry {
    pub runs: BTreeMap<String, Run>,
    pub sessions: BTreeMap<String, crate::sessions::Session>,
    pub active: usize,
    pub reserved: usize,
}
impl Registry {
    fn new() -> Self {
        Self {
            runs: BTreeMap::new(),
            sessions: BTreeMap::new(),
            active: 0,
            reserved: 0,
        }
    }
    fn forget(&mut self, id: &str) -> Result<(), &'static str> {
        let run = self.runs.get(id).ok_or("RUN_NOT_FOUND")?;
        if !run.terminal() {
            return Err("RUN_ACTIVE");
        }
        let reservation = run.reservation;
        self.runs.remove(id);
        self.reserved -= reservation;
        Ok(())
    }
}

pub struct Service {
    pub runtime: Runtime,
    pub id: String,
    pub(crate) registry: Mutex<Registry>,
    pub stopped: Arc<AtomicBool>,
    pub(crate) file_count: Arc<AtomicUsize>,
    pub(crate) file_cancellations: Mutex<BTreeMap<String, Arc<AtomicBool>>>,
}
impl Service {
    pub fn new(runtime: Runtime, stopped: Arc<AtomicBool>) -> io::Result<Self> {
        Ok(Self {
            runtime,
            id: sandcrab_core::new_uuid()?,
            registry: Mutex::new(Registry::new()),
            stopped,
            file_count: Arc::new(AtomicUsize::new(0)),
            file_cancellations: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn route(self: &Arc<Self>, method: &str, path: &str, body: &[u8]) -> (u16, Value) {
        if method == "GET" && (path == "/v1/openapi" || path.starts_with("/v1/openapi?")) {
            let capability = if path == "/v1/openapi" {
                None
            } else {
                let Some(name) = path
                    .strip_prefix("/v1/openapi?capability=")
                    .filter(|s| ["runs", "sessions", "volumes", "files"].contains(s))
                else {
                    return error(400, "INVALID_REQUEST");
                };
                Some(name)
            };
            return (200, crate::spec::document(capability));
        }
        if method == "GET" && path == "/v1/info" {
            let profiles = self.runtime.config.profiles.iter().map(|(name,p)|
                (name.clone(), json!({"timeoutMillis":p.timeout_millis,"outputLimitBytes":p.output_limit_bytes,"sessionTtlMillis":p.session_ttl_millis,"transferBytes":p.transfer_bytes,"network":p.network})))
                .collect::<serde_json::Map<_,_>>();
            let mut capabilities = vec!["runs", "sessions", "files"];
            let storage=self.runtime.storage.as_ref().map(|s| {
                capabilities.push("volumes");
                json!({"maxVolumeBytes":s.config.max_volume_bytes,"maxVolumeInodes":s.config.max_volume_inodes,
                    "maxVolumes":s.config.max_volumes,"maxRecords":s.config.max_records,"available":s.available()})
            });
            return (
                200,
                json!({"apiVersion":1,"serverId":self.id,"capabilities":capabilities,"profiles":profiles,"storage":storage,
                    "files":{"available":self.runtime.files.available(),"maxRecords":self.runtime.config.service.max_file_records,
                    "maxTransfers":self.runtime.config.service.max_file_transfers,"transferTimeoutMillis":30000,"entryLimit":10000}}),
            );
        }
        if method == "POST" && path == "/v1/runs" {
            let request = sandcrab_core::parse(body)
                .ok()
                .and_then(|v| serde_json::from_value(v).ok());
            return request
                .map(|r| self.submit(r))
                .unwrap_or_else(|| error(400, "INVALID_REQUEST"));
        }
        if path == "/v1/uploads"
            || path.starts_with("/v1/uploads/")
            || path.starts_with("/v1/uploads?")
        {
            return self.file_route(method, path, body);
        }
        if path == "/v1/sessions" || path.starts_with("/v1/sessions/") {
            return self.session_route(method, path, body);
        }
        if path == "/v1/volumes"
            || path.starts_with("/v1/volumes/")
            || path.starts_with("/v1/volumes?")
        {
            return self.volume_route(method, path, body);
        }
        let Some(path) = path.strip_prefix("/v1/runs/") else {
            return error(404, "NOT_FOUND");
        };
        let (id, action) = path.split_once('/').unwrap_or((path, ""));
        if !sandcrab_core::uuid(id) {
            return error(404, "RUN_NOT_FOUND");
        }
        if method == "POST"
            && ["cancel", "forget"].contains(&action)
            && sandcrab_core::parse(body).ok() != Some(json!({}))
        {
            return error(400, "INVALID_REQUEST");
        }
        let mut registry = self.registry.lock().unwrap();
        if method == "POST" && action == "forget" {
            return match registry.forget(id) {
                Ok(()) => (200, json!({"forgotten":true})),
                Err(code) => error(if code == "RUN_NOT_FOUND" { 404 } else { 409 }, code),
            };
        }
        let Some(run) = registry.runs.get_mut(id) else {
            return error(404, "RUN_NOT_FOUND");
        };
        if method == "POST" && action == "cancel" {
            let session = (!run.terminal())
                .then(|| run.request["sessionId"].as_str().map(str::to_owned))
                .flatten();
            if !run.terminal() {
                run.cancelled.store(true, Ordering::SeqCst);
            }
            let value = run.value();
            if let Some(session) = session {
                registry.stop_session(&session, "closed");
            }
            return (200, value);
        }
        if method == "GET" && action.is_empty() {
            return (200, run.value());
        }
        error(404, "NOT_FOUND")
    }

    fn submit(self: &Arc<Self>, request: Request) -> (u16, Value) {
        if request.server_id != self.id {
            return error(409, "SERVER_CHANGED");
        }
        let Some(profile) = self.runtime.config.profiles.get(&request.profile).cloned() else {
            return error(400, "PROFILE_NOT_FOUND");
        };
        let (timeout, limit) = match request.limits(&profile) {
            Ok(l) => l,
            Err(c) => return error(400, c),
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let id = request.id.clone();
        let mut registry = self.registry.lock().unwrap();
        if let Some(run) = registry.runs.get(&id) {
            return if run.request == serde_json::to_value(&request).unwrap() {
                (200, run.value())
            } else {
                error(409, "ID_CONFLICT")
            };
        }
        if registry.sessions.contains_key(&id) {
            return error(409, "ID_CONFLICT");
        }
        if self.stopped.load(Ordering::SeqCst) {
            return error(503, "STOPPING");
        }
        let limits = &self.runtime.config.service;
        if registry.active >= limits.max_sandboxes {
            return error(429, "RUN_CAPACITY");
        }
        if registry.runs.len() + registry.sessions.len() >= limits.max_records
            || registry.reserved + limit > limits.max_output_bytes
        {
            return error(429, "RESULT_CAPACITY");
        }
        registry.active += 1;
        registry.reserved += limit;
        let run = Run {
            request: serde_json::to_value(&request).unwrap(),
            profile: request.profile.clone(),
            state: "running".into(),
            result: None,
            cancelled: cancelled.clone(),
            reservation: limit,
        };
        let accepted = run.value();
        registry.runs.insert(id.clone(), run);
        let service = self.clone();
        if thread::Builder::new()
            .spawn(move || {
                let (finished, cleanup) = service.runtime.run(
                    &request.id,
                    &profile,
                    &request.command,
                    timeout,
                    limit,
                    &cancelled,
                );
                service.complete(&request.id, finished, cleanup, true);
            })
            .is_err()
        {
            registry.runs.remove(&id);
            registry.active -= 1;
            registry.reserved -= limit;
            return error(503, "RUN_UNAVAILABLE");
        }
        (202, accepted)
    }

    pub(crate) fn complete(
        &self,
        id: &str,
        finished: io::Result<job::Finished>,
        cleanup: io::Result<()>,
        release_admission: bool,
    ) {
        let mut registry = self.registry.lock().unwrap();
        let run = registry.runs.get_mut(id).unwrap();
        if cleanup.is_err() {
            run.state = "closing".into();
            run.result = Some(json!({"code":"CONTAINMENT_UNCONFIRMED"}));
            return;
        }
        let cancelled = run.cancelled.load(Ordering::SeqCst);
        match finished {
            Ok(finished) => {
                run.state = if cancelled {
                    "cancelled"
                } else {
                    match finished.end {
                        job::End::Timeout => "timed_out",
                        job::End::OutputLimit => "output_limit",
                        job::End::Cancelled => "cancelled",
                        job::End::ResourceLimit => "resource_limit",
                        job::End::Normal if finished.exit_code == 0 => "succeeded",
                        job::End::Normal => "failed",
                    }
                }
                .into();
                run.result = Some(
                    json!({"exitCode":finished.exit_code,"stdout":String::from_utf8_lossy(&finished.output[0]),
                    "stderr":String::from_utf8_lossy(&finished.output[1]),"truncated":finished.truncated}),
                );
            }
            Err(_) => {
                run.state = if cancelled { "cancelled" } else { "failed" }.into();
                run.result = Some(json!({"code":"RUN_FAILED"}));
            }
        }
        if release_admission {
            registry.active -= 1;
        } else if let Some(session_id) = run.request["sessionId"].as_str().map(str::to_owned)
            && let Some(session) = registry.sessions.get_mut(&session_id)
        {
            session.active_run = None;
            if session.state == "busy" {
                session.state = "ready".into();
            }
        }
    }

    pub fn shutdown(&self) -> io::Result<()> {
        self.stopped.store(true, Ordering::SeqCst);
        {
            let mut registry = self.registry.lock().unwrap();
            let sessions: Vec<_> = registry.sessions.keys().cloned().collect();
            for id in sessions {
                registry.stop_session(&id, "closed");
            }
            for run in registry.runs.values() {
                run.cancelled.store(true, Ordering::SeqCst);
            }
        }
        for flag in self.file_cancellations.lock().unwrap().values() {
            flag.store(true, Ordering::SeqCst);
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(75);
        loop {
            let registry = self.registry.lock().unwrap();
            if registry.runs.values().all(|r| r.state != "running")
                && self.runtime.storage.as_ref().is_none_or(|s| s.finished())
                && registry
                    .sessions
                    .values()
                    .all(|s| s.terminal() || s.state == "closing")
            {
                if registry.active != 0
                    || self.file_count.load(Ordering::SeqCst) != 0
                    || self
                        .runtime
                        .storage
                        .as_ref()
                        .is_some_and(|s| !s.quiescent())
                {
                    return Err(invalid("Containment unconfirmed; restart required"));
                }
                break;
            }
            drop(registry);
            if std::time::Instant::now() >= deadline {
                return Err(invalid("Shutdown containment deadline exceeded"));
            }
            thread::sleep(std::time::Duration::from_millis(25));
        }
        self.runtime.cleanup()
    }
}
pub fn error(status: u16, code: &str) -> (u16, Value) {
    (status, json!({"error":{"code":code}}))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        serde_json::from_value(json!({"id":"00000000-0000-4000-8000-000000000001","serverId":"00000000-0000-4000-8000-000000000002",
            "profile":"python","command":["python3","-c","print(1)"]})).unwrap()
    }
    #[test]
    fn callers_can_lower_but_not_raise_profile_limits() {
        let config = crate::config::Config::parse(include_str!("../config.example.toml")).unwrap();
        let profile = &config.profiles["python"];
        let mut input = request();
        assert_eq!(input.limits(profile), Ok((30000, 65536)));
        input.timeout_millis = Some(10);
        assert_eq!(input.limits(profile), Ok((10, 65536)));
        input.output_limit_bytes = Some(65537);
        assert_eq!(input.limits(profile), Err("PROFILE_LIMIT"));
        input.output_limit_bytes = Some(1);
        input.command.push("bad\0argument".into());
        assert_eq!(input.limits(profile), Err("INVALID_REQUEST"));
    }
    #[test]
    fn product_fields_and_host_configuration_are_not_request_options() {
        for key in [
            "accountId",
            "workspaceId",
            "uid",
            "mounts",
            "network",
            "memoryBytes",
        ] {
            let mut value = serde_json::to_value(request()).unwrap();
            value[key] = json!(0);
            assert!(serde_json::from_value::<Request>(value).is_err());
        }
    }
    #[test]
    fn running_and_uncontained_results_cannot_be_forgotten() {
        let mut registry = Registry::new();
        let request = request();
        let id = request.id.clone();
        registry.reserved = 123;
        registry.runs.insert(
            id.clone(),
            Run {
                request: serde_json::to_value(&request).unwrap(),
                profile: request.profile.clone(),
                state: "running".into(),
                result: None,
                cancelled: Arc::new(AtomicBool::new(false)),
                reservation: 123,
            },
        );
        assert_eq!(registry.forget(&id), Err("RUN_ACTIVE"));
        registry.runs.get_mut(&id).unwrap().state = "closing".into();
        assert_eq!(registry.forget(&id), Err("RUN_ACTIVE"));
        registry.runs.get_mut(&id).unwrap().state = "succeeded".into();
        registry.forget(&id).unwrap();
        assert_eq!(registry.reserved, 0);
        assert!(registry.runs.is_empty());
    }
}
