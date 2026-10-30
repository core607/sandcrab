//! Versioned SDK adapter. Native session/run generations remain the execution authority.
use crate::{
    auth::Token,
    sdk_commands,
    sdk_types::{self, Result},
    service::Service,
    transport::Stream,
};
use sandcrab_core::http;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    io::{self, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

pub struct Sandbox {
    pub id: String,
    pub incarnation: String,
    pub environment: BTreeMap<String, String>,
    pub profile: String,
    metadata: BTreeMap<String, String>,
    created: u64,
    token: Token,
    pub gate: Mutex<()>,
    pub closing: AtomicBool,
    pub contexts: Mutex<crate::sdk_contexts::Contexts>,
}
#[derive(Default)]
pub struct State {
    pub sandboxes: BTreeMap<String, Arc<Sandbox>>,
    pub commands: VecDeque<Arc<sdk_commands::Command>>,
}
#[derive(Default)]
pub struct Book {
    pub state: Mutex<State>,
}
impl Book {
    pub fn sandbox(&self, id: &str) -> Result<Arc<Sandbox>> {
        self.state
            .lock()
            .unwrap()
            .sandboxes
            .get(id)
            .cloned()
            .ok_or((404, "SANDBOX_NOT_FOUND"))
    }
    pub fn command(&self, id: &str) -> Option<Arc<sdk_commands::Command>> {
        self.state
            .lock()
            .unwrap()
            .commands
            .iter()
            .find(|c| c.id == id)
            .cloned()
    }
}
pub fn path(path: &str) -> bool {
    path == "/v1/sandboxes"
        || path.starts_with("/v1/sandboxes/")
        || path.starts_with("/v1/sandboxes?")
        || path.starts_with("/opensandbox/")
}
fn split(path: &str) -> (&str, &str) {
    path.split_once('?').unwrap_or((path, ""))
}
fn execd(path: &str) -> Option<(&str, &str)> {
    let (id, action) = path.strip_prefix("/opensandbox/")?.split_once('/')?;
    sandcrab_core::uuid(id).then_some((id, action))
}
pub(crate) fn empty_post(path: &str) -> bool {
    matches!(execd(path), Some((_, "session")))
}
pub fn write(stream: &Stream, status: u16, value: &Value, close: bool) -> io::Result<()> {
    let bytes = if status == 204 || (status == 200 && value.is_null()) {
        Vec::new()
    } else {
        serde_json::to_vec(value)?
    };
    let mut output = crate::events::Output {
        stream,
        deadline: Instant::now() + Duration::from_secs(5),
    };
    http::response_head_with(
        &mut output,
        status,
        "application/json",
        bytes.len() as u64,
        close,
        &[],
    )?;
    output.write_all(&bytes)
}
fn state(native: &Value) -> &'static str {
    match native["state"].as_str() {
        Some("ready" | "busy") => "Running",
        Some("starting") => "Pending",
        Some("closed" | "expired") => "Terminated",
        Some("failed") => "Failed",
        _ => "Stopping",
    }
}
impl Service {
    pub(crate) fn sdk_authorized(&self, head: &http::Head) -> bool {
        let (path, _) = split(&head.path);
        if let Some((id, _)) = execd(path) {
            let Ok(sandbox) = self.sdk.sandbox(id) else {
                return false;
            };
            return sandbox.token.matches(head.header("x-execd-access-token"))
                && self
                    .registry
                    .lock()
                    .unwrap()
                    .sessions
                    .get(id)
                    .is_some_and(|s| s.incarnation == sandbox.incarnation);
        }
        self.runtime
            .config
            .tcp
            .as_ref()
            .and_then(|t| t.token.as_ref())
            .is_some_and(|t| t.matches(head.header("open-sandbox-api-key")))
    }
    pub(crate) fn sdk_native(
        self: &Arc<Self>,
        sandbox: &Sandbox,
        action: &str,
        body: Option<&Value>,
    ) -> Result<Value> {
        let path = if action.is_empty() {
            format!("/v1/sessions/{}", sandbox.id)
        } else {
            format!("/v1/sessions/{}/{}", sandbox.id, action)
        };
        sdk_types::native(
            self.session_route_expected(
                if body.is_some() { "POST" } else { "GET" },
                &path,
                &body
                    .map(|v| serde_json::to_vec(v).unwrap())
                    .unwrap_or_default(),
                Some(&sandbox.incarnation),
            ),
        )
    }
    fn sdk_value(self: &Arc<Self>, sandbox: &Sandbox) -> Result<Value> {
        let native = self.sdk_native(sandbox, "", None)?;
        Ok(
            json!({"id":sandbox.id,"image":{"uri":sandbox.profile},"entrypoint":sdk_types::IDLE,
            "metadata":sandbox.metadata,"createdAt":sdk_types::timestamp(sandbox.created),
            "expiresAt":sdk_types::timestamp(native["expiresAtMillis"].as_u64().ok_or((503,"INVALID_NATIVE_STATE"))?),
            "status":{"state":state(&native)}}),
        )
    }
    fn sdk_create(self: &Arc<Self>, bytes: &[u8]) -> Result<(u16, Value)> {
        let request: sdk_types::Create = sdk_types::parse(bytes)?;
        if !request.supported() {
            return Err((400, "UNSUPPORTED_CREATE_OPTION"));
        }
        if !sdk_types::strings(&request.env, true) || !sdk_types::strings(&request.metadata, false)
        {
            return Err((400, "INVALID_METADATA_OR_ENVIRONMENT"));
        }
        let ttl = request
            .timeout
            .filter(|n| (60..=86400).contains(n))
            .ok_or((400, "BOUNDED_TIMEOUT_REQUIRED"))?
            * 1000;
        let resources = request.resource_limits.native()?;
        self.sdk_reap();
        let id = sandcrab_core::new_uuid().map_err(|_| (503, "SANDBOX_UNAVAILABLE"))?;
        let token = Token::random().map_err(|_| (503, "SANDBOX_UNAVAILABLE"))?;
        let input = json!({"id":id,"serverId":self.id,"profile":request.image.uri,"ttlMillis":ttl,"resources":resources});
        let accepted = sdk_types::native(self.session_route(
            "POST",
            "/v1/sessions",
            &serde_json::to_vec(&input).unwrap(),
        ))?;
        let (incarnation, expires_at) = self
            .registry
            .lock()
            .unwrap()
            .sessions
            .get(&id)
            .map(|s| (s.incarnation.clone(), s.expires_at))
            .ok_or((503, "SANDBOX_OUTCOME_UNKNOWN"))?;
        let sandbox = Arc::new(Sandbox {
            id: id.clone(),
            incarnation,
            profile: request.image.uri,
            environment: request.env,
            metadata: request.metadata,
            created: sdk_types::now(),
            token,
            gate: Mutex::new(()),
            closing: AtomicBool::new(false),
            contexts: Mutex::new(crate::sdk_contexts::Contexts::default()),
        });
        let response = json!({"id":id,"entrypoint":sdk_types::IDLE,"metadata":sandbox.metadata,
            "createdAt":sdk_types::timestamp(sandbox.created),"expiresAt":sdk_types::timestamp(expires_at),
            "status":{"state":state(&accepted)}});
        self.sdk.state.lock().unwrap().sandboxes.insert(id, sandbox);
        Ok((202, response))
    }
    fn sdk_remove(self: &Arc<Self>, sandbox: &Sandbox) -> Result<()> {
        sandbox.closing.store(true, Ordering::SeqCst);
        match self.sdk_native(sandbox, "close", Some(&json!({}))) {
            Ok(_) => (),
            Err((404 | 409, "NOT_FOUND" | "SANDBOX_CHANGED")) => {
                self.sdk_close_contexts(sandbox)?;
                self.sdk.state.lock().unwrap().sandboxes.remove(&sandbox.id);
                return Ok(());
            }
            Err(error) => return Err(error),
        }
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            let native = self.sdk_native(sandbox, "", None)?;
            if ["closed", "expired", "failed"].contains(&native["state"].as_str().unwrap_or("")) {
                break;
            }
            if native["state"] == "closing" || Instant::now() >= deadline {
                return Err((503, "CONTAINMENT_UNCONFIRMED"));
            }
            thread::sleep(Duration::from_millis(10));
        }
        let commands = self
            .sdk
            .state
            .lock()
            .unwrap()
            .commands
            .iter()
            .filter(|c| c.sandbox == sandbox.id)
            .cloned()
            .collect::<Vec<_>>();
        for command in commands {
            self.sdk_collect(&command);
        }
        self.sdk_close_contexts(sandbox)?;
        self.sdk_native(sandbox, "forget", Some(&json!({})))?;
        self.sdk.state.lock().unwrap().sandboxes.remove(&sandbox.id);
        Ok(())
    }
    pub(crate) fn sdk_reap(self: &Arc<Self>) {
        let sandboxes = self
            .sdk
            .state
            .lock()
            .unwrap()
            .sandboxes
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for sandbox in sandboxes {
            let Ok(_gate) = sandbox.gate.try_lock() else {
                continue;
            };
            let native = match self.sdk_native(&sandbox, "", None) {
                Ok(value) => value,
                Err((404 | 409, "NOT_FOUND" | "SANDBOX_CHANGED")) => {
                    let _ = self.sdk_remove(&sandbox);
                    continue;
                }
                Err(_) => continue,
            };
            if !["closed", "expired", "failed"].contains(&native["state"].as_str().unwrap_or("")) {
                continue;
            }
            if self
                .sdk
                .state
                .lock()
                .unwrap()
                .commands
                .iter()
                .any(|c| c.sandbox == sandbox.id && c.observed.load(Ordering::SeqCst))
            {
                continue;
            }
            let _ = self.sdk_remove(&sandbox);
        }
    }
    fn sdk_list(self: &Arc<Self>, pairs: &[(String, String)]) -> Result<Value> {
        let (mut page, mut size) = (None, None);
        let mut states = Vec::new();
        let mut metadata = None;
        for (key, value) in pairs {
            match key.as_str() {
                "page" if page.is_none() => {
                    page = Some(value.parse::<usize>().map_err(|_| (400, "INVALID_QUERY"))?)
                }
                "pageSize" if size.is_none() => {
                    size = Some(value.parse::<usize>().map_err(|_| (400, "INVALID_QUERY"))?)
                }
                "state" => states.extend(value.split(',').map(str::to_owned)),
                "metadata" if metadata.is_none() => metadata = Some(value),
                _ => return Err((400, "INVALID_QUERY")),
            }
        }
        let (page, size) = (page.unwrap_or(1), size.unwrap_or(20));
        if !(1..=1024).contains(&page) || !(1..=100).contains(&size) {
            return Err((400, "INVALID_QUERY"));
        }
        let filters = metadata
            .filter(|v| !v.is_empty())
            .map(|value| sdk_types::query(value))
            .transpose()?
            .unwrap_or_default();
        let sandboxes = self
            .sdk
            .state
            .lock()
            .unwrap()
            .sandboxes
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut items = Vec::new();
        for sandbox in sandboxes {
            if !filters
                .iter()
                .all(|(k, v)| sandbox.metadata.get(k).is_some_and(|value| value == v))
            {
                continue;
            }
            let Ok(value) = self.sdk_value(&sandbox) else {
                continue;
            };
            if !states.is_empty() && !states.iter().any(|s| value["status"]["state"] == *s) {
                continue;
            }
            items.push(value);
        }
        let total = items.len();
        let pages = total.div_ceil(size);
        let items = items
            .into_iter()
            .skip((page - 1) * size)
            .take(size)
            .collect::<Vec<_>>();
        Ok(
            json!({"items":items,"pagination":{"page":page,"pageSize":size,"totalItems":total,"totalPages":pages,"hasNextPage":page<pages}}),
        )
    }
    fn sdk_route(
        self: &Arc<Self>,
        method: &str,
        path: &str,
        query: &str,
        body: &[u8],
    ) -> Result<(u16, Value)> {
        let pairs = sdk_types::query(query)?;
        if path == "/v1/sandboxes" {
            return match method {
                "POST" if pairs.is_empty() => self.sdk_create(body),
                "GET" => Ok((200, self.sdk_list(&pairs)?)),
                _ => Err((404, "NOT_FOUND")),
            };
        }
        if let Some((id, action)) = execd(path) {
            let sandbox = self.sdk.sandbox(id)?;
            if method == "GET" && action == "ping" && pairs.is_empty() {
                let value = self.sdk_native(&sandbox, "", None)?;
                return if state(&value) == "Running" {
                    Ok((200, json!({"status":"ok"})))
                } else {
                    Err((503, "SANDBOX_NOT_READY"))
                };
            }
            if method == "GET" && action == "egress/policy" && pairs.is_empty() {
                self.sdk_native(&sandbox, "", None)?;
                return Ok((200, json!({"policy":{"defaultAction":"deny","egress":[]}})));
            }
            if crate::sdk_fs::endpoint(method, action) {
                let request = crate::sdk_fs::Request::parse(method, action, &pairs, body)?;
                return Ok((200, self.sdk_file_operation(id, &request)?));
            }
            if pairs.is_empty() && (action == "session" || action.starts_with("session/")) {
                return self.sdk_context_route(&sandbox, method, action, body);
            }
            return self.sdk_command_route(&sandbox, method, action, &pairs);
        }
        let rest = path
            .strip_prefix("/v1/sandboxes/")
            .ok_or((404, "NOT_FOUND"))?;
        let (id, action) = rest.split_once('/').unwrap_or((rest, ""));
        let sandbox = self.sdk.sandbox(id)?;
        match (method, action) {
            ("GET", "") if pairs.is_empty() => Ok((200, self.sdk_value(&sandbox)?)),
            ("DELETE", "") if pairs.is_empty() => {
                let _gate = sandbox.gate.lock().unwrap();
                self.sdk_remove(&sandbox)?;
                Ok((204, Value::Null))
            }
            ("POST", "renew-expiration") if pairs.is_empty() => {
                #[derive(Deserialize)]
                #[serde(rename_all = "camelCase", deny_unknown_fields)]
                struct Renew {
                    expires_at: String,
                }
                let input: Renew = sdk_types::parse(body)?;
                let _gate = sandbox.gate.lock().unwrap();
                if sandbox.closing.load(Ordering::SeqCst) {
                    return Err((409, "SANDBOX_CLOSING"));
                }
                self.sdk_native(
                    &sandbox,
                    "renew",
                    Some(&json!({"ttlMillis":sdk_types::expiration(&input.expires_at)?})),
                )?;
                Ok((
                    200,
                    json!({"expiresAt":sdk_types::timestamp(self.sdk_expiration(&sandbox)?)}),
                ))
            }
            ("GET", "endpoints/44772" | "endpoints/18080") => {
                if pairs.len() > 1
                    || pairs.iter().any(|(k, v)| {
                        k != "use_server_proxy" || !["true", "false"].contains(&v.as_str())
                    })
                {
                    return Err((400, "UNSUPPORTED_ENDPOINT_OPTION"));
                }
                let value = self.sdk_native(&sandbox, "", None)?;
                if !["Pending", "Running"].contains(&state(&value)) {
                    return Err((409, "SANDBOX_NOT_READY"));
                }
                let listen = &self.runtime.config.tcp.as_ref().unwrap().listen;
                let suffix = if action == "endpoints/18080" {
                    "/egress"
                } else {
                    ""
                };
                Ok((
                    200,
                    json!({"endpoint":format!("{listen}/opensandbox/{id}{suffix}"),"headers":{"X-EXECD-ACCESS-TOKEN":sandbox.token.text()}}),
                ))
            }
            _ => Err((400, "UNSUPPORTED_OPERATION")),
        }
    }
    pub(crate) fn sdk_exchange(
        self: &Arc<Self>,
        stream: &Stream,
        head: &http::Head,
        body: &[u8],
        close: bool,
    ) -> io::Result<()> {
        let (path, query) = split(&head.path);
        if head.method == "POST"
            && query.is_empty()
            && let Some((id, action)) = execd(path)
            && (action == "command" || crate::sdk_contexts::execution_path(action).is_some())
        {
            return match self.sdk_execute(id, crate::sdk_contexts::execution_path(action), body) {
                Ok(observer) => observer.write(stream, close),
                Err(error) => {
                    let (status, value) = sdk_types::reply(error);
                    write(stream, status, &value, close)
                }
            };
        }
        let (status, value) = self
            .sdk_route(&head.method, path, query, body)
            .unwrap_or_else(sdk_types::reply);
        write(stream, status, &value, close)
    }
}
