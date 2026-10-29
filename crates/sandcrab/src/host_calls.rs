//! Per-command opaque requests. Reply publication is separate from caller-side business effects.
use crate::config::invalid;
use base64::{Engine, engine::general_purpose::STANDARD};
use sandcrab_core::mailbox::Mailbox;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

pub const BYTES: usize = 65536;
pub const COUNT: usize = 64;
pub const FRAME: usize = 128 * 1024;
pub const DIRECTORY: &str = "/sandcrab-calls";

pub fn decode(value: &Value) -> Result<Vec<u8>, &'static str> {
    let text = value.as_str().ok_or("INVALID_CALL_PAYLOAD")?;
    if text.len() > BYTES.div_ceil(3) * 4 {
        return Err("CALL_PAYLOAD_LIMIT");
    }
    let bytes = STANDARD.decode(text).map_err(|_| "INVALID_CALL_PAYLOAD")?;
    if bytes.len() > BYTES || STANDARD.encode(&bytes) != text {
        return Err("CALL_PAYLOAD_LIMIT");
    }
    Ok(bytes)
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

struct Call {
    id: String,
    request_id: String,
    request: Option<Vec<u8>>,
    request_hash: String,
    reply_hash: Option<String>,
    state: &'static str,
}
impl Call {
    fn value(&self, sequence: usize, payload: bool) -> Value {
        let mut value = json!({"id":self.id,"requestId":self.request_id,"sequence":sequence,"state":self.state,
            "requestSha256":self.request_hash,"replySha256":self.reply_hash});
        if payload && let Some(bytes) = &self.request {
            value["base64"] = STANDARD.encode(bytes).into();
        }
        value
    }
}
#[derive(Default)]
struct State {
    mailbox: Option<Arc<Mailbox>>,
    calls: Vec<Call>,
    closed: bool,
    failure: Option<&'static str>,
}
pub struct Calls {
    state: Mutex<State>,
    cancelled: Arc<AtomicBool>,
    stopped: AtomicBool,
}
impl Calls {
    pub fn new(cancelled: Arc<AtomicBool>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::default(),
            cancelled,
            stopped: AtomicBool::new(false),
        })
    }
    pub fn start(self: &Arc<Self>, mailbox: Arc<Mailbox>, execution: &str) -> io::Result<Guard> {
        mailbox.reset(execution)?;
        self.state.lock().unwrap().mailbox = Some(mailbox.clone());
        let calls = self.clone();
        let execution = execution.to_owned();
        let reader = mailbox.clone();
        let worker = thread::Builder::new().spawn(move || {
            while !calls.stopped.load(Ordering::SeqCst) {
                let value = match reader.poll(Duration::from_millis(50), &execution) {
                    Ok(Some(value)) => value,
                    Ok(None) => continue,
                    Err(_) if calls.stopped.load(Ordering::SeqCst) => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        calls.fail("HOST_CALL_CHANNEL_FAILED");
                        break;
                    }
                };
                if let Err(code) = calls.receive(value) {
                    calls.fail(code);
                    break;
                }
            }
        })?;
        Ok(Guard {
            calls: self.clone(),
            mailbox,
            worker: Some(worker),
        })
    }
    fn receive(&self, value: Value) -> Result<(), &'static str> {
        let body = &value["arguments"];
        if body.as_object().is_none_or(|v| v.len() != 1) {
            return Err("INVALID_CALL_PAYLOAD");
        }
        let bytes = decode(&body["base64"])?;
        let id = value["requestId"]
            .as_str()
            .filter(|s| sandcrab_core::uuid(s))
            .ok_or("INVALID_CALL_ID")?;
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return Ok(());
        }
        if state.calls.len() == COUNT || state.calls.iter().any(|c| c.request_id == id) {
            return Err("CALL_CAPACITY");
        }
        state.calls.push(Call {
            // An untrusted guest cannot choose a public reply identity for another generation.
            id: sandcrab_core::new_uuid().map_err(|_| "HOST_CALL_UNAVAILABLE")?,
            request_id: id.into(),
            request_hash: digest(&bytes),
            request: Some(bytes),
            reply_hash: None,
            state: "pending",
        });
        Ok(())
    }
    pub fn fail(&self, code: &'static str) {
        self.state.lock().unwrap().failure = Some(code);
        self.cancelled.store(true, Ordering::SeqCst);
    }
    pub fn failure(&self) -> Option<&'static str> {
        self.state.lock().unwrap().failure
    }
    pub fn list(&self) -> Value {
        let state = self.state.lock().unwrap();
        json!({"closed":state.closed,"error":state.failure,
            "calls":state.calls.iter().enumerate().map(|(i,c)|c.value(i + 1,false)).collect::<Vec<_>>()})
    }
    /// A repeated identical reply confirms publication; it never publishes another file.
    /// An uncertain publication stays uncertain even when the caller retries.
    pub fn reply(&self, id: &str, bytes: &[u8]) -> Result<Value, (u16, &'static str)> {
        if bytes.len() > BYTES {
            return Err((413, "CALL_PAYLOAD_LIMIT"));
        }
        let hash = digest(bytes);
        let mut state = self.state.lock().unwrap();
        let index = state
            .calls
            .iter()
            .position(|c| c.id == id)
            .ok_or((404, "CALL_NOT_FOUND"))?;
        let call = &state.calls[index];
        if let Some(existing) = &call.reply_hash {
            if existing != &hash {
                return Err((409, "CALL_REPLY_CONFLICT"));
            }
            return if call.state == "replied" {
                Ok(call.value(index + 1, false))
            } else {
                Err((503, "CALL_REPLY_UNCERTAIN"))
            };
        }
        if state.closed || self.cancelled.load(Ordering::SeqCst) {
            return Err((409, "CALL_CLOSED"));
        }
        let mailbox = state.mailbox.clone().ok_or((409, "CALL_CLOSED"))?;
        let request_id = state.calls[index].request_id.clone();
        // Record intent before publication. A filesystem error cannot authorize replay.
        state.calls[index].reply_hash = Some(hash);
        state.calls[index].state = "uncertain";
        state.calls[index].request.take();
        if mailbox
            .complete(&request_id, &json!({"base64":STANDARD.encode(bytes)}))
            .is_err()
        {
            state.failure = Some("CALL_REPLY_UNCERTAIN");
            self.cancelled.store(true, Ordering::SeqCst);
            return Err((503, "CALL_REPLY_UNCERTAIN"));
        }
        state.calls[index].state = "replied";
        Ok(state.calls[index].value(index + 1, false))
    }
    pub fn length(&self) -> usize {
        self.state.lock().unwrap().calls.len()
    }
    /// Completed requests are not offered as work again. Unanswered requests keep their IDs.
    pub fn next(&self, cursor: &mut usize) -> Option<Value> {
        let state = self.state.lock().unwrap();
        while let Some(call) = state.calls.get(*cursor) {
            *cursor += 1;
            if call.state == "pending" {
                return Some(call.value(*cursor, true));
            }
        }
        None
    }
    pub fn close(&self) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        self.stopped.store(true, Ordering::SeqCst);
        for call in &mut state.calls {
            if call.state == "pending" {
                call.state = "abandoned";
                call.request.take();
            }
        }
        state.mailbox.take();
    }
}

pub struct Guard {
    calls: Arc<Calls>,
    mailbox: Arc<Mailbox>,
    worker: Option<JoinHandle<()>>,
}
impl Guard {
    pub fn finish(&mut self) -> io::Result<()> {
        self.calls.close();
        let reset = self.mailbox.reset("");
        let joined = self
            .worker
            .take()
            .map(|w| w.join())
            .transpose()
            .map_err(|_| invalid("Host-call worker failed"));
        reset.and(joined.map(|_| ()))
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        if self.worker.is_some() {
            let _ = self.finish();
        }
    }
}

impl crate::service::Service {
    pub(crate) fn calls(&self, id: &str) -> Result<(Arc<Calls>, String), (u16, Value)> {
        let registry = self.registry.lock().unwrap();
        let run = registry
            .runs
            .get(id)
            .ok_or_else(|| crate::service::error(404, "RUN_NOT_FOUND"))?;
        let calls = run
            .calls
            .clone()
            .ok_or_else(|| crate::service::error(409, "HOST_CALLS_DISABLED"))?;
        Ok((calls, run.stream_id.clone()))
    }
    pub(crate) fn call_route(
        &self,
        method: &str,
        id: &str,
        action: &str,
        body: &[u8],
    ) -> (u16, Value) {
        use crate::service::error;
        let (calls, _) = match self.calls(id) {
            Ok(value) => value,
            Err(error) => return error,
        };
        if method == "GET" && action == "calls" {
            return (200, calls.list());
        }
        let Some(request) = action
            .strip_prefix("calls/")
            .and_then(|s| s.strip_suffix("/reply"))
            .filter(|s| sandcrab_core::uuid(s))
        else {
            return error(404, "NOT_FOUND");
        };
        if method != "POST" {
            return error(404, "NOT_FOUND");
        }
        let value = match sandcrab_core::parse(body) {
            Ok(value) if value.as_object().is_some_and(|v| v.len() == 1) => value,
            _ => return error(400, "INVALID_CALL_PAYLOAD"),
        };
        let bytes = match decode(&value["base64"]) {
            Ok(bytes) => bytes,
            Err(code) => return error(400, code),
        };
        match calls.reply(request, &bytes) {
            Ok(reply) => (200, reply),
            Err((status, code)) => error(status, code),
        }
    }
}

pub fn reply_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/v1/runs/") else {
        return false;
    };
    let parts: Vec<_> = rest.split('/').collect();
    matches!(parts.as_slice(), [run,"calls",call,"reply"] if sandcrab_core::uuid(run) && sandcrab_core::uuid(call))
}
