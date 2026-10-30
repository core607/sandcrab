//! SDK output observation owns native result retention until its last frame or disconnect.
use crate::{
    events,
    opensandbox::Sandbox,
    sdk_types::{self, Result},
    service::{Run, Service},
    transport::Stream,
};
use sandcrab_core::http;
use serde_json::{Value, json};
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct Outcome {
    state: String,
    result: Value,
    finished: u64,
}
impl Outcome {
    fn of(run: &Run) -> Self {
        Self {
            state: run.state.clone(),
            result: run.result.clone().unwrap_or(Value::Null),
            finished: sdk_types::now(),
        }
    }
    fn code(&self) -> &str {
        match self.state.as_str() {
            "cancelled" => "COMMAND_CANCELLED",
            "timed_out" => "COMMAND_TIMEOUT",
            "output_limit" => "OUTPUT_LIMIT",
            "resource_limit" => "RESOURCE_LIMIT",
            _ => self.result["code"].as_str().unwrap_or("COMMAND_FAILED"),
        }
    }
}
pub struct Command {
    pub id: String,
    pub sandbox: String,
    content: String,
    started: u64,
    incarnation: Mutex<Option<String>>,
    pub observed: AtomicBool,
    pub outcome: Mutex<Option<Outcome>>,
}
pub struct Observer {
    service: Arc<Service>,
    command: Arc<Command>,
    _admission: events::Admission,
}
impl Drop for Observer {
    fn drop(&mut self) {
        self.command.observed.store(false, Ordering::SeqCst);
        self.service.sdk_collect(&self.command);
    }
}
impl Service {
    pub(crate) fn sdk_completed(&self, id: &str) {
        if let Some(command) = self.sdk.command(id) {
            self.sdk_collect(&command);
        }
    }
    pub(crate) fn sdk_collect(&self, command: &Command) {
        let incarnation = command.incarnation.lock().unwrap().clone();
        let Some(incarnation) = incarnation else {
            return;
        };
        let mut registry = self.registry.lock().unwrap();
        let Some(run) = registry.runs.get(&command.id) else {
            return;
        };
        if run.stream_id != incarnation || !run.terminal() {
            return;
        }
        // Never acquire the SDK book while holding the native registry or outcome lock.
        let mut outcome = command.outcome.lock().unwrap();
        if outcome.is_none() {
            *outcome = Some(Outcome::of(run));
        }
        if !command.observed.load(Ordering::SeqCst) {
            let _ = registry.forget(&command.id);
        }
    }
    pub(crate) fn sdk_execute(self: &Arc<Self>, sandbox: &str, body: &[u8]) -> Result<Observer> {
        let sandbox = self.sdk.sandbox(sandbox)?;
        let input: sdk_types::Execute = sdk_types::parse(body)?;
        let (content, source) = input.source(&sandbox.environment)?;
        let _gate = sandbox.gate.lock().unwrap();
        if sandbox.closing.load(Ordering::SeqCst) {
            return Err((409, "SANDBOX_CLOSING"));
        }
        let admission = events::admit(self).map_err(|(status, _)| (status, "EVENT_CAPACITY"))?;
        let command = Arc::new(Command {
            id: sandcrab_core::new_uuid().map_err(|_| (503, "COMMAND_UNAVAILABLE"))?,
            sandbox: sandbox.id.clone(),
            content,
            started: sdk_types::now(),
            incarnation: Mutex::new(None),
            observed: AtomicBool::new(true),
            outcome: Mutex::new(None),
        });
        {
            let mut book = self.sdk.state.lock().unwrap();
            if book.commands.len() >= self.runtime.config.service.max_records {
                let index = book
                    .commands
                    .iter()
                    .position(|c| {
                        !c.observed.load(Ordering::SeqCst) && c.outcome.lock().unwrap().is_some()
                    })
                    .ok_or((429, "COMMAND_HISTORY_CAPACITY"))?;
                book.commands.remove(index);
            }
            book.commands.push_back(command.clone());
        }
        let accepted = self.sdk_native(
            &sandbox,
            "commands",
            Some(&json!({"id":command.id,"serverId":self.id,
            "command":source,"timeoutMillis":input.timeout})),
        );
        if let Err(error) = accepted {
            self.sdk
                .state
                .lock()
                .unwrap()
                .commands
                .retain(|c| c.id != command.id);
            return Err(error);
        }
        let observer = Observer {
            service: self.clone(),
            command: command.clone(),
            _admission: admission,
        };
        let incarnation = self
            .registry
            .lock()
            .unwrap()
            .runs
            .get(&command.id)
            .map(|r| r.stream_id.clone());
        *command.incarnation.lock().unwrap() = incarnation;
        if command.incarnation.lock().unwrap().is_none() {
            return Err((503, "COMMAND_OUTCOME_UNKNOWN"));
        }
        self.sdk_collect(&command);
        Ok(observer)
    }
    pub(crate) fn sdk_command_route(
        self: &Arc<Self>,
        sandbox: &Sandbox,
        method: &str,
        path: &str,
        pairs: &[(String, String)],
    ) -> Result<(u16, Value)> {
        let id = if method == "GET" && pairs.is_empty() {
            path.strip_prefix("command/status/")
                .ok_or((400, "UNSUPPORTED_OPERATION"))?
        } else if method == "DELETE" && path == "command" && pairs.len() == 1 && pairs[0].0 == "id"
        {
            &pairs[0].1
        } else {
            return Err((400, "UNSUPPORTED_OPERATION"));
        };
        let command = self
            .sdk
            .command(id)
            .filter(|c| c.sandbox == sandbox.id)
            .ok_or((404, "COMMAND_NOT_FOUND"))?;
        self.sdk_native(sandbox, "", None)?;
        if method == "DELETE" {
            let incarnation = command
                .incarnation
                .lock()
                .unwrap()
                .clone()
                .ok_or((503, "COMMAND_OUTCOME_UNKNOWN"))?;
            let mut registry = self.registry.lock().unwrap();
            if registry
                .sessions
                .get(&sandbox.id)
                .is_none_or(|s| s.incarnation != sandbox.incarnation)
            {
                return Err((409, "SANDBOX_CHANGED"));
            }
            if let Some(run) = registry.runs.get(id) {
                if run.stream_id != incarnation {
                    return Err((409, "COMMAND_CHANGED"));
                }
                if !run.terminal() {
                    registry.stop_session(&sandbox.id, "closed");
                }
            } else if command.outcome.lock().unwrap().is_none() {
                return Err((503, "COMMAND_OUTCOME_UNKNOWN"));
            }
            return Ok((200, Value::Null));
        }
        self.sdk_collect(&command);
        let incarnation = command.incarnation.lock().unwrap().clone();
        let outcome = {
            let registry = self.registry.lock().unwrap();
            let cached = command.outcome.lock().unwrap().clone();
            if cached.is_some() {
                cached
            } else {
                let run = registry
                    .runs
                    .get(id)
                    .ok_or((503, "COMMAND_OUTCOME_UNKNOWN"))?;
                if incarnation.as_deref() != Some(run.stream_id.as_str()) {
                    return Err((409, "COMMAND_CHANGED"));
                }
                if run.state == "closing" {
                    return Err((503, "CONTAINMENT_UNCONFIRMED"));
                }
                run.terminal().then(|| Outcome::of(run))
            }
        };
        let mut value = json!({"id":id,"content":command.content,"running":outcome.is_none(),
            "started_at":sdk_types::timestamp(command.started),"finished_at":null,"exit_code":null});
        if let Some(outcome) = outcome {
            value["finished_at"] = sdk_types::timestamp(outcome.finished).into();
            value["exit_code"] = outcome.result["exitCode"].clone();
            if outcome.state != "succeeded" {
                value["error"] = outcome.code().into();
            }
        }
        Ok((200, value))
    }
}

#[derive(Default)]
struct Text {
    pending: Vec<u8>,
}
impl Text {
    fn push(&mut self, bytes: &[u8], end: bool) -> String {
        self.pending.extend_from_slice(bytes);
        let mut output = String::new();
        let mut used = 0;
        loop {
            match std::str::from_utf8(&self.pending[used..]) {
                Ok(text) => {
                    output.push_str(text);
                    used = self.pending.len();
                    break;
                }
                Err(error) => {
                    let valid = used + error.valid_up_to();
                    output.push_str(std::str::from_utf8(&self.pending[used..valid]).unwrap());
                    used = valid;
                    if let Some(count) = error.error_len() {
                        output.push('\u{fffd}');
                        used += count;
                    } else {
                        if end {
                            output.push('\u{fffd}');
                            used = self.pending.len();
                        }
                        break;
                    }
                }
            }
        }
        self.pending.drain(..used);
        output
    }
}
enum Next {
    Output(usize, Vec<u8>),
    Done(Outcome),
    Wait,
}
impl Observer {
    fn frame(&self, stream: &Stream, kind: &str, mut value: Value) -> io::Result<()> {
        value["type"] = kind.into();
        value["timestamp"] = sdk_types::now().into();
        let bytes = format!(
            "event: {kind}\ndata: {}\n\n",
            serde_json::to_string(&value)?
        );
        if bytes.len() > 32768 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        http::chunk(
            &mut events::Output {
                stream,
                deadline: Instant::now() + Duration::from_secs(5),
            },
            bytes.as_bytes(),
        )
    }
    fn next(
        &self,
        offsets: &mut [usize; 2],
        stream: &mut usize,
        flush: bool,
    ) -> std::result::Result<Next, &'static str> {
        let incarnation = self.command.incarnation.lock().unwrap().clone();
        let registry = self.service.registry.lock().unwrap();
        let run = registry
            .runs
            .get(&self.command.id)
            .ok_or("COMMAND_OUTCOME_UNKNOWN")?;
        if incarnation.as_deref() != Some(run.stream_id.as_str()) {
            return Err("COMMAND_CHANGED");
        }
        for index in [*stream, 1 - *stream] {
            let available = run.output[index].len().saturating_sub(offsets[index]);
            if available == 0 || (available < events::BLOCK && !flush && run.state == "running") {
                continue;
            }
            let start = offsets[index];
            offsets[index] += available.min(events::BLOCK);
            *stream = 1 - index;
            return Ok(Next::Output(
                index,
                run.output[index][start..offsets[index]].to_vec(),
            ));
        }
        if run.state == "closing" {
            return Err("CONTAINMENT_UNCONFIRMED");
        }
        Ok(if run.terminal() {
            Next::Done(Outcome::of(run))
        } else {
            Next::Wait
        })
    }
    pub fn write(self, stream: &Stream, close: bool) -> io::Result<()> {
        http::event_head(
            &mut events::Output {
                stream,
                deadline: Instant::now() + Duration::from_secs(5),
            },
            close,
        )?;
        self.frame(stream, "init", json!({"text":self.command.id}))?;
        let (mut offsets, mut next_stream) = ([0, 0], 0);
        let mut text = [Text::default(), Text::default()];
        let mut flush = Instant::now() + Duration::from_millis(40);
        let mut heartbeat = Instant::now() + Duration::from_secs(1);
        let deadline = Instant::now() + events::TIMEOUT;
        loop {
            let next = if self.service.stopped.load(Ordering::SeqCst) {
                Err("STOPPING")
            } else if Instant::now() >= deadline {
                Err("OBSERVATION_TIMEOUT")
            } else {
                self.next(&mut offsets, &mut next_stream, Instant::now() >= flush)
            };
            match next {
                Ok(Next::Output(index, bytes)) => {
                    let value = text[index].push(&bytes, false);
                    if !value.is_empty() {
                        self.frame(stream, ["stdout", "stderr"][index], json!({"text":value}))?;
                    }
                    flush = Instant::now() + Duration::from_millis(40);
                }
                Ok(Next::Done(outcome)) => {
                    for (index, decoder) in text.iter_mut().enumerate() {
                        let value = decoder.push(&[], true);
                        if !value.is_empty() {
                            self.frame(stream, ["stdout", "stderr"][index], json!({"text":value}))?;
                        }
                    }
                    if outcome.state != "succeeded" {
                        let value = outcome.result["exitCode"]
                            .as_i64()
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| outcome.code().into());
                        self.frame(
                            stream,
                            "error",
                            json!({"error":{"ename":outcome.code(),"evalue":value,"traceback":[]}}),
                        )?;
                    }
                    self.frame(stream,"execution_complete",json!({"execution_time":outcome.finished.saturating_sub(self.command.started)}))?;
                    break;
                }
                Err(code) => {
                    self.frame(
                        stream,
                        "error",
                        json!({"error":{"ename":code,"evalue":"unknown","traceback":[]}}),
                    )?;
                    break;
                }
                Ok(Next::Wait) => {
                    if Instant::now() >= heartbeat {
                        http::chunk(
                            &mut events::Output {
                                stream,
                                deadline: Instant::now() + Duration::from_secs(5),
                            },
                            b": keep-alive\n\n",
                        )?;
                        heartbeat = Instant::now() + Duration::from_secs(1);
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
        http::end_chunks(&mut events::Output {
            stream,
            deadline: Instant::now() + Duration::from_secs(5),
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn text_keeps_split_utf8_and_marks_invalid_or_truncated_bytes() {
        let mut decoder = Text::default();
        assert_eq!(decoder.push(&[0xe4, 0xb8], false), "");
        assert_eq!(decoder.push(&[0xad, 0xff, b'x'], false), "中\u{fffd}x");
        assert_eq!(decoder.push(&[0xe4], true), "\u{fffd}");
        assert!(decoder.pending.is_empty());
    }
}
