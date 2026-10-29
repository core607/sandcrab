//! Explicit observation of unresolved host calls. Delivery is not acknowledgement of a business effect.
use crate::{
    events::{self, Output},
    host_calls::{COUNT, Calls, FRAME},
    service::{Service, error},
    transport::Stream,
};
use sandcrab_core::http;
use serde_json::{Value, json};
use std::{
    io,
    sync::{Arc, atomic::Ordering},
    thread,
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct Cursor {
    pub incarnation: String,
    pub sequence: usize,
}
impl Cursor {
    pub fn parse(value: &str) -> Option<Self> {
        let (incarnation, number) = value.split_once(':')?;
        if !sandcrab_core::uuid(incarnation)
            || number.is_empty()
            || number.len() > 2
            || !number.bytes().all(|b| b.is_ascii_digit())
            || (number.len() > 1 && number.starts_with('0'))
        {
            return None;
        }
        let sequence = number.parse::<usize>().ok().filter(|n| *n <= COUNT)?;
        Some(Self {
            incarnation: incarnation.into(),
            sequence,
        })
    }
    pub fn text(&self) -> String {
        format!("{}:{}", self.incarnation, self.sequence)
    }
}
pub struct Subscription {
    service: Arc<Service>,
    id: String,
    calls: Arc<Calls>,
    cursor: Cursor,
    _admission: events::Admission,
}
pub fn subscribe(
    service: &Arc<Service>,
    id: &str,
    after: Option<&str>,
) -> Result<Subscription, (u16, Value)> {
    if service.stopped.load(Ordering::SeqCst) {
        return Err(error(503, "STOPPING"));
    }
    let (calls, incarnation) = service.calls(id)?;
    let cursor = match after {
        Some(value) => Cursor::parse(value).ok_or_else(|| error(400, "INVALID_CALL_CURSOR"))?,
        None => Cursor {
            incarnation: incarnation.clone(),
            sequence: 0,
        },
    };
    if cursor.incarnation != incarnation || cursor.sequence > calls.length() {
        return Err(error(409, "CALL_CURSOR_MISMATCH"));
    }
    Ok(Subscription {
        service: service.clone(),
        id: id.into(),
        calls,
        cursor,
        _admission: events::admit(service)?,
    })
}
impl Subscription {
    fn frame(&self, stream: &Stream, kind: &str, value: &Value) -> io::Result<()> {
        let bytes = format!(
            "id: {}\nevent: {kind}\ndata: {}\n\n",
            self.cursor.text(),
            serde_json::to_string(value)?
        );
        if bytes.len() > FRAME {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut output = Output {
            stream,
            deadline: Instant::now() + Duration::from_secs(5),
        };
        for block in bytes.as_bytes().chunks(65536) {
            http::chunk(&mut output, block)?;
        }
        Ok(())
    }
    pub fn write(mut self, stream: &Stream, close: bool) -> io::Result<()> {
        http::event_head(
            &mut Output {
                stream,
                deadline: Instant::now() + Duration::from_secs(5),
            },
            close,
        )?;
        self.frame(
            stream,
            "state",
            &json!({"runId":self.id,"calls":self.calls.list()}),
        )?;
        let deadline = Instant::now() + events::TIMEOUT;
        let mut heartbeat = Instant::now() + Duration::from_secs(1);
        loop {
            let next = (|| {
                if self.service.stopped.load(Ordering::SeqCst) {
                    return Err("STOPPING");
                }
                if Instant::now() >= deadline {
                    return Err("OBSERVATION_TIMEOUT");
                }
                let registry = self.service.registry.lock().unwrap();
                let run = registry.runs.get(&self.id).ok_or("RUN_NOT_FOUND")?;
                if run.stream_id != self.cursor.incarnation {
                    return Err("CALL_CURSOR_MISMATCH");
                }
                if run.state == "closing" {
                    return Err("CONTAINMENT_UNCONFIRMED");
                }
                if let Some(call) = self.calls.next(&mut self.cursor.sequence) {
                    return Ok(Some(("call", call, false)));
                }
                if run.terminal() {
                    return Ok(Some((
                        "result",
                        json!({"run":run.summary(),"calls":self.calls.list()}),
                        true,
                    )));
                }
                Ok(None)
            })();
            match next {
                Ok(Some((kind, value, terminal))) => {
                    self.frame(stream, kind, &value)?;
                    if terminal {
                        break;
                    }
                    heartbeat = Instant::now() + Duration::from_secs(1);
                }
                Err(code) => {
                    self.frame(stream, "error", &json!({"code":code}))?;
                    break;
                }
                Ok(None) => {
                    if Instant::now() >= heartbeat {
                        http::chunk(
                            &mut Output {
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
        http::end_chunks(&mut Output {
            stream,
            deadline: Instant::now() + Duration::from_secs(5),
        })
    }
}
