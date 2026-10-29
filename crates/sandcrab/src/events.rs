//! Bounded observers of retained command bytes. Connections own no command lifetime.
use crate::{
    service::{Run, Service, error},
    transport::Stream,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use sandcrab_core::http;
use serde_json::{Value, json};
use std::{
    io::{self, Write},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

pub const BLOCK: usize = 4096;
pub const FRAME: usize = 16384;
pub const TIMEOUT: Duration = Duration::from_secs(350);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub incarnation: String,
    pub offsets: [usize; 2],
}
impl Cursor {
    pub fn parse(value: &str) -> Option<Self> {
        if value.len() > 64 {
            return None;
        }
        let parts: Vec<_> = value.split(':').collect();
        let [incarnation, stdout, stderr] = parts.as_slice() else {
            return None;
        };
        let number = |value: &str| {
            if value.is_empty()
                || !value.bytes().all(|b| b.is_ascii_digit())
                || (value.len() > 1 && value.starts_with('0'))
            {
                None
            } else {
                value
                    .parse::<usize>()
                    .ok()
                    .filter(|v| *v <= crate::config::MAX_OUTPUT)
            }
        };
        sandcrab_core::uuid(incarnation).then_some(())?;
        let offsets = [number(stdout)?, number(stderr)?];
        (offsets.iter().sum::<usize>() <= crate::config::MAX_OUTPUT).then_some(Self {
            incarnation: (*incarnation).into(),
            offsets,
        })
    }
    pub fn text(&self) -> String {
        format!(
            "{}:{}:{}",
            self.incarnation, self.offsets[0], self.offsets[1]
        )
    }
    fn matches(&self, run: &Run) -> bool {
        self.incarnation == run.stream_id && (0..2).all(|i| self.offsets[i] <= run.output[i].len())
    }
}

struct Admission(Arc<AtomicUsize>);
impl Drop for Admission {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct Subscription {
    service: Arc<Service>,
    id: String,
    cursor: Cursor,
    initial: Value,
    next_stream: usize,
    _admission: Admission,
}
pub fn subscribe(
    service: &Arc<Service>,
    id: &str,
    after: Option<&str>,
) -> Result<Subscription, (u16, Value)> {
    if service.stopped.load(Ordering::SeqCst) {
        return Err(error(503, "STOPPING"));
    }
    let (cursor, initial) = {
        let registry = service.registry.lock().unwrap();
        let run = registry
            .runs
            .get(id)
            .ok_or_else(|| error(404, "RUN_NOT_FOUND"))?;
        let cursor = match after {
            Some(value) => {
                Cursor::parse(value).ok_or_else(|| error(400, "INVALID_EVENT_CURSOR"))?
            }
            None => Cursor {
                incarnation: run.stream_id.clone(),
                offsets: [0, 0],
            },
        };
        if !cursor.matches(run) {
            return Err(error(409, "EVENT_CURSOR_MISMATCH"));
        }
        (cursor, run.summary())
    };
    let count = service.event_count.clone();
    if count
        .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            (n < service.runtime.config.service.max_event_streams).then_some(n + 1)
        })
        .is_err()
    {
        return Err(error(429, "EVENT_CAPACITY"));
    }
    Ok(Subscription {
        service: service.clone(),
        id: id.into(),
        cursor,
        initial,
        next_stream: 0,
        _admission: Admission(count),
    })
}

struct Frame {
    kind: &'static str,
    value: Value,
    small: bool,
    terminal: bool,
}
fn next(
    run: &Run,
    cursor: &mut Cursor,
    stream: &mut usize,
    flush: bool,
) -> Result<Option<Frame>, &'static str> {
    if !cursor.matches(run) {
        return Err("EVENT_CURSOR_MISMATCH");
    }
    for index in [*stream, 1 - *stream] {
        let available = run.output[index].len() - cursor.offsets[index];
        if available == 0 || (available < BLOCK && !flush && run.state == "running") {
            continue;
        }
        let start = cursor.offsets[index];
        let count = available.min(BLOCK);
        cursor.offsets[index] += count;
        *stream = 1 - index;
        return Ok(Some(Frame {
            kind: if index == 0 { "stdout" } else { "stderr" },
            value: json!({"offset":start,"base64":STANDARD.encode(&run.output[index][start..start+count])}),
            small: count < BLOCK,
            terminal: false,
        }));
    }
    if (0..2).any(|i| cursor.offsets[i] != run.output[i].len()) || run.state == "running" {
        return Ok(None);
    }
    if run.state == "closing" {
        return Err("CONTAINMENT_UNCONFIRMED");
    }
    let mut result = run.summary();
    result["stdoutBytes"] = run.output[0].len().into();
    result["stderrBytes"] = run.output[1].len().into();
    Ok(Some(Frame {
        kind: "result",
        value: result,
        small: false,
        terminal: true,
    }))
}

// A five-second deadline covers a whole frame, not each successive byte. A slow reader
// releases only its observer; the command still has its original limits and owner.
struct Output<'a> {
    stream: &'a Stream,
    deadline: Instant,
}
impl Write for Output<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(io::ErrorKind::TimedOut)?;
        self.stream.set_write_timeout(Some(remaining))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
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
        http::chunk(
            &mut Output {
                stream,
                deadline: Instant::now() + Duration::from_secs(5),
            },
            bytes.as_bytes(),
        )
    }
    pub fn write(mut self, stream: &Stream, close: bool) -> io::Result<()> {
        http::event_head(
            &mut Output {
                stream,
                deadline: Instant::now() + Duration::from_secs(5),
            },
            close,
        )?;
        self.frame(stream, "state", &self.initial)?;
        let deadline = Instant::now() + TIMEOUT;
        let mut next_flush = Instant::now();
        let mut heartbeat = Instant::now() + Duration::from_secs(1);
        loop {
            let frame = if self.service.stopped.load(Ordering::SeqCst) {
                Err("STOPPING")
            } else if Instant::now() >= deadline {
                Err("OBSERVATION_TIMEOUT")
            } else {
                let registry = self.service.registry.lock().unwrap();
                registry
                    .runs
                    .get(&self.id)
                    .ok_or("RUN_NOT_FOUND")
                    .and_then(|run| {
                        next(
                            run,
                            &mut self.cursor,
                            &mut self.next_stream,
                            Instant::now() >= next_flush,
                        )
                    })
            };
            match frame {
                Ok(Some(frame)) => {
                    self.frame(stream, frame.kind, &frame.value)?;
                    if frame.terminal {
                        break;
                    }
                    if frame.small {
                        next_flush = Instant::now() + Duration::from_millis(25);
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
                    thread::sleep(Duration::from_millis(5));
                }
            }
        }
        http::end_chunks(&mut Output {
            stream,
            deadline: Instant::now() + Duration::from_secs(5),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn run() -> Run {
        Run::new(json!({"id":"11111111-1111-1111-1111-111111111111","serverId":"22222222-2222-2222-2222-222222222222"}),
                 "python".into(), Arc::new(AtomicBool::new(false)), 8192).unwrap()
    }
    #[test]
    fn cursor_binds_incarnation_and_both_byte_offsets() {
        let mut run = run();
        run.output = [b"hello".to_vec(), vec![0xff, 0]];
        let mut cursor = Cursor {
            incarnation: run.stream_id.clone(),
            offsets: [0, 0],
        };
        let mut stream = 0;
        let first = next(&run, &mut cursor, &mut stream, true).unwrap().unwrap();
        assert_eq!(first.kind, "stdout");
        assert_eq!(first.value, json!({"offset":0,"base64":"aGVsbG8="}));
        let mut resumed = Cursor::parse(&cursor.text()).unwrap();
        let second = next(&run, &mut resumed, &mut stream, true)
            .unwrap()
            .unwrap();
        assert_eq!(second.kind, "stderr");
        assert_eq!(
            STANDARD
                .decode(second.value["base64"].as_str().unwrap())
                .unwrap(),
            [0xff, 0]
        );
        assert!(
            next(&run, &mut resumed, &mut stream, true)
                .unwrap()
                .is_none()
        );
        run.state = "succeeded".into();
        run.result = Some(json!({"exitCode":0,"truncated":false}));
        assert_eq!(
            next(&run, &mut resumed, &mut stream, true)
                .unwrap()
                .unwrap()
                .kind,
            "result"
        );
        assert_eq!(run.value()["result"]["stdout"], "hello");
        assert!(run.summary()["result"].get("stdout").is_none());
        run.stream_id = sandcrab_core::new_uuid().unwrap();
        assert!(!resumed.matches(&run));
        assert!(Cursor::parse(&format!("{}:00:0", run.stream_id)).is_none());
        assert!(
            !Cursor {
                incarnation: run.stream_id.clone(),
                offsets: [6, 0]
            }
            .matches(&run)
        );
    }
    #[test]
    fn partial_blocks_coalesce_but_terminal_and_full_blocks_do_not_wait() {
        let mut run = run();
        let mut cursor = Cursor {
            incarnation: run.stream_id.clone(),
            offsets: [0, 0],
        };
        let mut stream = 0;
        run.output[0].extend_from_slice(b"a");
        assert!(
            next(&run, &mut cursor, &mut stream, false)
                .unwrap()
                .is_none()
        );
        run.output[0].resize(BLOCK, b'a');
        assert_eq!(
            next(&run, &mut cursor, &mut stream, false)
                .unwrap()
                .unwrap()
                .value["offset"],
            0
        );
        run.output[0].push(b'b');
        run.state = "closing".into();
        assert_eq!(
            next(&run, &mut cursor, &mut stream, false)
                .unwrap()
                .unwrap()
                .kind,
            "stdout"
        );
        assert_eq!(
            next(&run, &mut cursor, &mut stream, false).err(),
            Some("CONTAINMENT_UNCONFIRMED")
        );
    }
}
