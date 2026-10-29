//! Host-call observation and explicit replies. This client never runs a business handler.
use crate::{
    call_events::Cursor,
    client::{self, Endpoint},
    config::invalid,
    event_wire,
    host_calls::{self, FRAME},
    transport::Stream,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    io::{self, BufReader, Read, Write},
    time::{Duration, Instant},
};

struct Source {
    stream: Stream,
    deadline: Instant,
    bytes: usize,
}
impl Read for Source {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            if Instant::now() >= self.deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            match self.stream.read(bytes) {
                Ok(n) => {
                    self.bytes += n;
                    if self.bytes > 16 * 1024 * 1024 {
                        return Err(invalid("Host-call stream exceeds its bound"));
                    }
                    return Ok(n);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => return Err(error),
            }
        }
    }
}
pub fn events(endpoint: &Endpoint, id: &str, after: Option<&str>) -> io::Result<i32> {
    let mut cursor = after
        .map(|s| Cursor::parse(s).ok_or_else(|| invalid("Invalid host-call cursor")))
        .transpose()?;
    let mut stream = client::connect(endpoint)?;
    write!(
        stream,
        "GET /v1/runs/{id}/calls/events HTTP/1.1\r\nContent-Length: 0\r\nConnection: close\r\n"
    )?;
    endpoint.headers(&mut stream)?;
    if let Some(cursor) = &cursor {
        write!(stream, "Last-Event-ID: {}\r\n", cursor.text())?;
    }
    stream.write_all(b"\r\n")?;
    stream.set_read_timeout(Some(Duration::from_millis(200)))?;
    let mut source = Source {
        stream,
        deadline: Instant::now() + crate::events::TIMEOUT,
        bytes: 0,
    };
    let result = (|| {
        let (head, body) = sandcrab_core::http::event_response(&mut source)
            .map_err(|_| invalid("Invalid host-call response"))?;
        if head.status != 200 {
            return Err(invalid(format!(
                "Host-call observation refused: HTTP {}",
                head.status
            )));
        }
        let mut input = BufReader::new(body);
        let mut initial = true;
        while let Some(frame) = event_wire::read_frame(&mut input, FRAME)? {
            let next =
                Cursor::parse(&frame.id).ok_or_else(|| invalid("Invalid host-call cursor"))?;
            if cursor.as_ref().is_some_and(|old| {
                old.incarnation != next.incarnation || next.sequence < old.sequence
            }) {
                return Err(invalid("Host-call cursor changed or moved backwards"));
            }
            if initial {
                if frame.kind != "state"
                    || frame.data["runId"] != id
                    || next.sequence != cursor.as_ref().map_or(0, |c| c.sequence)
                {
                    return Err(invalid("Invalid host-call initial state"));
                }
                initial = false;
            } else {
                match frame.kind.as_str() {
                    "call" => {
                        if cursor
                            .as_ref()
                            .is_some_and(|old| next.sequence <= old.sequence)
                            || frame.data["sequence"].as_u64() != Some(next.sequence as u64)
                            || !frame.data["id"].as_str().is_some_and(sandcrab_core::uuid)
                            || !frame.data["requestId"]
                                .as_str()
                                .is_some_and(sandcrab_core::uuid)
                        {
                            return Err(invalid("Invalid host-call request identity"));
                        }
                        let bytes = host_calls::decode(&frame.data["base64"]).map_err(invalid)?;
                        if frame.data["requestSha256"] != format!("{:x}", Sha256::digest(bytes)) {
                            return Err(invalid("Invalid host-call request digest"));
                        }
                    }
                    "result" => {
                        if frame.data["run"]["id"] != id
                            || frame.data["calls"]["closed"] != true
                            || !frame.data["run"]["state"].as_str().is_some_and(|s| {
                                [
                                    "succeeded",
                                    "failed",
                                    "cancelled",
                                    "timed_out",
                                    "output_limit",
                                    "resource_limit",
                                ]
                                .contains(&s)
                            })
                        {
                            return Err(invalid("Invalid host-call final state"));
                        }
                    }
                    "error" => {
                        return Err(invalid(
                            "Host-call observation ended without confirmed completion",
                        ));
                    }
                    _ => return Err(invalid("Unknown host-call event")),
                }
            }
            let mut stdout = io::stdout().lock();
            serde_json::to_writer(
                &mut stdout,
                &json!({"event":frame.kind,"id":frame.id,"data":frame.data}),
            )?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
            cursor = Some(next);
            if frame.kind == "result" {
                return Ok(0);
            }
        }
        Err(invalid("Host-call stream ended before its final state"))
    })();
    result.map_err(|error|invalid(format!("{error}; lastEventId={}. Inspect unresolved call IDs before repeating any outside action",
        cursor.as_ref().map(Cursor::text).unwrap_or_else(||"none".into()))))
}
