//! An observer never resubmits a command. Complete frames carry the cursor for an explicit resume.
use crate::{
    client::{self, Endpoint},
    config::invalid,
    events::{BLOCK, Cursor, FRAME, TIMEOUT},
    transport::Stream,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    io::{self, BufRead, BufReader, Read, Write},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

struct Source<'a> {
    socket: &'a Endpoint,
    stream: Stream,
    id: &'a str,
    stopped: Option<&'a AtomicBool>,
    cancel_sent: bool,
    deadline: Instant,
    bytes: usize,
}
impl Read for Source<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            if Instant::now() >= self.deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            if self.stopped.is_some_and(|flag| flag.load(Ordering::SeqCst)) && !self.cancel_sent {
                // Cancellation uses its own connection; the event response is still being read.
                self.cancel_sent = true;
                client::request(
                    self.socket,
                    "POST",
                    &format!("/v1/runs/{}/cancel", self.id),
                    Some(&json!({})),
                )?;
            }
            match self.stream.read(bytes) {
                Ok(n) => {
                    self.bytes += n;
                    if self.bytes > 32 * 1024 * 1024 {
                        return Err(invalid("Event response exceeds its wire bound"));
                    }
                    return Ok(n);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
        }
    }
}

struct Frame {
    kind: String,
    cursor: Cursor,
    data: Value,
}
fn read_frame(reader: &mut impl BufRead) -> io::Result<Option<Frame>> {
    crate::event_wire::read_frame(reader, FRAME)?
        .map(|frame| {
            Ok(Frame {
                cursor: Cursor::parse(&frame.id).ok_or_else(|| invalid("Invalid event cursor"))?,
                kind: frame.kind,
                data: frame.data,
            })
        })
        .transpose()
}

pub fn observe(
    socket: &Endpoint,
    id: &str,
    after: Option<&str>,
    stopped: Option<&AtomicBool>,
    mut receive: impl FnMut(&str, &str, &Value) -> io::Result<()>,
) -> io::Result<Value> {
    let mut cursor = after
        .map(|v| Cursor::parse(v).ok_or_else(|| invalid("Invalid --after cursor")))
        .transpose()?;
    let mut stream = client::connect(socket)?;
    write!(
        stream,
        "GET /v1/runs/{id}/events HTTP/1.1\r\nContent-Length: 0\r\nConnection: close\r\n"
    )?;
    socket.headers(&mut stream)?;
    if let Some(cursor) = &cursor {
        write!(stream, "Last-Event-ID: {}\r\n", cursor.text())?;
    }
    stream.write_all(b"\r\n")?;
    stream.set_read_timeout(Some(Duration::from_millis(200)))?;
    let mut source = Source {
        socket,
        stream,
        id,
        stopped,
        cancel_sent: false,
        deadline: Instant::now() + TIMEOUT,
        bytes: 0,
    };
    let result = (|| {
        let (head, mut body) = sandcrab_core::http::event_response(&mut source).map_err(invalid)?;
        if !head.chunked {
            let mut bytes = Vec::new();
            body.read_to_end(&mut bytes)?;
            let value = sandcrab_core::parse(&bytes).map_err(invalid)?;
            return Err(invalid(format!(
                "HTTP {}: {}",
                head.status,
                value["error"]["code"]
                    .as_str()
                    .unwrap_or("INVALID_EVENT_RESPONSE")
            )));
        }
        let mut reader = BufReader::new(body);
        let mut server = None;
        while let Some(frame) = read_frame(&mut reader)? {
            if server.is_none() {
                if frame.kind != "state" {
                    return Err(invalid("Output preceded its command state"));
                }
                if frame.data["id"] != id
                    || !frame.data["serverId"]
                        .as_str()
                        .is_some_and(sandcrab_core::uuid)
                {
                    return Err(invalid("Event belongs to a different command"));
                }
                if cursor.as_ref().is_some_and(|c| c != &frame.cursor)
                    || (cursor.is_none() && frame.cursor.offsets != [0, 0])
                {
                    return Err(invalid(
                        "Event cursor does not match the requested position",
                    ));
                }
                server = Some(frame.data["serverId"].clone());
            } else {
                let previous = cursor
                    .as_ref()
                    .ok_or_else(|| invalid("Output preceded its command state"))?;
                if previous.incarnation != frame.cursor.incarnation {
                    return Err(invalid("Event incarnation changed"));
                }
                match frame.kind.as_str() {
                    "stdout" | "stderr" => {
                        let index = usize::from(frame.kind == "stderr");
                        let bytes = decode(&frame.data)?;
                        let mut expected = previous.offsets;
                        expected[index] += bytes.len();
                        if frame.data["offset"].as_u64() != Some(previous.offsets[index] as u64)
                            || frame.cursor.offsets != expected
                            || expected.iter().sum::<usize>() > crate::config::MAX_OUTPUT
                        {
                            return Err(invalid("Event byte offsets do not match its output"));
                        }
                    }
                    "result" => {
                        if frame.cursor != *previous
                            || frame.data["id"] != id
                            || Some(&frame.data["serverId"]) != server.as_ref()
                            || frame.data["stdoutBytes"].as_u64()
                                != Some(previous.offsets[0] as u64)
                            || frame.data["stderrBytes"].as_u64()
                                != Some(previous.offsets[1] as u64)
                            || !frame.data["state"].as_str().is_some_and(|s| {
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
                            return Err(invalid("Invalid terminal event"));
                        }
                    }
                    "error" => {
                        return Err(invalid(
                            frame.data["code"].as_str().unwrap_or("EVENT_FAILED"),
                        ));
                    }
                    _ => return Err(invalid("Unexpected event kind")),
                }
            }
            receive(&frame.kind, &frame.cursor.text(), &frame.data)?;
            cursor = Some(frame.cursor);
            if frame.kind == "result" {
                // The complete result frame acknowledges containment. Losing the HTTP zero
                // chunk afterwards must not turn that outcome into an uncertain command.
                return Ok(frame.data);
            }
        }
        Err(invalid("Event stream ended without a terminal result"))
    })();
    result.map_err(|error| invalid(format!("Run {id} observation failed: {error}. Result retained; lastEventId={}. Observe or inspect this ID; do not rerun the command.",
        cursor.map(|c|c.text()).unwrap_or_else(||"none".into()))))
}

pub fn decode(data: &Value) -> io::Result<Vec<u8>> {
    let encoded = data["base64"]
        .as_str()
        .filter(|v| v.len() <= BLOCK.div_ceil(3) * 4)
        .ok_or_else(|| invalid("Invalid output bytes"))?;
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| invalid("Invalid output encoding"))?;
    if bytes.is_empty() || bytes.len() > BLOCK {
        return Err(invalid("Invalid output block size"));
    }
    Ok(bytes)
}

pub fn events(socket: &Endpoint, id: &str, after: Option<&str>) -> io::Result<i32> {
    observe(socket, id, after, None, |kind, cursor, data| {
        let line = json!({"event":kind,"id":cursor,"data":data});
        let mut output = io::stdout().lock();
        writeln!(output, "{line}")?;
        output.flush()
    })?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_partial_result_or_ambiguous_frame_is_not_acknowledged() {
        let prefix = "id: 11111111-1111-1111-1111-111111111111:0:0\nevent: result\ndata: {}\n";
        assert!(read_frame(&mut prefix.as_bytes()).is_err());
        assert!(read_frame(&mut format!("{prefix}data: {{}}\n\n").as_bytes()).is_err());
        assert!(read_frame(&mut format!("data: {}\n\n", "x".repeat(FRAME)).as_bytes()).is_err());
        assert_eq!(
            read_frame(&mut format!("{prefix}\n").as_bytes())
                .unwrap()
                .unwrap()
                .kind,
            "result"
        );
        assert!(decode(&json!({"base64":""})).is_err());
    }
}
