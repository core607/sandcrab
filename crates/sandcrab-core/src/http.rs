//! Bounded HTTP/1.1 framing. Bodies stream at their declared length; ambiguous
//! framing, chunked messages and upgrades are rejected. Pipelining is unsupported.
use std::{
    collections::BTreeMap,
    io::{self, Cursor, Read, Write},
};

pub const MAX_HEAD: usize = 8192;
const MAX_HEADERS: usize = 32;
const INVALID: &str = "INVALID_HTTP";

pub struct Head {
    pub method: String,
    pub path: String,
    pub length: u64,
    pub close: bool,
    headers: BTreeMap<String, String>,
}
impl Head {
    /// Header names are lower case; duplicate fields are rejected before dispatch.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

/// The source is never read beyond this request's declared length. Truncation is
/// an error, including when the first body bytes arrived with the headers.
pub struct Body<'a, R: Read> {
    source: &'a mut R,
    prefix: Cursor<Vec<u8>>,
    remaining: u64,
}
impl<R: Read> Body<'_, R> {
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
}
impl<R: Read> Read for Body<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let limit = self.remaining.min(buffer.len() as u64) as usize;
        if limit == 0 {
            return Ok(0);
        }
        let read = if self.prefix.position() < (self.prefix.get_ref().len() as u64) {
            self.prefix.read(&mut buffer[..limit])?
        } else {
            self.source.read(&mut buffer[..limit])?
        };
        if read == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.remaining -= read as u64;
        Ok(read)
    }
}

pub struct Request {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}
pub struct ResponseHead {
    pub status: u16,
    pub length: u64,
    pub close: bool,
    headers: BTreeMap<String, String>,
}
impl ResponseHead {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}
struct Envelope {
    line: String,
    headers: BTreeMap<String, String>,
    prefix: Vec<u8>,
}
fn token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Parse only the bounded head, retaining at most one 1 KiB read's body prefix.
/// Callers authenticate first, bound the selected operation's length, and impose
/// socket deadlines. PUT permits an explicitly declared empty file.
fn envelope(source: &mut impl Read) -> Result<Option<Envelope>, &'static str> {
    let mut buffer = Vec::with_capacity(1024);
    let end = loop {
        if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break end;
        }
        if buffer.len() >= MAX_HEAD + 4 {
            return Err(INVALID);
        }
        let mut chunk = [0; 1024];
        let size = source
            .read(&mut chunk[..(MAX_HEAD + 4 - buffer.len()).min(1024)])
            .map_err(|_| INVALID)?;
        if size == 0 {
            return if buffer.is_empty() {
                Ok(None)
            } else {
                Err(INVALID)
            };
        }
        buffer.extend_from_slice(&chunk[..size]);
    };
    if end > MAX_HEAD {
        return Err(INVALID);
    }
    let head = std::str::from_utf8(&buffer[..end]).map_err(|_| INVALID)?;
    let mut lines = head.split("\r\n");
    let line = lines.next().ok_or(INVALID)?.to_owned();
    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(INVALID)?;
        let value = value.trim_matches(|c| c == ' ' || c == '\t');
        if headers.len() >= MAX_HEADERS
            || !token(name)
            || value.bytes().any(|b| b.is_ascii_control())
        {
            return Err(INVALID);
        }
        let name = name.to_ascii_lowercase();
        if ["transfer-encoding", "upgrade"].contains(&name.as_str())
            || headers.insert(name, value.to_owned()).is_some()
        {
            return Err(INVALID);
        }
    }
    Ok(Some(Envelope {
        line,
        headers,
        prefix: buffer[end + 4..].to_vec(),
    }))
}
impl Envelope {
    fn length(&self, implicit_zero: bool) -> Result<u64, &'static str> {
        let length = match self.headers.get("content-length") {
            Some(value) if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => {
                value.parse::<u64>().map_err(|_| INVALID)?
            }
            None if implicit_zero => 0,
            _ => return Err(INVALID),
        };
        if self.prefix.len() as u64 > length {
            return Err(INVALID);
        }
        Ok(length)
    }
    fn close(&self) -> bool {
        self.headers
            .get("connection")
            .is_some_and(|v| v.split(',').any(|s| s.trim().eq_ignore_ascii_case("close")))
    }
}

/// Read one request head. Clean EOF before the first byte returns `None`; an
/// incomplete message is an error. A body must be consumed before reading again.
pub fn start<R: Read>(source: &mut R) -> Result<Option<(Head, Body<'_, R>)>, &'static str> {
    let Some(raw) = envelope(source)? else {
        return Ok(None);
    };
    let parts: Vec<_> = raw.line.split(' ').collect();
    let [method, path, version] = parts.as_slice() else {
        return Err(INVALID);
    };
    if !["GET", "POST", "PUT", "DELETE"].contains(method)
        || !path.starts_with('/')
        || !path.bytes().all(|b| b.is_ascii_graphic())
        || *version != "HTTP/1.1"
    {
        return Err(INVALID);
    }
    let length = raw.length(["GET", "DELETE"].contains(method))?;
    if *method == "GET" && length != 0 {
        return Err(INVALID);
    }
    let head = Head {
        method: (*method).into(),
        path: (*path).into(),
        length,
        close: raw.close(),
        headers: raw.headers,
    };
    Ok(Some((
        head,
        Body {
            source,
            prefix: Cursor::new(raw.prefix),
            remaining: length,
        },
    )))
}

/// Fixed-length response framing for native clients. No EOF-delimited body or
/// informational response is accepted; a lost response never authorizes replay.
pub fn response<R: Read>(source: &mut R) -> Result<(ResponseHead, Body<'_, R>), &'static str> {
    let raw = envelope(source)?.ok_or(INVALID)?;
    let mut parts = raw.line.splitn(3, ' ');
    if parts.next() != Some("HTTP/1.1") {
        return Err(INVALID);
    }
    let status = parts
        .next()
        .filter(|s| s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|s| (200..600).contains(s))
        .ok_or(INVALID)?;
    if parts
        .next()
        .is_none_or(|s| s.bytes().any(|b| b.is_ascii_control()))
    {
        return Err(INVALID);
    }
    let length = raw.length(false)?;
    if status == 204 && length != 0 {
        return Err(INVALID);
    }
    let head = ResponseHead {
        status,
        length,
        close: raw.close(),
        headers: raw.headers,
    };
    Ok((
        head,
        Body {
            source,
            prefix: Cursor::new(raw.prefix),
            remaining: length,
        },
    ))
}

/// Buffered JSON/control entrance. Only a bodiless GET or a nonempty POST is valid.
/// Streaming entrances use `start` and validate their own method and body limits.
pub fn read(stream: &mut impl Read, max_body: usize) -> Result<Request, &'static str> {
    let (head, mut body) = start(stream)?.ok_or(INVALID)?;
    if !["GET", "POST"].contains(&head.method.as_str())
        || head.header("expect").is_some()
        || head.length > max_body as u64
        || (head.method == "POST") != (head.length > 0)
    {
        return Err(INVALID);
    }
    let mut bytes = Vec::with_capacity(head.length as usize);
    body.read_to_end(&mut bytes).map_err(|_| INVALID)?;
    Ok(Request {
        method: head.method,
        path: head.path,
        body: bytes,
    })
}

/// Write a complete JSON response and announce that the connection closes.
pub fn write(stream: &mut impl Write, status: u16, body: &[u8]) -> io::Result<()> {
    respond(stream, status, "application/json", body, true)
}

pub fn respond(
    stream: &mut impl Write,
    status: u16,
    content_type: &str,
    body: &[u8],
    close: bool,
) -> io::Result<()> {
    response_head(stream, status, content_type, body.len() as u64, close)?;
    stream.write_all(body)?;
    stream.flush()
}

/// Write the status line and headers of a response whose `length` body bytes follow.
pub fn write_head(
    stream: &mut impl Write,
    status: u16,
    content_type: &str,
    length: u64,
) -> io::Result<()> {
    response_head(stream, status, content_type, length, true)
}

/// A response with a fixed length. A reusable connection can be retained only after
/// both sides have consumed the complete request and response bodies.
pub fn response_head(
    stream: &mut impl Write,
    status: u16,
    content_type: &str,
    length: u64,
    close: bool,
) -> io::Result<()> {
    response_head_with(stream, status, content_type, length, close, &[])
}

pub fn response_head_with(
    stream: &mut impl Write,
    status: u16,
    content_type: &str,
    length: u64,
    close: bool,
    extra: &[(&str, &str)],
) -> io::Result<()> {
    if content_type.bytes().any(|b| b.is_ascii_control()) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let reason = match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let connection = if close { "close" } else { "keep-alive" };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {length}\r\nConnection: {connection}\r\n"
    );
    let mut names = BTreeMap::new();
    if extra.len() > MAX_HEADERS - 3 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    for (key, value) in extra {
        if head.len() + key.len() + value.len() + 6 > MAX_HEAD {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let normalized = key.to_ascii_lowercase();
        if !token(key)
            || [
                "connection",
                "content-length",
                "content-type",
                "transfer-encoding",
            ]
            .contains(&normalized.as_str())
            || value.bytes().any(|b| b.is_ascii_control())
            || names.insert(normalized, ()).is_some()
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        head.push_str(&format!("{key}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(raw: &[u8]) -> Result<Request, &'static str> {
        read(&mut &raw[..], 64)
    }
    #[test]
    fn a_declared_body_and_a_bodiless_get_are_read() {
        let request =
            parse(b"POST /v1/requests HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}")
                .ok()
                .unwrap();
        assert_eq!(
            (request.method.as_str(), request.path.as_str()),
            ("POST", "/v1/requests")
        );
        assert_eq!(request.body, b"{}");
        let hello = parse(b"GET /v1/hello HTTP/1.1\r\ncontent-length: 0\r\n\r\n")
            .ok()
            .unwrap();
        assert!(hello.body.is_empty());
    }
    #[test]
    fn malformed_unbounded_or_unsupported_requests_are_refused() {
        let long_header = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD));
        let many_headers = format!(
            "GET / HTTP/1.1\r\n{}\r\n",
            "X: a\r\n".repeat(MAX_HEADERS + 1)
        );
        for raw in [
            &b"POST /v1/requests HTTP/1.1\r\nContent-Length: 65\r\n\r\n"[..],
            b"POST /v1/requests HTTP/1.1\r\n\r\n",
            b"POST /v1/requests HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            b"POST /v1/requests HTTP/1.1\r\nContent-Length: +2\r\n\r\n{}",
            b"POST /v1/requests HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
            b"POST /v1/requests HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}GET",
            b"POST /v1/requests HTTP/1.1\r\nContent-Length: 4\r\n\r\n{}",
            b"GET /v1/hello HTTP/1.1\r\nContent-Length: 1\r\n\r\nx",
            b"GET /v1/hello HTTP/1.0\r\n\r\n",
            b"DELETE /v1/hello HTTP/1.1\r\n\r\n",
            b"GET v1/hello HTTP/1.1\r\n\r\n",
            b"GET /v1/hello HTTP/1.1\r\nNo colon\r\n\r\n",
            b"GET /v1/hello HTTP/1.1\r\nBad Name: a\r\n\r\n",
            b"GET /v1/hello HTTP/1.1\r\n",
            b"",
            long_header.as_bytes(),
            many_headers.as_bytes(),
        ] {
            assert_eq!(
                parse(raw).err(),
                Some("INVALID_HTTP"),
                "{}",
                String::from_utf8_lossy(raw)
            );
        }
    }
    #[test]
    fn responses_declare_their_length_and_close() {
        let mut output = Vec::new();
        write(&mut output, 404, br#"{"ok":false}"#).unwrap();
        assert_eq!(
            output,
            b"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: 12\r\nConnection: close\r\n\r\n{\"ok\":false}"
        );
    }
    #[test]
    fn distinct_header_count_and_expectations_have_separate_bounds() {
        for count in [32, 33] {
            let fields = (0..count)
                .map(|i| format!("X-{i}: value\r\n"))
                .collect::<String>();
            let message = format!("GET / HTTP/1.1\r\n{fields}\r\n");
            assert_eq!(parse(message.as_bytes()).is_ok(), count == 32);
        }
        let bytes = b"POST / HTTP/1.1\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n{}";
        assert!(parse(bytes).is_err());
        let mut source = &bytes[..];
        assert_eq!(
            start(&mut source).unwrap().unwrap().0.header("expect"),
            Some("100-continue")
        );
    }
    #[test]
    fn extra_response_headers_are_read_back_without_changing_framing() {
        let mut bytes = Vec::new();
        response_head_with(
            &mut bytes,
            200,
            "application/octet-stream",
            0,
            true,
            &[("ETag", "\"abc\"")],
        )
        .unwrap();
        let mut source = bytes.as_slice();
        let (head, _) = response(&mut source).unwrap();
        assert_eq!(head.header("etag"), Some("\"abc\""));
        assert_eq!(head.length, 0);
        for extra in [[("Content-Length", "3")], [("ETag", "x\r\nInjected: y")]] {
            let mut bytes = Vec::new();
            assert!(
                response_head_with(&mut bytes, 200, "application/octet-stream", 0, true, &extra)
                    .is_err()
            );
            assert!(bytes.is_empty());
        }
    }
    #[test]
    fn a_large_declared_upload_does_not_read_or_allocate_its_body() {
        let mut input=&b"PUT /content HTTP/1.1\r\nContent-Length: 1073741824\r\nContent-Type: application/octet-stream\r\n\r\nabc"[..];
        let (head, mut body) = start(&mut input).unwrap().unwrap();
        assert_eq!(head.length, 1_073_741_824);
        assert_eq!(
            head.header("content-type"),
            Some("application/octet-stream")
        );
        assert!(body.prefix.get_ref().len() <= 1024);
        let mut bytes = [0; 3];
        body.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"abc");
        assert_eq!(body.remaining(), 1_073_741_821);
        assert_eq!(
            body.read(&mut bytes).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
    #[test]
    fn body_ends_at_its_boundary_and_headers_may_be_split_byte_by_byte() {
        struct Slow<'a>(&'a [u8]);
        impl Read for Slow<'_> {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                if self.0.is_empty() || output.is_empty() {
                    return Ok(0);
                }
                output[0] = self.0[0];
                self.0 = &self.0[1..];
                Ok(1)
            }
        }
        let padding = "a".repeat(MAX_HEAD - "PUT / HTTP/1.1\r\nContent-Length: 3\r\nX: ".len());
        let bytes = format!(
            "PUT / HTTP/1.1\r\nContent-Length: 3\r\nX: {padding}\r\n\r\nabcGET / HTTP/1.1\r\n\r\n"
        );
        let mut source = Slow(bytes.as_bytes());
        let (head, mut body) = start(&mut source).unwrap().unwrap();
        assert!(!head.close);
        let mut result = Vec::new();
        body.read_to_end(&mut result).unwrap();
        assert_eq!(result, b"abc");
        assert_eq!(body.remaining(), 0);
        drop(body);
        assert_eq!(start(&mut source).unwrap().unwrap().0.method, "GET");
        assert!(start(&mut source).unwrap().is_none());
    }
    #[test]
    fn empty_put_is_explicit_and_ambiguous_framing_is_rejected() {
        let mut source =
            &b"PUT / HTTP/1.1\r\nContent-Length: 0\r\nConnection: keep-alive, close\r\n\r\n"[..];
        let (head, mut body) = start(&mut source).unwrap().unwrap();
        assert!(head.close);
        assert_eq!(body.read(&mut [0; 1]).unwrap(), 0);
        for raw in [
            &b"PUT / HTTP/1.1\r\n\r\n"[..],
            b"PUT / HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
            b"PUT / HTTP/1.1\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"PUT / HTTP/1.1\r\nContent-Length: 0\r\nX: a\r\nx: b\r\n\r\n",
        ] {
            assert!(start(&mut &raw[..]).is_err());
        }
    }
    #[test]
    fn fixed_response_body_finishes_without_waiting_for_eof() {
        struct Open;
        impl Read for Open {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("response body read past Content-Length")
            }
        }
        let header = Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec());
        let mut input = header.chain(Open);
        let (head, mut body) = response(&mut input).unwrap();
        assert_eq!(head.status, 200);
        assert!(!head.close);
        let mut result = Vec::new();
        body.read_to_end(&mut result).unwrap();
        assert_eq!(result, b"{}");
    }
    #[test]
    fn responses_reject_ambiguous_lengths_and_detect_truncation() {
        for raw in [
            &b"HTTP/1.1 200 OK\r\n\r\n{}"[..],
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\ncontent-length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n{}",
            b"HTTP/1.1 204 No Content\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 101 Switching Protocols\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n",
        ] {
            assert!(response(&mut &raw[..]).is_err());
        }
        let mut input = &b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\n{}"[..];
        let (head, mut body) = response(&mut input).unwrap();
        assert!(head.close);
        assert_eq!(
            body.read_to_end(&mut Vec::new()).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
