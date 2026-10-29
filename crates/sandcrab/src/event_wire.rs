//! Bounded SSE framing shared by native observers; each observer validates its own cursor.
use crate::config::invalid;
use serde_json::Value;
use std::io::{self, BufRead, Read};

pub struct Frame {
    pub id: String,
    pub kind: String,
    pub data: Value,
}

pub fn read_frame(reader: &mut impl BufRead, limit: usize) -> io::Result<Option<Frame>> {
    let (mut id, mut kind, mut data) = (None::<String>, None::<String>, None::<String>);
    let mut total = 0;
    loop {
        let mut bytes = Vec::new();
        let count = (&mut *reader)
            .take((limit + 1 - total) as u64)
            .read_until(b'\n', &mut bytes)?;
        total += count;
        if total > limit {
            return Err(invalid("Event frame exceeds its byte bound"));
        }
        if count == 0 {
            return if total == 0 {
                Ok(None)
            } else {
                Err(io::ErrorKind::UnexpectedEof.into())
            };
        }
        if bytes.last() != Some(&b'\n') {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
        if bytes.is_empty() {
            if id.is_none() && kind.is_none() && data.is_none() {
                total = 0;
                continue;
            }
            return Ok(Some(Frame {
                id: id.ok_or_else(|| invalid("Missing event cursor"))?,
                kind: kind.ok_or_else(|| invalid("Missing event kind"))?,
                data: sandcrab_core::parse(
                    data.ok_or_else(|| invalid("Missing event data"))?
                        .as_bytes(),
                )
                .map_err(invalid)?,
            }));
        }
        if bytes[0] == b':' {
            continue;
        }
        let line = std::str::from_utf8(&bytes).map_err(|_| invalid("Invalid event encoding"))?;
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("Invalid event field"))?;
        let value = value.strip_prefix(' ').unwrap_or(value);
        let target = match name {
            "id" => &mut id,
            "event" => &mut kind,
            "data" => &mut data,
            _ => return Err(invalid("Unknown event field")),
        };
        if target.replace(value.to_owned()).is_some() {
            return Err(invalid("Duplicate event field"));
        }
    }
}
