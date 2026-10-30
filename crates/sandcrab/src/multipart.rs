//! Streaming multipart framing. Header filenames never select filesystem paths.
use crate::config::invalid;
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
};

pub fn boundary(value: &str) -> io::Result<String> {
    let parts = value.split(';').map(str::trim).collect::<Vec<_>>();
    if parts.len() != 2 || !parts[0].eq_ignore_ascii_case("multipart/form-data") {
        return Err(invalid("INVALID_MULTIPART"));
    }
    let (name, value) = parts[1]
        .split_once('=')
        .ok_or_else(|| invalid("INVALID_MULTIPART"))?;
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value);
    if name != "boundary" || !valid_boundary(value) {
        return Err(invalid("INVALID_MULTIPART"));
    }
    Ok(value.into())
}
fn valid_boundary(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 70
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"'()+_,-./:=?".contains(&b))
}
fn disposition(value: &str) -> io::Result<Vec<&str>> {
    let (mut quoted, mut escaped, mut start) = (false, false, 0);
    let mut parts = Vec::new();
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if quoted && character == '\\' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if character == ';' && !quoted {
            parts.push(value[start..index].trim());
            start = index + 1;
        }
    }
    if quoted || escaped {
        return Err(invalid("INVALID_MULTIPART"));
    }
    parts.push(value[start..].trim());
    Ok(parts)
}
pub struct Multipart<R> {
    source: R,
    buffer: Vec<u8>,
    marker: Vec<u8>,
    read: u64,
    limit: u64,
    closed: bool,
}
impl<R: Read> Multipart<R> {
    pub fn new(source: R, boundary: &str, limit: u64) -> io::Result<Self> {
        if !valid_boundary(boundary) {
            return Err(invalid("INVALID_MULTIPART"));
        }
        let mut reader = Self {
            source,
            buffer: Vec::new(),
            marker: format!("\r\n--{boundary}").into_bytes(),
            read: 0,
            limit,
            closed: false,
        };
        if reader.line()? != format!("--{boundary}").as_bytes() {
            return Err(invalid("INVALID_MULTIPART"));
        }
        Ok(reader)
    }
    fn fill(&mut self) -> io::Result<()> {
        let mut bytes = [0; 32768];
        let length = bytes
            .len()
            .min(self.limit.saturating_sub(self.read).saturating_add(1) as usize);
        let count = self.source.read(&mut bytes[..length])?;
        self.read += count as u64;
        if self.read > self.limit {
            return Err(invalid("FILE_LIMIT"));
        }
        if count == 0 {
            return Err(invalid("CONTENT_INCOMPLETE"));
        }
        self.buffer.extend_from_slice(&bytes[..count]);
        Ok(())
    }
    fn line(&mut self) -> io::Result<Vec<u8>> {
        loop {
            if let Some(end) = self.buffer.windows(2).position(|s| s == b"\r\n") {
                if end > 4096 {
                    return Err(invalid("INVALID_MULTIPART"));
                }
                let value = self.buffer[..end].to_vec();
                self.buffer.drain(..end + 2);
                return Ok(value);
            }
            if self.buffer.len() > 4096 {
                return Err(invalid("INVALID_MULTIPART"));
            }
            self.fill()?;
        }
    }
    pub fn header(&mut self, expected: &str) -> io::Result<()> {
        if self.closed {
            return Err(invalid("INVALID_MULTIPART"));
        }
        let mut headers = BTreeMap::new();
        let mut size = 0;
        loop {
            let line = self.line()?;
            size += line.len() + 2;
            if size > 8192 {
                return Err(invalid("INVALID_MULTIPART"));
            }
            if line.is_empty() {
                break;
            }
            let line = std::str::from_utf8(&line).map_err(|_| invalid("INVALID_MULTIPART"))?;
            let (key, value) = line
                .split_once(':')
                .ok_or_else(|| invalid("INVALID_MULTIPART"))?;
            let key = key.to_ascii_lowercase();
            if !["content-disposition", "content-type", "content-length"].contains(&key.as_str())
                || value.bytes().any(|c| c.is_ascii_control())
                || headers.insert(key, value.trim().to_owned()).is_some()
            {
                return Err(invalid("INVALID_MULTIPART"));
            }
        }
        let disposition = headers
            .get("content-disposition")
            .ok_or_else(|| invalid("INVALID_MULTIPART"))?;
        let parameters = self::disposition(disposition)?;
        let names = parameters
            .iter()
            .filter_map(|s| s.strip_prefix("name="))
            .collect::<Vec<_>>();
        if parameters[0] != "form-data" || names != [format!("\"{expected}\"").as_str()] {
            return Err(invalid("INVALID_MULTIPART"));
        }
        Ok(())
    }
    pub fn part(&mut self, output: &mut impl Write, limit: u64) -> io::Result<u64> {
        let mut written = 0u64;
        loop {
            let mut found = None;
            for start in 0..self.buffer.len().saturating_sub(self.marker.len() + 3) {
                let end = start + self.marker.len();
                if self.buffer[start..end] == self.marker
                    && (&self.buffer[end..end + 2] == b"\r\n"
                        || &self.buffer[end..end + 4] == b"--\r\n")
                {
                    found = Some((start, end));
                    break;
                }
            }
            let count = found.map_or_else(
                || self.buffer.len().saturating_sub(self.marker.len() + 4),
                |(n, _)| n,
            );
            written += count as u64;
            if written > limit {
                return Err(invalid("FILE_LIMIT"));
            }
            output.write_all(&self.buffer[..count])?;
            if let Some((_, end)) = found {
                self.closed = &self.buffer[end..end + 2] == b"--";
                self.buffer.drain(..end + if self.closed { 4 } else { 2 });
                return Ok(written);
            }
            self.buffer.drain(..count);
            self.fill()?;
        }
    }
    pub fn closed(&self) -> bool {
        self.closed
    }
    pub fn finish(mut self) -> io::Result<()> {
        let mut byte = [0];
        if !self.closed || !self.buffer.is_empty() || self.source.read(&mut byte)? != 0 {
            return Err(invalid("INVALID_MULTIPART"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fragments<'a> {
        bytes: &'a [u8],
        size: usize,
    }
    impl Read for Fragments<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let size = out.len().min(self.size).min(self.bytes.len());
            out[..size].copy_from_slice(&self.bytes[..size]);
            self.bytes = &self.bytes[size..];
            Ok(size)
        }
    }
    #[test]
    fn delimiters_split_at_every_offset_preserve_binary_and_false_matches() {
        let body = b"--bound\r\nContent-Disposition: form-data; name=\"file\"; filename=\"ignored; name=\\\"fake\\\"\"\r\n\r\n\x00\xff\r\n--boundXXtail\r\n--bound--\r\n";
        for size in 1..=body.len() {
            let mut input = Multipart::new(Fragments { bytes: body, size }, "bound", 4096).unwrap();
            input.header("file").unwrap();
            let mut data = Vec::new();
            input.part(&mut data, 128).unwrap();
            assert_eq!(data, b"\x00\xff\r\n--boundXXtail");
            input.finish().unwrap();
        }
        for limit in [0, 1, 40] {
            let result = Multipart::new(body.as_slice(), "bound", limit).and_then(|mut p| {
                p.header("file")?;
                p.part(&mut Vec::new(), 1)
            });
            assert!(result.is_err());
        }
        let mut input = Multipart::new(&body[..body.len() - 1], "bound", 4096).unwrap();
        input.header("file").unwrap();
        assert!(input.part(&mut Vec::new(), 128).is_err());
    }
}
