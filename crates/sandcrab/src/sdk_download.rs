//! SDK selections operate on bounded snapshots, including arbitrarily long lines.
use crate::{
    config::invalid,
    sdk_types::{self, Result},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{self, BufWriter, Read, Seek, SeekFrom, Write},
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Selection {
    Bytes {
        start: Option<u64>,
        end: Option<u64>,
    },
    Lines {
        offset: u64,
        limit: Option<u64>,
    },
}
pub struct Range {
    pub start: u64,
    pub total: u64,
}
fn number(value: &str) -> Option<u64> {
    (!value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
}
pub fn request(query: &str, range: Option<&str>) -> Result<(String, Option<Selection>)> {
    let (mut path, mut offset, mut limit) = (None, None, None);
    for (key, value) in sdk_types::query(query)? {
        match key.as_str() {
            "path" if path.is_none() => path = Some(value),
            "offset" if offset.is_none() => {
                offset = Some(
                    number(&value)
                        .filter(|n| (1..=i64::MAX as u64).contains(n))
                        .ok_or((400, "INVALID_OFFSET"))?,
                )
            }
            "limit" if limit.is_none() => {
                limit = Some(
                    number(&value)
                        .filter(|n| (1..=i64::MAX as u64).contains(n))
                        .ok_or((400, "INVALID_LIMIT"))?,
                )
            }
            _ => return Err((400, "INVALID_QUERY")),
        }
    }
    let path = crate::sdk_file_io::path(&path.ok_or((400, "INVALID_QUERY"))?, false)
        .map_err(|_| (400, "INVALID_PATH"))?;
    if offset.is_some() || limit.is_some() {
        if range.is_some() {
            return Err((400, "CONFLICTING_SELECTIONS"));
        }
        return Ok((
            path,
            Some(Selection::Lines {
                offset: offset.unwrap_or(1),
                limit,
            }),
        ));
    }
    let selection = if let Some(range) = range {
        let value = range.strip_prefix("bytes=").ok_or((416, "INVALID_RANGE"))?;
        if value.contains(',') {
            return Err((400, "MULTIPLE_RANGES_UNSUPPORTED"));
        }
        let (first, last) = value.split_once('-').ok_or((416, "INVALID_RANGE"))?;
        let start = if first.is_empty() {
            None
        } else {
            Some(number(first).ok_or((416, "INVALID_RANGE"))?)
        };
        let end = if last.is_empty() {
            None
        } else {
            Some(number(last).ok_or((416, "INVALID_RANGE"))?)
        };
        if start.is_none() && end.is_none() {
            return Err((416, "INVALID_RANGE"));
        }
        Some(Selection::Bytes { start, end })
    } else {
        None
    };
    Ok((path, selection))
}
impl Selection {
    pub fn range(&self, size: u64) -> io::Result<(u64, u64)> {
        let Self::Bytes { start, end } = self else {
            return Err(invalid("INVALID_SELECTION"));
        };
        if size == 0 {
            return Err(invalid("RANGE_NOT_SATISFIABLE"));
        }
        let start = match start {
            Some(start) if *start < size => *start,
            None if end.is_some_and(|n| n > 0) => size.saturating_sub(end.unwrap()),
            _ => return Err(invalid("RANGE_NOT_SATISFIABLE")),
        };
        let last = if matches!(self, Self::Bytes { start: Some(_), .. }) {
            end.unwrap_or(size - 1).min(size - 1)
        } else {
            size - 1
        };
        if last < start {
            return Err(invalid("RANGE_NOT_SATISFIABLE"));
        }
        Ok((start, last - start + 1))
    }
    pub fn text(&self) -> bool {
        matches!(self, Self::Lines { .. })
    }
    pub fn copy(&self, input: &mut File, output: &mut impl Write, limit: u64) -> io::Result<()> {
        match self {
            Self::Bytes { .. } => {
                let (start, count) = self.range(input.metadata()?.len())?;
                if count > limit {
                    return Err(invalid("FILE_LIMIT"));
                }
                input.seek(SeekFrom::Start(start))?;
                if io::copy(&mut input.take(count), output)? != count {
                    return Err(invalid("FILE_CHANGED"));
                }
                Ok(())
            }
            Self::Lines {
                offset,
                limit: lines,
            } => selected_lines(input, output, *offset, *lines, limit),
        }
    }
}
fn carriage_returns(output: &mut impl Write, mut count: u64) -> io::Result<()> {
    let block = [b'\r'; 32768];
    while count != 0 {
        let bytes = count.min(block.len() as u64) as usize;
        output.write_all(&block[..bytes])?;
        count -= bytes as u64;
    }
    Ok(())
}
fn selected_lines(
    input: &mut impl Read,
    output: &mut impl Write,
    offset: u64,
    limit: Option<u64>,
    scan_limit: u64,
) -> io::Result<()> {
    if offset == 0 || limit == Some(0) {
        return Err(invalid("INVALID_SELECTION"));
    }
    let mut output = BufWriter::new(output);
    let (mut line, mut written, mut scanned, mut pending) = (1u64, 0u64, 0u64, 0u64);
    let (mut started, mut chosen) = (false, false);
    let mut block = [0; 32768];
    loop {
        let capacity = block
            .len()
            .min(scan_limit.saturating_sub(scanned).saturating_add(1) as usize);
        let count = input.read(&mut block[..capacity])?;
        if count == 0 {
            return output.flush();
        }
        for byte in &block[..count] {
            scanned += 1;
            if scanned > scan_limit {
                return Err(invalid("FILE_LIMIT"));
            }
            if !started {
                started = true;
                chosen = line >= offset;
                if chosen {
                    if written != 0 {
                        output.write_all(b"\n")?;
                    }
                    written += 1;
                }
            }
            if chosen {
                match byte {
                    b'\r' => pending += 1,
                    b'\n' => (),
                    byte => {
                        carriage_returns(&mut output, pending)?;
                        pending = 0;
                        output.write_all(&[*byte])?;
                    }
                }
            }
            if *byte == b'\n' {
                if chosen && limit.is_some_and(|limit| written >= limit) {
                    return output.flush();
                }
                pending = 0;
                started = false;
                line += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn line_scan_prefetch_is_bounded_to_the_budget_and_one_eof_byte() {
        struct Counted<'a> {
            bytes: &'a [u8],
            read: usize,
        }
        impl Read for Counted<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let count = self.bytes.read(buffer)?;
                self.read += count;
                Ok(count)
            }
        }
        let mut input = Counted {
            bytes: &[b'a'; 100],
            read: 0,
        };
        assert!(selected_lines(&mut input, &mut Vec::new(), 2, Some(1), 10).is_err());
        assert_eq!(input.read, 11);
    }
    #[test]
    fn byte_selection_clamps_bounds_and_rejects_ambiguous_or_empty_ranges() {
        for (header, size, expected) in [
            ("bytes=1-3", 5, (1, 3)),
            ("bytes=2-", 5, (2, 3)),
            ("bytes=-2", 5, (3, 2)),
            ("bytes=-20", 5, (0, 5)),
            ("bytes=1-99", 5, (1, 4)),
        ] {
            let selection = request("path=a", Some(header)).unwrap().1.unwrap();
            assert_eq!(selection.range(size).unwrap(), expected);
        }
        for header in ["bytes=-0", "bytes=5-", "bytes=4-2"] {
            assert!(
                request("path=a", Some(header))
                    .unwrap()
                    .1
                    .unwrap()
                    .range(5)
                    .is_err()
            );
        }
        assert!(request("path=a&offset=1", Some("bytes=0-1")).is_err());
        assert!(request("path=a&limit=0", None).is_err());
        assert!(request("path=a", Some("bytes=0-1,3-4")).is_err());
    }
    #[test]
    fn lines_trim_line_endings_without_buffering_whole_lines() {
        for (mut input, offset, count, expected) in [
            (
                b"one\r\n\r\ntwo\r\nlast".as_slice(),
                2,
                Some(2),
                b"\ntwo".as_slice(),
            ),
            (b"one\nlast", 2, None, b"last"),
            (b"one\n", 2, None, b""),
            (b"a\rb\r\r\n", 1, None, b"a\rb"),
            (b"\n\n", 1, None, b"\n"),
        ] {
            let mut output = Vec::new();
            selected_lines(&mut input, &mut output, offset, count, 65536).unwrap();
            assert_eq!(output, expected);
        }
        let mut input = vec![b'x'; 131073];
        input.extend_from_slice(b"\r\nend\n");
        let mut output = Vec::new();
        selected_lines(&mut input.as_slice(), &mut output, 2, Some(1), 262144).unwrap();
        assert_eq!(output, b"end");
        assert!(selected_lines(&mut input.as_slice(), &mut Vec::new(), 2, Some(1), 10).is_err());
    }
}
