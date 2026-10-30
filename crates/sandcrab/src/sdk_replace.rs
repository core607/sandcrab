//! Literal replacement streams bytes into private staging before any publication.
use crate::{
    config::invalid,
    file_io::{self, Job},
    sdk_file_io::Entry,
    sdk_fs::Replace,
};
use rustix::fs::{AtFlags, unlinkat};
use serde_json::{Value, json};
use std::io::{self, BufWriter, Read, Write};
use std::os::unix::fs::PermissionsExt;

struct Bounded<W> {
    output: W,
    written: u64,
    limit: u64,
}
impl<W: Write> Write for Bounded<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.limit - self.written {
            return Err(invalid("FILE_LIMIT"));
        }
        let count = self.output.write(bytes)?;
        self.written += count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}
fn replace(
    input: &mut impl Read,
    output: &mut impl Write,
    old: &[u8],
    new: &[u8],
    limit: u64,
) -> io::Result<(u64, u64)> {
    if old.is_empty() {
        return Err(invalid("INVALID_FILE_METADATA"));
    }
    let mut prefix = vec![0; old.len()];
    for index in 1..old.len() {
        let mut previous = prefix[index - 1];
        while previous != 0 && old[index] != old[previous] {
            previous = prefix[previous - 1];
        }
        if old[index] == old[previous] {
            previous += 1;
        }
        prefix[index] = previous;
    }
    let (mut matched, mut count, mut read) = (0, 0u64, 0u64);
    let mut block = [0; 32768];
    loop {
        let bytes = input.read(&mut block)?;
        if bytes == 0 {
            break;
        }
        read += bytes as u64;
        if read > limit {
            return Err(invalid("FILE_LIMIT"));
        }
        for byte in &block[..bytes] {
            while matched != 0 && old[matched] != *byte {
                let next = prefix[matched - 1];
                output.write_all(&old[..matched - next])?;
                matched = next;
            }
            if old[matched] == *byte {
                matched += 1;
                if matched == old.len() {
                    output.write_all(new)?;
                    count += 1;
                    matched = 0;
                }
            } else {
                output.write_all(&[*byte])?;
            }
        }
    }
    output.write_all(&old[..matched])?;
    output.flush()?;
    Ok((read, count))
}
pub fn stage(job: &Job, replacements: &[Replace]) -> io::Result<(Value, bool)> {
    let root = file_io::directory(&job.workspace)?;
    let stage = file_io::directory(&job.stage)?;
    let (mut input_bytes, mut output_bytes) = (0, 0);
    let mut entries = Vec::new();
    let mut counts = serde_json::Map::new();
    for request in replacements {
        let path = crate::sdk_file_io::path(&request.path, false)?;
        let (parent, name) = file_io::parent(&root, &path, false)?;
        let mut input = file_io::regular(&parent, &name)?;
        let mode = input.metadata()?.permissions().mode() & 0o7777;
        if mode > 0o777 {
            return Err(invalid("INVALID_FILE_MODE"));
        }
        let name = format!("content-{}", entries.len());
        let output = file_io::new_file(&stage, &name)?;
        let mut writer = Bounded {
            output: BufWriter::new(&output),
            written: 0,
            limit: job.byte_limit - output_bytes,
        };
        let (read, count) = replace(
            &mut input,
            &mut writer,
            request.old.as_bytes(),
            request.new.as_bytes(),
            job.byte_limit - input_bytes,
        )?;
        input_bytes += read;
        output_bytes += writer.written;
        drop(writer);
        counts.insert(request.path.clone(), json!({"replacedCount":count}));
        if count == 0 {
            drop(output);
            unlinkat(&stage, &name, AtFlags::empty())?;
        } else {
            file_io::ownership(&output, job, mode)?;
            entries.push(Entry { path, mode });
        }
    }
    let changed = !entries.is_empty();
    if changed {
        let manifest = file_io::new_file(&stage, "manifest.json")?;
        serde_json::to_writer(&manifest, &entries)?;
        manifest.sync_all()?;
    }
    stage.sync_all()?;
    Ok((Value::Object(counts), changed))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn streamed_matching_agrees_with_independent_literal_string_replacement() {
        for size in 0..8 {
            for bits in 0..1u32 << size {
                let data = (0..size)
                    .map(|i| if bits & (1 << i) == 0 { 'a' } else { 'b' })
                    .collect::<String>();
                for pattern in ["a", "ab", "aa", "aba", "aabb", "aaab", "abab"] {
                    let mut output = Vec::new();
                    let (_, count) = replace(
                        &mut data.as_bytes(),
                        &mut output,
                        pattern.as_bytes(),
                        b"XY",
                        64,
                    )
                    .unwrap();
                    assert_eq!(output, data.replace(pattern, "XY").as_bytes());
                    assert_eq!(count as usize, data.matches(pattern).count());
                }
            }
        }
    }
    #[test]
    fn literal_byte_replacement_handles_overlap_split_patterns_and_expansion_limits() {
        for (mut data, old, new, expected, count) in [
            (
                b"ababbababc".as_slice(),
                b"ababc".as_slice(),
                b"X".as_slice(),
                b"ababbX".as_slice(),
                1,
            ),
            (b"aaaaa", b"aa", b"x", b"xxa", 2),
            (b"\xffabcabc\0", b"abc", b"x", b"\xffxx\0", 2),
            (b"abab", b"ababab", b"x", b"abab", 0),
        ] {
            let mut output = Vec::new();
            assert_eq!(
                replace(&mut data, &mut output, old, new, 65536).unwrap().1,
                count
            );
            assert_eq!(output, expected);
        }
        let mut data = vec![b'x'; 32767];
        data.extend_from_slice("中abc中".as_bytes());
        let mut output = Vec::new();
        assert_eq!(
            replace(
                &mut data.as_slice(),
                &mut output,
                "中abc".as_bytes(),
                b"ok",
                65536
            )
            .unwrap()
            .1,
            1
        );
        assert!(output.ends_with("ok中".as_bytes()));
        let mut limited = Bounded {
            output: Vec::new(),
            written: 0,
            limit: 3,
        };
        assert!(replace(&mut b"aaa".as_slice(), &mut limited, b"a", b"xx", 3).is_err());
        assert!(replace(&mut b"too large".as_slice(), &mut Vec::new(), b"a", b"b", 1).is_err());
    }
}
