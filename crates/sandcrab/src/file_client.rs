//! Streaming CLI file operations. A lost upload response keeps its recovery ID;
//! a failed download never replaces an existing local destination.
use crate::{
    client,
    config::invalid,
    file_io::{Format, digest, valid_path},
};
use rustix::fs::{CWD, RenameFlags, renameat_with};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

pub struct Put {
    pub id: Option<String>,
    pub format: Format,
    pub replace: bool,
    pub freeze: bool,
    pub mode: Option<u32>,
    pub keep_result: bool,
}
fn hash(file: &mut File) -> io::Result<(u64, String)> {
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 32768];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        if bytes > 1_073_741_824 {
            return Err(invalid("File exceeds the 1 GiB transfer limit"));
        }
        hash.update(&buffer[..n]);
    }
    Ok((bytes, format!("{:x}", hash.finalize())))
}
fn outcome(socket: &Path, result: Value, keep: bool) -> io::Result<i32> {
    println!("{result}");
    let id = result["id"]
        .as_str()
        .ok_or_else(|| invalid("Upload response has no ID"))?;
    let state = result["state"].as_str().unwrap_or("unknown");
    if ["unknown", "closing", "publishing", "published", "receiving"].contains(&state) {
        eprintln!(
            "Upload {id} requires inspection; retain this ID and inspect its publication state before another write."
        );
    } else if !keep
        && ["succeeded", "failed"].contains(&state)
        && let Err(error) = client::request(
            socket,
            "POST",
            &format!("/v1/uploads/{id}/forget"),
            Some(&json!({})),
        )
    {
        eprintln!(
            "Upload {id} outcome is final; forgetting its record failed: {error}. Do not repeat the write."
        );
    }
    Ok(if state == "succeeded" { 0 } else { 1 })
}
pub fn put(
    socket: &Path,
    session: &str,
    source: &Path,
    destination: &str,
    options: Put,
) -> io::Result<i32> {
    if !valid_path(destination, false) {
        return Err(invalid("Destination must be a relative workspace path"));
    }
    let mut file = File::open(source)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("Upload source must be a regular file"));
    }
    let (bytes, sha256) = hash(&mut file)?;
    file.seek(SeekFrom::Start(0))?;
    let info = client::request(socket, "GET", "/v1/info", None)?;
    let id = match options.id {
        Some(id) => id,
        None => sandcrab_core::new_uuid()?,
    };
    eprintln!("uploadId={id}");
    let plan = json!({"id":id,"serverId":info["serverId"],"sessionId":session,"path":destination,"format":options.format,
        "bytes":bytes,"sha256":sha256,"replace":options.replace,"freeze":options.freeze,"mode":options.mode});
    let registered = client::request(socket, "POST", "/v1/uploads", Some(&plan))?;
    if registered["state"] != "waiting" {
        return outcome(socket, registered, options.keep_result);
    }
    let mut stream = client::connect(socket)?;
    stream.set_write_timeout(Some(Duration::from_secs(35)))?;
    stream.set_read_timeout(Some(Duration::from_secs(75)))?;
    write!(
        stream,
        "PUT /v1/uploads/{id}/content HTTP/1.1\r\nHost: sandcrab\r\nContent-Type: application/octet-stream\r\nContent-Length: {bytes}\r\nConnection: close\r\n\r\n"
    )?;
    let sent = io::copy(&mut (&mut file).take(bytes), &mut stream);
    if sent.as_ref().is_err() || sent.as_ref().is_ok_and(|n| *n != bytes) {
        return Err(invalid(format!(
            "Upload {id} did not finish sending; inspect this ID before retrying"
        )));
    }
    let (head, mut response) = sandcrab_core::http::response(&mut stream).map_err(|_| {
        invalid(format!(
            "Upload {id} response is incomplete; inspect this ID before retrying"
        ))
    })?;
    if head.length > 65536 {
        return Err(invalid("Upload response exceeds 65536 bytes"));
    }
    let mut payload = Vec::new();
    response.read_to_end(&mut payload).map_err(|_| {
        invalid(format!(
            "Upload {id} response is incomplete; inspect this ID before retrying"
        ))
    })?;
    let value: Value = serde_json::from_slice(&payload)?;
    if head.status != 200 {
        return Err(invalid(format!(
            "Upload {id}: HTTP {} {}",
            head.status, value["error"]["code"]
        )));
    }
    outcome(socket, value, options.keep_result)
}
struct Partial {
    path: PathBuf,
    file: File,
    installed: bool,
}
impl Drop for Partial {
    fn drop(&mut self) {
        if !self.installed {
            let _ = fs::remove_file(&self.path);
        }
    }
}
fn receive(
    input: &mut impl Read,
    output: &mut impl Write,
    bytes: u64,
    expected: &str,
) -> io::Result<()> {
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 32768];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        output.write_all(&buffer[..n])?;
        hash.update(&buffer[..n]);
        count += n as u64;
    }
    if count != bytes || format!("{:x}", hash.finalize()) != expected {
        return Err(invalid("Snapshot length or SHA-256 did not match"));
    }
    output.flush()
}
pub struct Get {
    pub format: Format,
    pub freeze: bool,
    pub replace: bool,
}
pub fn get(
    socket: &Path,
    session: &str,
    path: &str,
    destination: &Path,
    options: Get,
) -> io::Result<i32> {
    if !valid_path(path, options.format == Format::Tar) {
        return Err(invalid("Source must be a relative workspace path"));
    }
    let mut stream = client::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(75)))?;
    let body =
        serde_json::to_vec(&json!({"path":path,"format":options.format,"freeze":options.freeze}))?;
    write!(
        stream,
        "POST /v1/sessions/{session}/snapshot HTTP/1.1\r\nHost: sandcrab\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    let (head, mut response) = sandcrab_core::http::response(&mut stream)
        .map_err(|_| invalid("Invalid snapshot response"))?;
    if head.status != 200 {
        if head.length > 65536 {
            return Err(invalid("Snapshot error response too large"));
        }
        let mut body = Vec::new();
        response.read_to_end(&mut body)?;
        let value: Value = serde_json::from_slice(&body)?;
        return Err(invalid(format!(
            "HTTP {}: {}",
            head.status, value["error"]["code"]
        )));
    }
    if head.length > 1_073_741_824 {
        return Err(invalid("Snapshot exceeds the 1 GiB transfer limit"));
    }
    let expected = head
        .header("etag")
        .and_then(|s| s.strip_prefix('"')?.strip_suffix('"'))
        .filter(|s| digest(s))
        .ok_or_else(|| invalid("Snapshot has no SHA-256 ETag"))?;
    if destination == Path::new("-") {
        receive(
            &mut response,
            &mut io::stdout().lock(),
            head.length,
            expected,
        )?;
        eprintln!("snapshotBytes={} sha256={expected}", head.length);
        return Ok(0);
    }
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temporary = parent.join(format!(".sandcrab-{}.part", sandcrab_core::new_uuid()?));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let mut partial = Partial {
        path: temporary,
        file,
        installed: false,
    };
    receive(&mut response, &mut partial.file, head.length, expected)?;
    partial.file.sync_all()?;
    if options.replace {
        match fs::symlink_metadata(destination) {
            Ok(info) if !info.is_file() => {
                return Err(invalid("Local destination is not a regular file"));
            }
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => (),
        }
    }
    renameat_with(
        CWD,
        &partial.path,
        CWD,
        destination,
        if options.replace {
            RenameFlags::empty()
        } else {
            RenameFlags::NOREPLACE
        },
    )?;
    partial.installed = true;
    File::open(parent)?.sync_all()?;
    println!(
        "{}",
        json!({"bytes":head.length,"sha256":expected,"destination":destination})
    );
    Ok(0)
}
