//! CLI transport verifies the daemon's root-owned socket before sending command bytes.
use crate::{config::invalid, service::Request};
use sandcrab_core::fs::protected_directory;
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        net::UnixStream,
    },
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

pub fn request(socket: &Path, method: &str, path: &str, body: Option<&Value>) -> io::Result<Value> {
    protected_directory(
        socket
            .parent()
            .ok_or_else(|| invalid("Socket needs a parent"))?,
    )?;
    let info = fs::symlink_metadata(socket)?;
    if !info.file_type().is_socket() || info.uid() != 0 || info.mode() & 0o007 != 0 {
        return Err(invalid("Socket must be root-owned and private"));
    }
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    if rustix::net::sockopt::socket_peercred(&stream)
        .map(|c| c.uid.as_raw())
        .ok()
        != Some(0)
    {
        return Err(invalid("Daemon peer must be root"));
    }
    let body = body
        .map(serde_json::to_vec)
        .transpose()?
        .unwrap_or_default();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: sandcrab\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    let mut response = Vec::new();
    (&mut stream)
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut response)?;
    if response.len() > 8 * 1024 * 1024 {
        return Err(invalid("Response too large"));
    }
    let end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| invalid("Invalid HTTP response"))?;
    let head =
        std::str::from_utf8(&response[..end]).map_err(|_| invalid("Invalid HTTP headers"))?;
    let status = head
        .lines()
        .next()
        .and_then(|s| s.split(' ').nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| invalid("Missing HTTP status"))?;
    let length = head
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("Content-Length"))
        })
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .ok_or_else(|| invalid("Missing response length"))?;
    if length != response.len() - end - 4 {
        return Err(invalid(
            "Incomplete HTTP response; query the existing run instead of retrying it",
        ));
    }
    let value: Value = serde_json::from_slice(&response[end + 4..])?;
    if !(200..300).contains(&status) {
        return Err(invalid(format!(
            "HTTP {status}: {}",
            value["error"]["code"].as_str().unwrap_or("UNKNOWN_ERROR")
        )));
    }
    Ok(value)
}

pub fn run(
    socket: &Path,
    profile: &str,
    command: &[String],
    timeout: Option<u64>,
) -> io::Result<i32> {
    let stopped = Arc::new(AtomicBool::new(false));
    let signals = [
        signal_hook::flag::register(signal_hook::consts::SIGINT, stopped.clone())?,
        signal_hook::flag::register(signal_hook::consts::SIGTERM, stopped.clone())?,
    ];
    let info = request(socket, "GET", "/v1/info", None)?;
    let server_id = info["serverId"]
        .as_str()
        .ok_or_else(|| invalid("No serverId"))?
        .to_string();
    let input = Request {
        id: sandcrab_core::new_uuid()?,
        server_id,
        profile: profile.into(),
        command: command.into(),
        timeout_millis: timeout,
        output_limit_bytes: None,
    };
    let path = format!("/v1/runs/{}", input.id);
    // Publish the recovery handle before dispatch; a lost POST response must never cause replay
    // with a newly generated ID or a newly fetched server epoch.
    eprintln!("runId={}", input.id);
    let result = (|| {
        request(
            socket,
            "POST",
            "/v1/runs",
            Some(&serde_json::to_value(&input)?),
        )?;
        let deadline = Instant::now() + Duration::from_secs(340);
        let mut cancelled = false;
        loop {
            if stopped.load(Ordering::SeqCst) && !cancelled {
                request(socket, "POST", &format!("{path}/cancel"), Some(&json!({})))?;
                cancelled = true;
            }
            let state = request(socket, "GET", &path, None)?;
            match state["state"].as_str() {
                Some("running") => {}
                Some("closing") => {
                    return Err(invalid(format!(
                        "Run {} requires daemon cleanup; result retained",
                        input.id
                    )));
                }
                Some(_) => {
                    println!("{}", serde_json::to_string(&state)?);
                    request(socket, "POST", &format!("{path}/forget"), Some(&json!({})))?;
                    return Ok(if state["state"] == "succeeded" { 0 } else { 1 });
                }
                None => return Err(invalid("Missing run state")),
            }
            if Instant::now() >= deadline {
                return Err(invalid(format!(
                    "Run {} observation timed out; inspect it before another run",
                    input.id
                )));
            }
            thread::sleep(Duration::from_millis(50));
        }
    })();
    for signal in signals {
        signal_hook::low_level::unregister(signal);
    }
    result
}
