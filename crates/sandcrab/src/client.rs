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
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

pub fn request(socket: &Path, method: &str, path: &str, body: Option<&Value>) -> io::Result<Value> {
    Client::new(socket).request(method, path, body)
}

struct Client {
    socket: PathBuf,
    stream: Option<UnixStream>,
}
impl Client {
    fn new(socket: &Path) -> Self {
        Self {
            socket: socket.into(),
            stream: None,
        }
    }
    fn request(&mut self, method: &str, path: &str, body: Option<&Value>) -> io::Result<Value> {
        // Take ownership before any I/O. A failed exchange discards the connection
        // and returns the error; even a GET is not automatically replayed.
        let mut stream = match self.stream.take() {
            Some(stream) => stream,
            None => connect(&self.socket)?,
        };
        let body = body
            .map(serde_json::to_vec)
            .transpose()?
            .unwrap_or_default();
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: sandcrab\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            body.len()
        )?;
        stream.write_all(&body)?;
        let (head, mut body) = sandcrab_core::http::response(&mut stream).map_err(|_| {
            invalid("Invalid or incomplete HTTP response; inspect the existing ID before retrying")
        })?;
        if head.length > 8 * 1024 * 1024 {
            return Err(invalid("Response too large"));
        }
        let mut bytes = Vec::with_capacity(head.length as usize);
        body.read_to_end(&mut bytes).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "Incomplete HTTP response ({error}); inspect the existing ID before retrying"
                ),
            )
        })?;
        let value: Value = serde_json::from_slice(&bytes)?;
        if !head.close {
            self.stream = Some(stream);
        }
        if !(200..300).contains(&head.status) {
            return Err(invalid(format!(
                "HTTP {}: {}",
                head.status,
                value["error"]["code"].as_str().unwrap_or("UNKNOWN_ERROR")
            )));
        }
        Ok(value)
    }
}

pub(crate) fn connect(socket: &Path) -> io::Result<UnixStream> {
    protected_directory(
        socket
            .parent()
            .ok_or_else(|| invalid("Socket needs a parent"))?,
    )?;
    let info = fs::symlink_metadata(socket)?;
    if !info.file_type().is_socket() || info.uid() != 0 || info.mode() & 0o007 != 0 {
        return Err(invalid("Socket must be root-owned and private"));
    }
    let stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    if rustix::net::sockopt::socket_peercred(&stream)
        .map(|c| c.uid.as_raw())
        .ok()
        != Some(0)
    {
        return Err(invalid("Daemon peer must be root"));
    }
    Ok(stream)
}

pub fn run(
    socket: &Path,
    profile: &str,
    command: &[String],
    timeout: Option<u64>,
) -> io::Result<i32> {
    let mut client = Client::new(socket);
    let info = client.request("GET", "/v1/info", None)?;
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
    submit_run(&mut client, "/v1/runs", &serde_json::to_value(&input)?)
}

pub fn execute_session(
    socket: &Path,
    session: &str,
    command: &str,
    timeout: Option<u64>,
) -> io::Result<i32> {
    let mut client = Client::new(socket);
    let info = client.request("GET", "/v1/info", None)?;
    let input = json!({"id":sandcrab_core::new_uuid()?,"serverId":info["serverId"],
        "command":command,"timeoutMillis":timeout});
    submit_run(
        &mut client,
        &format!("/v1/sessions/{session}/commands"),
        &input,
    )
}

fn submit_run(client: &mut Client, endpoint: &str, input: &Value) -> io::Result<i32> {
    let stopped = Arc::new(AtomicBool::new(false));
    let signals = [
        signal_hook::flag::register(signal_hook::consts::SIGINT, stopped.clone())?,
        signal_hook::flag::register(signal_hook::consts::SIGTERM, stopped.clone())?,
    ];
    let id = input["id"]
        .as_str()
        .ok_or_else(|| invalid("Missing run ID"))?;
    let path = format!("/v1/runs/{id}");
    // Publish the recovery handle before dispatch; a lost POST response must never cause replay
    // with a newly generated ID or a newly fetched server epoch.
    eprintln!("runId={id}");
    let result = (|| {
        client.request("POST", endpoint, Some(input))?;
        let deadline = Instant::now() + Duration::from_secs(340);
        let mut cancelled = false;
        loop {
            if stopped.load(Ordering::SeqCst) && !cancelled {
                client.request("POST", &format!("{path}/cancel"), Some(&json!({})))?;
                cancelled = true;
            }
            let state = client.request("GET", &path, None)?;
            match state["state"].as_str() {
                Some("running") => {}
                Some("closing") => {
                    return Err(invalid(format!(
                        "Run {} requires daemon cleanup; result retained",
                        id
                    )));
                }
                Some(_) => {
                    println!("{}", serde_json::to_string(&state)?);
                    if let Err(error) =
                        client.request("POST", &format!("{path}/forget"), Some(&json!({})))
                    {
                        eprintln!(
                            "Run {} outcome is final; forgetting its record failed: {error}. Inspect or forget this ID; do not rerun the command.",
                            id
                        );
                    }
                    return Ok(if state["state"] == "succeeded" { 0 } else { 1 });
                }
                None => return Err(invalid("Missing run state")),
            }
            if Instant::now() >= deadline {
                return Err(invalid(format!(
                    "Run {} observation timed out; inspect it before another run",
                    id
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

pub fn open_session(
    socket: &Path,
    profile: &str,
    ttl: Option<u64>,
    volume: Option<&str>,
) -> io::Result<i32> {
    let info = request(socket, "GET", "/v1/info", None)?;
    let id = sandcrab_core::new_uuid()?;
    eprintln!("sessionId={id}");
    request(
        socket,
        "POST",
        "/v1/sessions",
        Some(
            &json!({"id":id,"serverId":info["serverId"],"profile":profile,"ttlMillis":ttl,"volumeId":volume}),
        ),
    )?;
    wait_session(socket, &id, true)
}

pub fn create_volume(socket: &Path, plan: crate::storage::Plan) -> io::Result<i32> {
    let info = request(socket, "GET", "/v1/info", None)?;
    let id = plan.id.clone();
    let mut input = serde_json::to_value(plan)?;
    input["serverId"] = info["serverId"].clone();
    eprintln!("volumeId={id}");
    request(socket, "POST", "/v1/volumes", Some(&input))?;
    wait_volume(socket, &id, true)
}

pub fn wait_volume(socket: &Path, id: &str, creating: bool) -> io::Result<i32> {
    let mut client = Client::new(socket);
    let deadline = Instant::now() + Duration::from_secs(340);
    loop {
        let state = client.request("GET", &format!("/v1/volumes/{id}"), None)?;
        match state["state"].as_str() {
            Some("creating" | "deleting") => (),
            Some(status) => {
                println!("{state}");
                return Ok(
                    if (creating && status == "ready") || (!creating && status == "deleted") {
                        0
                    } else {
                        1
                    },
                );
            }
            None => return Err(invalid("Missing volume state")),
        }
        if Instant::now() >= deadline {
            return Err(invalid(format!(
                "Volume {id} observation timed out; inspect the existing ID"
            )));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

pub fn wait_session(socket: &Path, id: &str, opening: bool) -> io::Result<i32> {
    let mut client = Client::new(socket);
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let state = client.request("GET", &format!("/v1/sessions/{id}"), None)?;
        let status = state["state"]
            .as_str()
            .ok_or_else(|| invalid("Missing session state"))?;
        if status == "closing"
            || ["closed", "expired", "failed"].contains(&status)
            || (opening && status == "ready")
        {
            println!("{state}");
            return Ok(
                if (opening && status == "ready")
                    || (!opening && ["closed", "expired", "failed"].contains(&status))
                {
                    0
                } else {
                    1
                },
            );
        }
        if Instant::now() >= deadline {
            return Err(invalid(format!(
                "Session {id} observation timed out; inspect the existing ID"
            )));
        }
        thread::sleep(Duration::from_millis(50));
    }
}
