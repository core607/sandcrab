//! Stream plain tar or an already unpacked OCI root tree through the public API.
use crate::{
    client::{self, Endpoint},
    config::invalid,
};
use serde_json::Value;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
    time::Duration,
};

const HELP: &str = "sandcrab template capture --socket PATH SESSION_ID DESTINATION\nsandcrab template import --socket PATH --profile NAME [--directory | --expected-id SHA256] SOURCE\nsandcrab template list --socket PATH [--after SHA256]\nsandcrab template get|delete --socket PATH SHA256\nUse --endpoint URL with the normal token option for loopback HTTP. Capture freezes the session's writers while creating a full filesystem tar; it restores no process, variable or cwd. DESTINATION must be a new local file. SOURCE is plain tar; --directory streams an unpacked tree without pulling an image.\n";

struct Chunks<'a, W> {
    output: &'a mut W,
    bytes: u64,
}
impl<W: Write> Write for Chunks<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| invalid("Template exceeds 1 GiB"))?;
        if self.bytes > 1_073_741_824 {
            return Err(invalid("Template exceeds 1 GiB"));
        }
        write!(self.output, "{:x}\r\n", bytes.len())?;
        self.output.write_all(bytes)?;
        self.output.write_all(b"\r\n")?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

fn import(
    endpoint: &Endpoint,
    profile: &str,
    source: &Path,
    directory: bool,
    expected: Option<&str>,
) -> io::Result<Value> {
    if !crate::config::name(profile) {
        return Err(invalid("Invalid profile name"));
    }
    if expected.is_some_and(|id| !crate::file_io::digest(id)) {
        return Err(invalid("Invalid expected template ID"));
    }
    let route = format!(
        "/v1/templates?profile={profile}{}",
        expected
            .map(|id| format!("&expectedId={id}"))
            .unwrap_or_default()
    );
    let recovery = expected
        .map(|id| format!("inspect template {id} before retrying this archive"))
        .unwrap_or_else(|| "inspect template list before retrying".into());
    let result = (|| {
        let mut stream = client::connect(endpoint)?;
        stream.set_write_timeout(Some(Duration::from_secs(35)))?;
        stream.set_read_timeout(Some(Duration::from_secs(75)))?;
        write!(
            stream,
            "POST {route} HTTP/1.1\r\nContent-Type: application/x-tar\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n"
        )?;
        endpoint.headers(&mut stream)?;
        stream.write_all(b"\r\n")?;
        let mut chunks = Chunks {
            output: &mut stream,
            bytes: 0,
        };
        if directory {
            crate::file_io::pack_tree(
                &crate::file_io::directory(source)?,
                &mut chunks,
                1_073_741_824,
                crate::templates::ENTRY_LIMIT,
            )?;
        } else {
            let mut file = File::open(source)?;
            if !file.metadata()?.is_file() {
                return Err(invalid("Template source must be a regular tar file"));
            }
            io::copy(&mut file, &mut chunks)?;
        }
        stream.write_all(b"0\r\n\r\n")?;
        stream.flush()?;
        let (head, mut body) = sandcrab_core::http::response(&mut stream).map_err(invalid)?;
        if head.length > 65536 {
            return Err(invalid("Template reply exceeds 65536 bytes"));
        }
        let mut bytes = Vec::new();
        body.read_to_end(&mut bytes)?;
        let value: Value = serde_json::from_slice(&bytes)?;
        if head.status != 200 {
            return Err(invalid(format!(
                "Template: HTTP {} {}",
                head.status, value["error"]["code"]
            )));
        }
        if expected.is_some_and(|id| value["id"].as_str() != Some(id)) {
            return Err(invalid("Template reply does not match the expected ID"));
        }
        Ok(value)
    })();
    result.map_err(|error: io::Error| io::Error::new(error.kind(), format!("{error}; {recovery}")))
}

pub fn command(args: &[String], token_file: Option<&Path>) -> io::Result<i32> {
    if matches!(args,[flag] if ["--help","-h"].contains(&flag.as_str())) {
        print!("{HELP}");
        return Ok(0);
    }
    let [mode, flag, address, rest @ ..] = args else {
        return Err(invalid(HELP));
    };
    let endpoint = Endpoint::parse(flag, address, token_file)?;
    if let ("capture", [session, destination]) = (mode.as_str(), rest)
        && sandcrab_core::uuid(session)
        && destination != "-"
    {
        return crate::file_client::checkpoint(&endpoint, session, Path::new(destination));
    }
    let result = match (mode.as_str(), rest) {
        ("import", [flag, profile, source]) if flag == "--profile" => {
            import(&endpoint, profile, Path::new(source), false, None)?
        }
        ("import", [flag, profile, directory, source])
            if flag == "--profile" && directory == "--directory" =>
        {
            import(&endpoint, profile, Path::new(source), true, None)?
        }
        ("import", [flag, profile, expected, id, source])
            if flag == "--profile" && expected == "--expected-id" =>
        {
            import(&endpoint, profile, Path::new(source), false, Some(id))?
        }
        ("list", []) => client::request(&endpoint, "GET", "/v1/templates", None)?,
        ("list", [flag, after]) if flag == "--after" && crate::file_io::digest(after) => {
            client::request(
                &endpoint,
                "GET",
                &format!("/v1/templates?after={after}"),
                None,
            )?
        }
        ("get" | "delete", [id]) if crate::file_io::digest(id) => client::request(
            &endpoint,
            if mode == "get" { "GET" } else { "DELETE" },
            &format!("/v1/templates/{id}"),
            None,
        )?,
        _ => return Err(invalid(HELP)),
    };
    println!("{result}");
    Ok(0)
}
