//! Stream plain or gzip-compressed tar archives or an unpacked root tree through the public API.
use crate::{
    cli::{self, Connection, Env},
    client::{self, Endpoint},
    config::invalid,
};
use serde_json::Value;
use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

const HELP: &str = "sandcrab template capture [--socket PATH] SESSION_ID DESTINATION\nsandcrab template import [--socket PATH] [--profile NAME] [--directory | [--gzip] [--layer] [--expected-id SHA256]] SOURCE\nsandcrab template compose [--socket PATH] BASE_ID [LAYER_ID ...]\nsandcrab template list [--socket PATH] [--after SHA256]\nsandcrab template get|delete [--socket PATH] SHA256\nUse --endpoint URL with --token-file FILE (or SANDCRAB_ENDPOINT / SANDCRAB_SOCKET / SANDCRAB_PROFILE / SANDCRAB_TOKEN_FILE). Capture freezes the session's writers while creating a full filesystem tar; it restores no process, variable or cwd. DESTINATION must be a new local file. SOURCE is plain tar (or client-decompressed .tar.gz / .tgz / --gzip) unless --layer explicitly enables deletion markers; --directory streams an unpacked tree without pulling an image.\n";

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

struct LimitedReader<R> {
    inner: R,
    remaining: u64,
}
impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.remaining = self
            .remaining
            .checked_sub(n as u64)
            .ok_or_else(|| invalid("Template archive exceeds 1 GiB"))?;
        Ok(n)
    }
}

pub fn has_gzip_suffix(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".tar.gz") || lower.ends_with(".tgz")
}

fn copy_archive<R: Read, W: Write>(source: R, gzip: bool, output: &mut W) -> io::Result<()> {
    let mut limited = LimitedReader {
        inner: source,
        remaining: 1_073_741_824,
    };
    if gzip {
        let mut buffered = BufReader::new(&mut limited);
        if buffered.fill_buf()?.is_empty() {
            return Err(invalid("Compressed template archive is empty"));
        }
        let mut decoder = flate2::read::MultiGzDecoder::new(buffered);
        io::copy(&mut decoder, output)?;
        let mut inner = decoder.into_inner();
        let mut probe = [0u8; 1];
        if inner.read(&mut probe)? != 0 {
            return Err(invalid(
                "Invalid or trailing bytes in gzip template archive",
            ));
        }
        Ok(())
    } else {
        io::copy(&mut limited, output).map(|_| ())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ImportSpec {
    profile: String,
    source: PathBuf,
    directory: bool,
    gzip: bool,
    layer: bool,
    expected: Option<String>,
}

fn parse_import(args: &[String], env: &Env) -> io::Result<ImportSpec> {
    let (mut profile, mut source, mut expected) = (None, None, None);
    let (mut directory, mut gzip, mut layer) = (false, false, false);
    let mut iter = args.iter();
    while let Some(item) = iter.next() {
        match item.as_str() {
            "--directory" if !directory => directory = true,
            "--gzip" if !gzip => gzip = true,
            "--layer" if !layer => layer = true,
            "--profile" if profile.is_none() => {
                profile = Some(
                    iter.next()
                        .ok_or_else(|| invalid("--profile requires a name"))?
                        .as_str(),
                );
            }
            "--expected-id" if expected.is_none() => {
                expected = Some(
                    iter.next()
                        .ok_or_else(|| invalid("--expected-id requires a SHA-256 digest"))?
                        .clone(),
                );
            }
            flag if flag.starts_with('-') => return Err(invalid(HELP)),
            path if source.is_none() => source = Some(PathBuf::from(path)),
            _ => return Err(invalid(HELP)),
        }
    }
    let source = source.ok_or_else(|| invalid(HELP))?;
    if directory && (layer || gzip) {
        return Err(invalid(
            "--directory cannot be combined with --layer or --gzip",
        ));
    }
    let gzip = !directory && (gzip || has_gzip_suffix(&source));
    Ok(ImportSpec {
        profile: cli::resolve_profile(profile, env)?,
        source,
        directory,
        gzip,
        layer,
        expected,
    })
}

fn import(endpoint: &Endpoint, spec: &ImportSpec) -> io::Result<Value> {
    if !crate::config::name(&spec.profile) {
        return Err(invalid("Invalid profile name"));
    }
    if spec
        .expected
        .as_deref()
        .is_some_and(|id| !crate::file_io::digest(id))
    {
        return Err(invalid("Invalid expected template ID"));
    }
    let route = format!(
        "/v1/templates?profile={}{}{}",
        spec.profile,
        spec.expected
            .as_deref()
            .map(|id| format!("&expectedId={id}"))
            .unwrap_or_default(),
        if spec.layer { "&format=layer" } else { "" }
    );
    let recovery = spec
        .expected
        .as_deref()
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
        if spec.directory {
            crate::file_io::pack_tree(
                &crate::file_io::directory(&spec.source)?,
                &mut chunks,
                1_073_741_824,
                crate::templates::ENTRY_LIMIT,
            )?;
        } else {
            let file = File::open(&spec.source)?;
            if !file.metadata()?.is_file() {
                return Err(invalid("Template source must be a regular tar file"));
            }
            copy_archive(file, spec.gzip, &mut chunks)?;
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
        if spec
            .expected
            .as_deref()
            .is_some_and(|id| value["id"].as_str() != Some(id))
        {
            return Err(invalid("Template reply does not match the expected ID"));
        }
        Ok(value)
    })();
    result.map_err(|error: io::Error| io::Error::new(error.kind(), format!("{error}; {recovery}")))
}

pub fn command(args: &[String], connection: &Connection, env: &Env) -> io::Result<i32> {
    if matches!(args, [flag] if ["--help", "-h"].contains(&flag.as_str())) {
        print!("{HELP}");
        return Ok(0);
    }
    let [mode, rest @ ..] = args else {
        return Err(invalid(HELP));
    };
    let endpoint = connection.endpoint(env)?;
    if let ("capture", [session, destination]) = (mode.as_str(), rest)
        && sandcrab_core::uuid(session)
        && destination != "-"
    {
        return crate::file_client::checkpoint(&endpoint, session, Path::new(destination));
    }
    let result = match (mode.as_str(), rest) {
        ("compose", layers)
            if !layers.is_empty()
                && layers.len() <= crate::recipes::MAX_LAYERS
                && layers.iter().all(|id| crate::file_io::digest(id)) =>
        {
            let id = crate::recipes::identity(layers).map_err(|(_, code)| invalid(code))?;
            eprintln!("templateId={id}");
            client::request(
                &endpoint,
                "POST",
                "/v1/templates/compose",
                Some(&serde_json::json!({"layers":layers})),
            )?
        }
        ("import", rest) => {
            let spec = parse_import(rest, env)?;
            import(&endpoint, &spec)?
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

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};

    fn vec_args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn import_accepts_flexible_flag_order_env_profile_and_gzip_detection() {
        let digest = "a".repeat(64);
        let env = Env {
            profile: Some("default".into()),
            ..Env::default()
        };
        let spec = parse_import(
            &vec_args(&["--expected-id", &digest, "rootfs.tar.gz", "--layer"]),
            &env,
        )
        .unwrap();
        assert_eq!(
            spec,
            ImportSpec {
                profile: "default".into(),
                source: PathBuf::from("rootfs.tar.gz"),
                directory: false,
                gzip: true,
                layer: true,
                expected: Some(digest),
            }
        );

        let dir_spec = parse_import(
            &vec_args(&["./unpacked", "--directory", "--profile", "python"]),
            &env,
        )
        .unwrap();
        assert!(dir_spec.directory && !dir_spec.gzip && dir_spec.profile == "python");

        assert!(parse_import(&vec_args(&["--directory", "--gzip", "./unpacked"]), &env).is_err());
        assert!(parse_import(&vec_args(&["--directory", "--layer", "./unpacked"]), &env).is_err());
    }

    #[test]
    fn gzip_stream_decompresses_cleanly_and_rejects_plain_or_trailing_garbage() {
        let payload = b"synthetic tar payload bytes";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(payload).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut decoded = Vec::new();
        copy_archive(compressed.as_slice(), true, &mut decoded).unwrap();
        assert_eq!(decoded, payload);

        let mut with_garbage = compressed.clone();
        with_garbage.extend_from_slice(b"not-gzip");
        assert!(copy_archive(with_garbage.as_slice(), true, &mut Vec::new()).is_err());
        assert!(copy_archive(b"".as_slice(), true, &mut Vec::new()).is_err());
        assert!(copy_archive(payload.as_slice(), true, &mut Vec::new()).is_err());
    }
}
