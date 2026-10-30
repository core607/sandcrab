#![forbid(unsafe_code)]
//! Native Sandcrab service and client; consumer-specific identities and extensions are absent.
mod auth;
mod call_client;
mod call_events;
mod client;
mod config;
mod event_client;
mod event_wire;
mod events;
mod file_access;
mod file_client;
mod file_io;
mod file_records;
mod files;
mod guest_call;
mod host_calls;
mod multipart;
mod opensandbox;
mod runtime;
mod sdk_commands;
mod sdk_download;
mod sdk_file_io;
mod sdk_files;
mod sdk_fs;
mod sdk_fs_io;
mod sdk_glob;
mod sdk_replace;
mod sdk_types;
mod server;
mod service;
mod session_resources;
mod sessions;
mod spec;
mod storage;
mod transport;
mod volumes;

use client::Endpoint;
use std::{
    io,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{Arc, atomic::AtomicBool},
};

const HELP: &str = "Sandcrab\n\nCommands:\n  sandcrab serve --config FILE\n  sandcrab check --config FILE\n  sandcrab info --socket PATH\n  sandcrab run --socket PATH --profile NAME [--timeout-ms N] [--stream] [--keep-result] [--memory-bytes N] [--cpu-percent N] -- COMMAND [ARG...]\n  sandcrab get|cancel|forget --socket PATH RUN_ID\n  sandcrab events --socket PATH RUN_ID [--after CURSOR]\n  sandcrab session open --socket PATH --profile NAME [--ttl-ms N] [--volume UUID] [--memory-bytes N] [--cpu-percent N]\n  sandcrab session shell --socket PATH PARENT_SESSION_ID\n  sandcrab session exec --socket PATH SESSION_ID [--timeout-ms N] [--stream] [--keep-result] -- SHELL_SOURCE\n  sandcrab session get|close|forget --socket PATH SESSION_ID\n  sandcrab session renew --socket PATH SESSION_ID --ttl-ms N\n  sandcrab volume create --socket PATH --profile NAME [--id UUID] [--clone-from UUID] [--bytes N] [--inodes N]\n  sandcrab volume list --socket PATH [--after UUID]\n  sandcrab volume get|delete|forget --socket PATH VOLUME_ID\n\nClient commands also accept --endpoint http://LOOPBACK:PORT in place of --socket PATH.\nUse sandcrab --token-file FILE COMMAND ... or SANDCRAB_TOKEN_FILE for TCP.\n\nserve requires root and the configured systemd unit. run uses the profile's isolated execution account.\n";

fn connection_flag(flag: &str) -> bool {
    matches!(flag, "--socket" | "--endpoint")
}

fn execute(args: &[String]) -> io::Result<i32> {
    let (token_file, args) = match args {
        [flag, path, rest @ ..] if flag == "--token-file" => (Some(PathBuf::from(path)), rest),
        _ => (
            std::env::var_os("SANDCRAB_TOKEN_FILE").map(PathBuf::from),
            args,
        ),
    };
    let token_file = token_file.as_deref();
    match args {
        [mode, flag] if mode == "call" && ["--help", "-h"].contains(&flag.as_str()) => {
            print!("{CALL_HELP}");
            Ok(0)
        }
        [mode, file, rest @ ..] if mode == "call" => {
            let timeout = numeric_option(rest, "--timeout-ms")?.unwrap_or(60000);
            guest_call::call(Path::new(file), timeout)
        }
        [] => {
            print!("{HELP}{FILE_HELP}{CALL_HELP}");
            Ok(0)
        }
        [flag] if ["--help", "-h"].contains(&flag.as_str()) => {
            print!("{HELP}{FILE_HELP}{CALL_HELP}");
            Ok(0)
        }
        [flag] if flag == "--version" => {
            println!("sandcrab {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        [mode, path] if mode == "__shell" => {
            sandcrab_shell::run(Path::new(path), "SANDBOX_EXECUTION_ID")?;
            Ok(0)
        }
        [mode, path] if mode == "__launch" => {
            runtime::launch(Path::new(path))?;
            Ok(0)
        }
        [mode, source, destination, pool] if mode == "__copy-tree" => {
            storage::copy_tree(Path::new(source), Path::new(destination), Path::new(pool))?;
            Ok(0)
        }
        [mode, path] if mode == "__file" => match file_io::execute(Path::new(path)) {
            Ok(value) => {
                println!("{value}");
                Ok(0)
            }
            Err(error) => {
                println!(
                    "{}",
                    serde_json::json!({"error":file_io::error_code(&error)})
                );
                eprintln!("{error}");
                Ok(1)
            }
        },
        [mode, flag, path] if ["serve", "check"].contains(&mode.as_str()) && flag == "--config" => {
            if rustix::process::geteuid().as_raw() != 0 {
                return Err(config::invalid(
                    "serve/check require root to validate protected configuration",
                ));
            }
            let config = config::Config::load(Path::new(path))?;
            if mode == "check" {
                println!("{{\"configurationValid\":true}}");
                return Ok(0);
            }
            let stopped = Arc::new(AtomicBool::new(false));
            let _signals = [
                signal_hook::flag::register(signal_hook::consts::SIGTERM, stopped.clone())?,
                signal_hook::flag::register(signal_hook::consts::SIGINT, stopped.clone())?,
            ];
            let runtime = runtime::Runtime::start(config)?;
            server::serve(Arc::new(service::Service::new(runtime, stopped)?))?;
            Ok(0)
        }
        [mode, flag, path] if mode == "info" && connection_flag(flag) => {
            println!(
                "{}",
                client::request(
                    &Endpoint::parse(flag, path, token_file)?,
                    "GET",
                    "/v1/info",
                    None
                )?
            );
            Ok(0)
        }
        [mode, flag, path, id]
            if ["get", "cancel", "forget"].contains(&mode.as_str()) && connection_flag(flag) =>
        {
            if !sandcrab_core::uuid(id) {
                return Err(config::invalid("RUN_ID must be a UUID"));
            }
            let (method, route, body) = if mode == "get" {
                ("GET", format!("/v1/runs/{id}"), None)
            } else {
                (
                    "POST",
                    format!("/v1/runs/{id}/{mode}"),
                    Some(serde_json::json!({})),
                )
            };
            println!(
                "{}",
                client::request(
                    &Endpoint::parse(flag, path, token_file)?,
                    method,
                    &route,
                    body.as_ref()
                )?
            );
            Ok(0)
        }
        [mode, flag, socket, id, rest @ ..]
            if mode == "events" && connection_flag(flag) && sandcrab_core::uuid(id) =>
        {
            let after = match rest {
                [] => None,
                [flag, cursor] if flag == "--after" => Some(cursor.as_str()),
                _ => {
                    return Err(config::invalid(
                        "Expected events --socket PATH RUN_ID [--after CURSOR]",
                    ));
                }
            };
            event_client::events(&Endpoint::parse(flag, socket, token_file)?, id, after)
        }
        [mode, rest @ ..] if mode == "run" => run(rest, token_file),
        [mode, rest @ ..] if mode == "session" => session(rest, token_file),
        [mode, rest @ ..] if mode == "volume" => volume(rest, token_file),
        [mode, rest @ ..] if mode == "files" => file_command(rest, token_file),
        [mode, rest @ ..] if mode == "calls" => call_command(rest, token_file),
        _ => Err(config::invalid(HELP)),
    }
}
const CALL_HELP: &str = "\nHost calls:\n  sandcrab call FILE [--timeout-ms N]\n  sandcrab calls list --socket PATH RUN_ID\n  sandcrab calls events --socket PATH RUN_ID [--after CURSOR]\n  sandcrab calls reply --socket PATH RUN_ID CALL_ID FILE\n\ncall runs inside a profile with host_calls enabled. Input and replies are raw bytes, at most 65536 bytes. FILE - reads stdin.\nHost commands also accept --endpoint URL. Callers authorize outside actions and reconcile repeated request IDs.\n";

fn call_command(args: &[String], token_file: Option<&Path>) -> io::Result<i32> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    if matches!(args, [flag] if ["--help","-h"].contains(&flag.as_str())) {
        print!("{CALL_HELP}");
        return Ok(0);
    }
    let [mode, flag, address, id, rest @ ..] = args else {
        return Err(config::invalid(CALL_HELP));
    };
    if !connection_flag(flag) || !sandcrab_core::uuid(id) {
        return Err(config::invalid(CALL_HELP));
    }
    let endpoint = Endpoint::parse(flag, address, token_file)?;
    match (mode.as_str(), rest) {
        ("list", []) => {
            println!(
                "{}",
                client::request(&endpoint, "GET", &format!("/v1/runs/{id}/calls"), None)?
            );
            Ok(0)
        }
        ("events", []) => call_client::events(&endpoint, id, None),
        ("events", [flag, cursor]) if flag == "--after" => {
            call_client::events(&endpoint, id, Some(cursor))
        }
        ("reply", [request, file]) if sandcrab_core::uuid(request) => {
            let bytes = guest_call::input(Path::new(file))?;
            println!(
                "{}",
                client::request(
                    &endpoint,
                    "POST",
                    &format!("/v1/runs/{id}/calls/{request}/reply"),
                    Some(&serde_json::json!({"base64":STANDARD.encode(bytes)}))
                )?
            );
            Ok(0)
        }
        _ => Err(config::invalid(CALL_HELP)),
    }
}

fn run(args: &[String], token_file: Option<&Path>) -> io::Result<i32> {
    let split = args
        .iter()
        .position(|s| s == "--")
        .ok_or_else(|| config::invalid("run requires -- before COMMAND"))?;
    let (options, command) = (&args[..split], &args[split + 1..]);
    let (mut socket, mut profile, mut timeout, mut streaming, mut keep_result) =
        (None, None, None, false, false);
    let mut resources = config::Resources::default();
    let mut options = options.iter();
    while let Some(key) = options.next() {
        if key == "--keep-result" && !keep_result {
            keep_result = true;
            continue;
        }
        if key == "--stream" && !streaming {
            streaming = true;
            continue;
        }
        let value = options
            .next()
            .ok_or_else(|| config::invalid("This run option needs a value"))?;
        match key.as_str() {
            "--socket" | "--endpoint" if socket.is_none() => socket = Some((key, value)),
            "--profile" if profile.is_none() => profile = Some(value),
            "--timeout-ms" if timeout.is_none() => {
                timeout = Some(
                    value
                        .parse()
                        .map_err(|_| config::invalid("Invalid timeout"))?,
                )
            }
            _ => {
                if !resource_option(&mut resources, key, value)? {
                    return Err(config::invalid(format!(
                        "Unknown or repeated option: {key}"
                    )));
                }
            }
        }
    }
    if command.is_empty() {
        return Err(config::invalid("COMMAND is required"));
    }
    let (flag, value) =
        socket.ok_or_else(|| config::invalid("--socket or --endpoint is required"))?;
    client::run(
        &Endpoint::parse(flag, value, token_file)?,
        profile.ok_or_else(|| config::invalid("--profile is required"))?,
        command,
        timeout,
        streaming,
        keep_result,
        resources,
    )
}
fn session(args: &[String], token_file: Option<&Path>) -> io::Result<i32> {
    match args {
        [mode, flag, socket, profile_flag, profile, rest @ ..]
            if mode == "open" && connection_flag(flag) && profile_flag == "--profile" =>
        {
            let (mut ttl, mut volume) = (None, None);
            let mut resources = config::Resources::default();
            for pair in rest.chunks(2) {
                match pair {
                    [key, _] if key == "--ttl-ms" && ttl.is_none() => {
                        ttl = numeric_option(pair, "--ttl-ms")?
                    }
                    [key, value]
                        if key == "--volume" && volume.is_none() && sandcrab_core::uuid(value) =>
                    {
                        volume = Some(value.as_str())
                    }
                    [key, value] if resource_option(&mut resources, key, value)? => (),
                    _ => {
                        return Err(config::invalid(
                            "Expected unique --ttl-ms N, --volume UUID, --memory-bytes N or --cpu-percent N options",
                        ));
                    }
                }
            }
            client::open_session(
                &Endpoint::parse(flag, socket, token_file)?,
                profile,
                ttl,
                volume,
                resources,
            )
        }
        [mode, flag, socket, id, rest @ ..] if connection_flag(flag) && sandcrab_core::uuid(id) => {
            let endpoint = Endpoint::parse(flag, socket, token_file)?;
            let socket = &endpoint;
            let path = format!("/v1/sessions/{id}");
            match mode.as_str() {
                "shell" if rest.is_empty() => client::open_shell(socket, id),
                "exec" => {
                    let split = rest.iter().position(|v| v == "--").ok_or_else(|| {
                        config::invalid("session exec requires -- before one shell source argument")
                    })?;
                    let [source] = &rest[split + 1..] else {
                        return Err(config::invalid("Pass one quoted shell source argument"));
                    };
                    let (timeout, streaming, keep_result) = command_options(&rest[..split])?;
                    client::execute_session(socket, id, source, timeout, streaming, keep_result)
                }
                "renew" => {
                    let ttl = numeric_option(rest, "--ttl-ms")?
                        .ok_or_else(|| config::invalid("--ttl-ms is required"))?;
                    println!(
                        "{}",
                        client::request(
                            socket,
                            "POST",
                            &format!("{path}/renew"),
                            Some(&serde_json::json!({"ttlMillis":ttl}))
                        )?
                    );
                    Ok(0)
                }
                "get" if rest.is_empty() => {
                    println!("{}", client::request(socket, "GET", &path, None)?);
                    Ok(0)
                }
                "close" | "forget" if rest.is_empty() => {
                    let result = client::request(
                        socket,
                        "POST",
                        &format!("{path}/{mode}"),
                        Some(&serde_json::json!({})),
                    )?;
                    if mode == "close" {
                        client::wait_session(socket, id, false)
                    } else {
                        println!("{result}");
                        Ok(0)
                    }
                }
                _ => Err(config::invalid(HELP)),
            }
        }
        _ => Err(config::invalid(HELP)),
    }
}
fn resource_option(resources: &mut config::Resources, key: &str, value: &str) -> io::Result<bool> {
    let target = match key {
        "--memory-bytes" => &mut resources.memory_bytes,
        "--cpu-percent" => &mut resources.cpu_quota_percent,
        _ => return Ok(false),
    };
    if target.is_some() {
        return Err(config::invalid(format!("Repeated resource option: {key}")));
    }
    *target = Some(
        value
            .parse()
            .map_err(|_| config::invalid(format!("Invalid value for {key}")))?,
    );
    Ok(true)
}
fn command_options(args: &[String]) -> io::Result<(Option<u64>, bool, bool)> {
    let (mut timeout, mut streaming, mut keep_result) = (None, false, false);
    let mut values = args.iter();
    while let Some(key) = values.next() {
        match key.as_str() {
            "--stream" if !streaming => streaming = true,
            "--keep-result" if !keep_result => keep_result = true,
            "--timeout-ms" if timeout.is_none() => {
                timeout = Some(
                    values
                        .next()
                        .ok_or_else(|| config::invalid("--timeout-ms requires a value"))?
                        .parse()
                        .map_err(|_| config::invalid("Invalid timeout"))?,
                );
            }
            _ => {
                return Err(config::invalid(
                    "Expected unique --stream, --keep-result and --timeout-ms N options",
                ));
            }
        }
    }
    Ok((timeout, streaming, keep_result))
}
fn volume(args: &[String], token_file: Option<&Path>) -> io::Result<i32> {
    let [mode, flag, socket, rest @ ..] = args else {
        return Err(config::invalid(HELP));
    };
    if !connection_flag(flag) {
        return Err(config::invalid(HELP));
    }
    let endpoint = Endpoint::parse(flag, socket, token_file)?;
    let socket = &endpoint;
    if mode == "create" {
        let mut options = std::collections::BTreeMap::new();
        for pair in rest.chunks(2) {
            let [key, value] = pair else {
                return Err(config::invalid("Every volume option needs a value"));
            };
            if !["--id", "--profile", "--clone-from", "--bytes", "--inodes"].contains(&key.as_str())
                || options.insert(key.as_str(), value.as_str()).is_some()
            {
                return Err(config::invalid("Unknown or repeated volume option"));
            }
        }
        let number = |key: &str| {
            options
                .get(key)
                .map(|v| {
                    v.parse::<u64>()
                        .map_err(|_| config::invalid("Invalid volume limit"))
                })
                .transpose()
        };
        let plan = storage::Plan {
            id: match options.get("--id") {
                Some(id) => id.to_string(),
                None => sandcrab_core::new_uuid()?,
            },
            profile: options
                .get("--profile")
                .ok_or_else(|| config::invalid("--profile is required"))?
                .to_string(),
            clone_from: options.get("--clone-from").map(|s| s.to_string()),
            byte_limit: number("--bytes")?,
            inode_limit: number("--inodes")?,
        };
        if !sandcrab_core::uuid(&plan.id)
            || plan
                .clone_from
                .as_ref()
                .is_some_and(|s| !sandcrab_core::uuid(s))
        {
            return Err(config::invalid("Volume IDs must be UUIDs"));
        }
        return client::create_volume(socket, plan);
    }
    if mode == "list" {
        let path = match rest {
            [] => "/v1/volumes".into(),
            [key, id] if key == "--after" && sandcrab_core::uuid(id) => {
                format!("/v1/volumes?after={id}")
            }
            _ => return Err(config::invalid("Expected optional --after UUID")),
        };
        println!("{}", client::request(socket, "GET", &path, None)?);
        return Ok(0);
    }
    let [id] = rest else {
        return Err(config::invalid(HELP));
    };
    if !sandcrab_core::uuid(id) {
        return Err(config::invalid("VOLUME_ID must be a UUID"));
    }
    let path = format!("/v1/volumes/{id}");
    match mode.as_str() {
        "get" => {
            println!("{}", client::request(socket, "GET", &path, None)?);
            Ok(0)
        }
        "delete" | "forget" => {
            let result = client::request(
                socket,
                "POST",
                &format!("{path}/{mode}"),
                Some(&serde_json::json!({})),
            )?;
            if mode == "delete" {
                client::wait_volume(socket, id, false)
            } else {
                println!("{result}");
                Ok(0)
            }
        }
        _ => Err(config::invalid(HELP)),
    }
}
fn numeric_option(args: &[String], name: &str) -> io::Result<Option<u64>> {
    match args {
        [] => Ok(None),
        [key, value] if key == name => value
            .parse()
            .map(Some)
            .map_err(|_| config::invalid(format!("Invalid {name}"))),
        _ => Err(config::invalid(format!("Expected {name} VALUE"))),
    }
}

const FILE_HELP: &str = "\nFiles:\n  sandcrab files put --socket PATH SESSION_ID LOCAL_FILE WORKSPACE_PATH [--tar] [--replace] [--no-freeze] [--id UUID] [--mode OCTAL] [--keep-result]\n  sandcrab files get --socket PATH SESSION_ID WORKSPACE_PATH LOCAL_FILE [--tar] [--replace] [--no-freeze]\n  sandcrab files status|cancel|forget --socket PATH UPLOAD_ID\n  sandcrab files list --socket PATH [--after UUID]\n\nget writes raw bytes to stdout when LOCAL_FILE is -. Existing destinations require --replace.\n";
fn file_command(args: &[String], token_file: Option<&Path>) -> io::Result<i32> {
    use file_io::Format;
    match args {
        [flag] if ["--help", "-h"].contains(&flag.as_str()) => {
            print!("{FILE_HELP}");
            Ok(0)
        }
        [mode, flag, socket, id]
            if ["status", "cancel", "forget"].contains(&mode.as_str())
                && connection_flag(flag)
                && sandcrab_core::uuid(id) =>
        {
            let (method, path, body) = if mode == "status" {
                ("GET", format!("/v1/uploads/{id}"), None)
            } else {
                (
                    "POST",
                    format!("/v1/uploads/{id}/{mode}"),
                    Some(serde_json::json!({})),
                )
            };
            println!(
                "{}",
                client::request(
                    &Endpoint::parse(flag, socket, token_file)?,
                    method,
                    &path,
                    body.as_ref()
                )?
            );
            Ok(0)
        }
        [mode, flag, socket, rest @ ..] if mode == "list" && connection_flag(flag) => {
            let path = match rest {
                [] => "/v1/uploads".into(),
                [flag, id] if flag == "--after" && sandcrab_core::uuid(id) => {
                    format!("/v1/uploads?after={id}")
                }
                _ => return Err(config::invalid("Expected optional --after UUID")),
            };
            println!(
                "{}",
                client::request(
                    &Endpoint::parse(flag, socket, token_file)?,
                    "GET",
                    &path,
                    None
                )?
            );
            Ok(0)
        }
        [mode, flag, socket, session, source, destination, rest @ ..]
            if ["put", "get"].contains(&mode.as_str())
                && connection_flag(flag)
                && sandcrab_core::uuid(session) =>
        {
            let (mut format, mut replace, mut freeze, mut keep, mut id, mut permissions) =
                (Format::Raw, false, true, false, None, None);
            let mut args = rest.iter();
            let mut seen = std::collections::BTreeSet::new();
            while let Some(flag) = args.next() {
                if !seen.insert(flag) {
                    return Err(config::invalid("Repeated file option"));
                }
                match flag.as_str() {
                    "--tar" => format = Format::Tar,
                    "--replace" => replace = true,
                    "--no-freeze" => freeze = false,
                    "--keep-result" if mode == "put" => keep = true,
                    "--id" if mode == "put" => {
                        id = Some(
                            args.next()
                                .filter(|s| sandcrab_core::uuid(s))
                                .ok_or_else(|| config::invalid("--id requires a UUID"))?
                                .clone(),
                        )
                    }
                    "--mode" if mode == "put" => {
                        let value = args
                            .next()
                            .ok_or_else(|| config::invalid("--mode requires octal permissions"))?;
                        permissions = Some(
                            u32::from_str_radix(value, 8)
                                .ok()
                                .filter(|m| *m <= 0o777)
                                .ok_or_else(|| config::invalid("--mode must be 000..777"))?,
                        );
                    }
                    _ => return Err(config::invalid("Unknown file option")),
                }
            }
            if mode == "put" {
                file_client::put(
                    &Endpoint::parse(flag, socket, token_file)?,
                    session,
                    Path::new(source),
                    destination,
                    file_client::Put {
                        id,
                        format,
                        replace,
                        freeze,
                        mode: permissions,
                        keep_result: keep,
                    },
                )
            } else {
                file_client::get(
                    &Endpoint::parse(flag, socket, token_file)?,
                    session,
                    source,
                    Path::new(destination),
                    file_client::Get {
                        format,
                        freeze,
                        replace,
                    },
                )
            }
        }
        _ => Err(config::invalid(FILE_HELP)),
    }
}

fn main() -> ExitCode {
    match execute(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok(code) => ExitCode::from(code as u8),
        Err(error) => {
            eprintln!("sandcrab: {error}");
            ExitCode::FAILURE
        }
    }
}
