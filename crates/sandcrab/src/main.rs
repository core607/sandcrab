#![forbid(unsafe_code)]
//! Native Sandcrab service and client; consumer-specific identities and extensions are absent.
mod auth;
mod call_client;
mod call_events;
mod cli;
mod client;
mod config;
mod delegation;
mod diff;
mod doctor;
mod egress;
mod event_client;
mod event_wire;
mod events;
mod file_access;
mod file_client;
mod file_io;
mod file_records;
mod file_stream;
mod files;
mod guest_call;
mod helper;
mod host_calls;
mod installer;
mod inventory;
mod multipart;
mod opensandbox;
mod overlay;
mod queue;
mod recipes;
mod rootfs;
mod runtime;
mod sdk_commands;
mod sdk_contexts;
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
mod template_api;
mod template_client;
mod template_io;
mod template_layers;
mod templates;
mod transport;
mod usage;
mod volumes;
mod workspaces;

use cli::{ClientArgs, Connection, Env};
use client::Endpoint;
use std::{
    io,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{Arc, atomic::AtomicBool},
};

const HELP: &str = "Sandcrab\n\nCommands:\n  sandcrab install [--dry-run] [--upgrade]\n  sandcrab upgrade [--dry-run]\n  sandcrab uninstall [--dry-run]\n  sandcrab client-token --user USER --output FILE [--config FILE] [--replace]\n  sandcrab doctor [--config FILE]\n  sandcrab serve --config FILE | --container\n  sandcrab check --config FILE\n  sandcrab info [--socket PATH]\n  sandcrab run [--socket PATH] [--profile NAME] [--timeout-ms DURATION] [--stream] [--keep-result] [--memory-bytes BYTES] [--cpu-percent N] -- COMMAND [ARG...]\n  sandcrab list [--socket PATH] [--after UUID]\n  sandcrab get|cancel|forget [--socket PATH] RUN_ID\n  sandcrab events [--socket PATH] RUN_ID [--after CURSOR]\n  sandcrab session open [--socket PATH] [--profile NAME] [--ttl-ms DURATION] [--keep-result] [--volume UUID | --template SHA256] [--rootfs] [--memory-bytes BYTES] [--cpu-percent N]\n  sandcrab session shell [--socket PATH] PARENT_SESSION_ID [--keep-result]\n  sandcrab session exec [--socket PATH] SESSION_ID [--timeout-ms DURATION] [--stream] [--keep-result] -- SHELL_SOURCE\n  sandcrab session list [--socket PATH] [--after UUID]\n  sandcrab session get|close|forget [--socket PATH] SESSION_ID\n  sandcrab session renew [--socket PATH] SESSION_ID --ttl-ms DURATION\n  sandcrab session diff [--socket PATH] SESSION_ID DESTINATION [--replace]\n  sandcrab template --help\n  sandcrab volume create [--socket PATH] [--profile NAME] [--id UUID] [--clone-from UUID] [--bytes BYTES] [--inodes N]\n  sandcrab volume list [--socket PATH] [--after UUID]\n  sandcrab volume get|delete|forget [--socket PATH] VOLUME_ID\n\nClient commands accept --socket PATH or --endpoint http://LOOPBACK:PORT anywhere before --, or SANDCRAB_SOCKET / SANDCRAB_ENDPOINT.\nProfile commands fall back to SANDCRAB_PROFILE. Pass --token-file FILE anywhere before -- or set SANDCRAB_TOKEN_FILE for TCP.\nQuantities accept plain integers or suffixes (e.g. 32Mi, 1Gi, 30s, 5m; --memory and --cpu/--timeout/--ttl aliases).\n\nserve requires root and a bounded delegated cgroup v2 subtree. run uses the profile's isolated execution account.\n";

fn parse_install_flags(args: &[String], allow_upgrade: bool) -> io::Result<(bool, bool)> {
    let (mut dry_run, mut upgrade) = (false, false);
    for flag in args {
        match flag.as_str() {
            "--dry-run" if !dry_run => dry_run = true,
            "--upgrade" if allow_upgrade && !upgrade => upgrade = true,
            _ => return Err(config::invalid(HELP)),
        }
    }
    Ok((dry_run, upgrade))
}

fn parse_guest_call(args: &[String]) -> io::Result<(&str, u64)> {
    let (mut file, mut timeout) = (None, None);
    let mut iter = args.iter();
    while let Some(item) = iter.next() {
        match item.as_str() {
            "--timeout-ms" | "--timeout" if timeout.is_none() => {
                let value = iter
                    .next()
                    .ok_or_else(|| config::invalid(format!("{item} requires a duration")))?;
                timeout = Some(cli::parse_millis(value)?);
            }
            flag if flag.starts_with('-') && flag != "-" => return Err(config::invalid(CALL_HELP)),
            path if file.is_none() => file = Some(path),
            _ => return Err(config::invalid(CALL_HELP)),
        }
    }
    Ok((
        file.ok_or_else(|| config::invalid(CALL_HELP))?,
        timeout.unwrap_or(60_000),
    ))
}

fn execute(args: &[String]) -> io::Result<i32> {
    match args {
        [mode, path] if mode == "__shell" => {
            sandcrab_shell::run(Path::new(path), "SANDBOX_EXECUTION_ID")?;
            return Ok(0);
        }
        [mode, path] if mode == "__launch" => {
            runtime::launch(Path::new(path))?;
            return Ok(0);
        }
        [mode, path] if mode == "__helper" => {
            helper::launch(Path::new(path))?;
            return Ok(0);
        }
        [mode] if mode == "__overlay-export" => {
            overlay::export()?;
            return Ok(0);
        }
        [mode, source, destination, pool] if mode == "__copy-tree" => {
            storage::copy_tree(Path::new(source), Path::new(destination), Path::new(pool))?;
            return Ok(0);
        }
        [mode, path] if ["__file", "__template-layer"].contains(&mode.as_str()) => {
            return match file_io::execute(Path::new(path), mode == "__template-layer") {
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
            };
        }
        [] => {
            print!("{HELP}{FILE_HELP}{CALL_HELP}");
            return Ok(0);
        }
        [flag] if ["--help", "-h"].contains(&flag.as_str()) => {
            print!("{HELP}{FILE_HELP}{CALL_HELP}");
            return Ok(0);
        }
        [flag] if flag == "--version" => {
            println!("sandcrab {}", env!("CARGO_PKG_VERSION"));
            return Ok(0);
        }
        [mode, rest @ ..] if mode == "install" => {
            let (dry_run, upgrade) = parse_install_flags(rest, true)?;
            installer::install(dry_run, false, upgrade)?;
            return Ok(0);
        }
        [mode, rest @ ..] if mode == "upgrade" => {
            let (dry_run, _) = parse_install_flags(rest, false)?;
            installer::install(dry_run, false, true)?;
            return Ok(0);
        }
        [mode, rest @ ..] if mode == "uninstall" => {
            let (dry_run, _) = parse_install_flags(rest, false)?;
            installer::uninstall(dry_run)?;
            return Ok(0);
        }
        [mode, rest @ ..] if mode == "client-token" => {
            installer::client_token(rest)?;
            return Ok(0);
        }
        [mode] if mode == "doctor" => return doctor::doctor(Path::new(installer::CONFIG)),
        [mode, flag, path] if mode == "doctor" && flag == "--config" => {
            return doctor::doctor(Path::new(path));
        }
        [mode, flag] if mode == "serve" && flag == "--container" => {
            installer::install(false, true, false)?;
            return execute(&["serve".into(), "--config".into(), installer::CONFIG.into()]);
        }
        [mode, flag] if mode == "call" && ["--help", "-h"].contains(&flag.as_str()) => {
            print!("{CALL_HELP}");
            return Ok(0);
        }
        [mode, rest @ ..] if mode == "call" => {
            let (file, timeout) = parse_guest_call(rest)?;
            return guest_call::call(Path::new(file), timeout);
        }
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
            // Mounts left by an older host-namespace daemon need that owner's
            // cleanup. Unsharing first would hide the host's retained references.
            storage::no_mounts_below(&config.service.runtime_root, true).map_err(|_| {
                config::invalid("Runtime has host-visible submounts; reconcile them with the previous service before starting the mount-isolated daemon")
            })?;
            // Preserve the verified path before cloning a service manager's
            // mount namespace: /proc/self/exe can then name a detached mount.
            let executable = std::env::current_exe()?.canonicalize()?;
            sandcrab_launch::trusted_executable(&executable).map_err(io::Error::other)?;
            sandcrab_core::process::private_mount_namespace()?;
            let stopped = Arc::new(AtomicBool::new(false));
            let _signals = [
                signal_hook::flag::register(signal_hook::consts::SIGTERM, stopped.clone())?,
                signal_hook::flag::register(signal_hook::consts::SIGINT, stopped.clone())?,
            ];
            let runtime = runtime::Runtime::start(config, executable)?;
            server::serve(Arc::new(service::Service::new(runtime, stopped)?))?;
            return Ok(0);
        }
        _ => {}
    }

    let parsed = ClientArgs::parse(args)?;
    let env = Env::from_process()?;
    let command_tail = parsed.command;
    match parsed.args.as_slice() {
        [mode] if mode == "info" && command_tail.is_none() => {
            println!(
                "{}",
                client::request(&parsed.connection.endpoint(&env)?, "GET", "/v1/info", None)?
            );
            Ok(0)
        }
        [mode, rest @ ..] if mode == "list" && command_tail.is_none() => {
            list_records("runs", &parsed.connection.endpoint(&env)?, rest)
        }
        [mode, id]
            if ["get", "cancel", "forget"].contains(&mode.as_str()) && command_tail.is_none() =>
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
                    &parsed.connection.endpoint(&env)?,
                    method,
                    &route,
                    body.as_ref()
                )?
            );
            Ok(0)
        }
        [mode, rest @ ..] if mode == "events" && command_tail.is_none() => {
            let (id, after) = parse_id_and_after(
                rest,
                "Expected events [--socket PATH] RUN_ID [--after CURSOR]",
            )?;
            event_client::events(&parsed.connection.endpoint(&env)?, id, after)
        }
        [mode, rest @ ..] if mode == "run" => run(rest, command_tail, &parsed.connection, &env),
        [mode, rest @ ..] if mode == "session" => {
            session(rest, command_tail, &parsed.connection, &env)
        }
        [mode, rest @ ..] if mode == "volume" && command_tail.is_none() => {
            volume(rest, &parsed.connection, &env)
        }
        [mode, rest @ ..] if mode == "files" && command_tail.is_none() => {
            file_command(rest, &parsed.connection, &env)
        }
        [mode, rest @ ..] if mode == "template" && command_tail.is_none() => {
            template_client::command(rest, &parsed.connection, &env)
        }
        [mode, rest @ ..] if mode == "calls" && command_tail.is_none() => {
            call_command(rest, &parsed.connection, &env)
        }
        _ => Err(config::invalid(HELP)),
    }
}

fn parse_id_and_after<'a>(
    args: &'a [String],
    usage: &str,
) -> io::Result<(&'a str, Option<&'a str>)> {
    let (mut id, mut after) = (None, None);
    let mut iter = args.iter();
    while let Some(item) = iter.next() {
        if item == "--after" && after.is_none() {
            after = Some(iter.next().ok_or_else(|| config::invalid(usage))?.as_str());
        } else if !item.starts_with('-') && id.is_none() && sandcrab_core::uuid(item) {
            id = Some(item.as_str());
        } else {
            return Err(config::invalid(usage));
        }
    }
    Ok((id.ok_or_else(|| config::invalid(usage))?, after))
}

const CALL_HELP: &str = "\nHost calls:\n  sandcrab call FILE [--timeout-ms DURATION]\n  sandcrab calls list [--socket PATH] RUN_ID\n  sandcrab calls events [--socket PATH] RUN_ID [--after CURSOR]\n  sandcrab calls reply [--socket PATH] RUN_ID CALL_ID FILE\n\ncall runs inside a profile with host_calls enabled. Input and replies are raw bytes, at most 65536 bytes. FILE - reads stdin.\nHost commands also accept --endpoint URL or SANDCRAB_SOCKET / SANDCRAB_ENDPOINT. Callers authorize outside actions and reconcile repeated request IDs.\n";

fn call_command(args: &[String], connection: &Connection, env: &Env) -> io::Result<i32> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    if matches!(args, [flag] if ["--help", "-h"].contains(&flag.as_str())) {
        print!("{CALL_HELP}");
        return Ok(0);
    }
    let [mode, rest @ ..] = args else {
        return Err(config::invalid(CALL_HELP));
    };
    let endpoint = connection.endpoint(env)?;
    match (mode.as_str(), rest) {
        ("list", [id]) if sandcrab_core::uuid(id) => {
            println!(
                "{}",
                client::request(&endpoint, "GET", &format!("/v1/runs/{id}/calls"), None)?
            );
            Ok(0)
        }
        ("events", rest) => {
            let (id, after) = parse_id_and_after(rest, CALL_HELP)?;
            call_client::events(&endpoint, id, after)
        }
        ("reply", [id, request, file])
            if sandcrab_core::uuid(id) && sandcrab_core::uuid(request) =>
        {
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

fn run(
    options: &[String],
    command: Option<&[String]>,
    connection: &Connection,
    env: &Env,
) -> io::Result<i32> {
    let command = command.ok_or_else(|| config::invalid("run requires -- before COMMAND"))?;
    let (mut profile, mut timeout, mut streaming, mut keep_result) = (None, None, false, false);
    let mut resources = config::Resources::default();
    let mut iter = options.iter();
    while let Some(key) = iter.next() {
        if key == "--keep-result" && !keep_result {
            keep_result = true;
            continue;
        }
        if key == "--stream" && !streaming {
            streaming = true;
            continue;
        }
        let value = iter
            .next()
            .ok_or_else(|| config::invalid("This run option needs a value"))?;
        match key.as_str() {
            "--profile" if profile.is_none() => profile = Some(value.as_str()),
            "--timeout-ms" | "--timeout" if timeout.is_none() => {
                timeout = Some(cli::parse_millis(value)?)
            }
            _ => {
                if !cli::resource_option(&mut resources, key, value)? {
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
    let endpoint = connection.endpoint(env)?;
    let profile = cli::resolve_profile(profile, env)?;
    client::run(
        &endpoint,
        &profile,
        command,
        timeout,
        streaming,
        keep_result,
        resources,
    )
}

fn session(
    args: &[String],
    command_tail: Option<&[String]>,
    connection: &Connection,
    env: &Env,
) -> io::Result<i32> {
    let [mode, rest @ ..] = args else {
        return Err(config::invalid(HELP));
    };
    match mode.as_str() {
        "list" if command_tail.is_none() => {
            list_records("sessions", &connection.endpoint(env)?, rest)
        }
        "open" if command_tail.is_none() => {
            let (mut profile, mut ttl, mut volume, mut template) = (None, None, None, None);
            let mut rootfs = false;
            let mut keep_result = false;
            let mut resources = config::Resources::default();
            let mut options = rest.iter();
            while let Some(key) = options.next() {
                if key == "--keep-result" && !keep_result {
                    keep_result = true;
                    continue;
                }
                if key == "--rootfs" && !rootfs {
                    rootfs = true;
                    continue;
                }
                let value = options
                    .next()
                    .ok_or_else(|| config::invalid("Missing session option value"))?;
                match key.as_str() {
                    "--profile" if profile.is_none() => profile = Some(value.as_str()),
                    "--ttl-ms" | "--ttl" if ttl.is_none() => ttl = Some(cli::parse_millis(value)?),
                    "--volume" if volume.is_none() && sandcrab_core::uuid(value) => {
                        volume = Some(value.as_str());
                    }
                    "--template" if template.is_none() && file_io::digest(value) => {
                        template = Some(value.as_str());
                    }
                    _ if cli::resource_option(&mut resources, key, value)? => (),
                    _ => return Err(config::invalid("Expected unique session options")),
                }
            }
            if volume.is_some() && template.is_some() {
                return Err(config::invalid("Choose either --volume or --template"));
            }
            if rootfs && template.is_none() {
                return Err(config::invalid("--rootfs requires --template"));
            }
            let profile = cli::resolve_profile(profile, env)?;
            client::open_session(
                &connection.endpoint(env)?,
                &profile,
                ttl,
                volume,
                template.map(|id| (id, rootfs)),
                resources,
                keep_result,
            )
        }
        "exec" => {
            let tail = command_tail.ok_or_else(|| {
                config::invalid("session exec requires -- before one shell source argument")
            })?;
            let [source] = tail else {
                return Err(config::invalid("Pass one quoted shell source argument"));
            };
            let (id, timeout, streaming, keep_result) = session_exec_options(rest)?;
            client::execute_session(
                &connection.endpoint(env)?,
                id,
                source,
                timeout,
                streaming,
                keep_result,
            )
        }
        "shell" if command_tail.is_none() => {
            let (mut id, mut keep_result) = (None, false);
            for item in rest {
                if item == "--keep-result" && !keep_result {
                    keep_result = true;
                } else if !item.starts_with('-') && id.is_none() && sandcrab_core::uuid(item) {
                    id = Some(item.as_str());
                } else {
                    return Err(config::invalid(HELP));
                }
            }
            let id = id.ok_or_else(|| config::invalid(HELP))?;
            client::open_shell(&connection.endpoint(env)?, id, keep_result)
        }
        "renew" if command_tail.is_none() => {
            let (mut id, mut ttl) = (None, None);
            let mut iter = rest.iter();
            while let Some(item) = iter.next() {
                match item.as_str() {
                    "--ttl-ms" | "--ttl" if ttl.is_none() => {
                        let value = iter
                            .next()
                            .ok_or_else(|| config::invalid("--ttl-ms requires a duration"))?;
                        ttl = Some(cli::parse_millis(value)?);
                    }
                    _ if !item.starts_with('-') && id.is_none() && sandcrab_core::uuid(item) => {
                        id = Some(item.as_str());
                    }
                    _ => return Err(config::invalid(HELP)),
                }
            }
            let id = id.ok_or_else(|| config::invalid(HELP))?;
            let ttl = ttl.ok_or_else(|| config::invalid("--ttl-ms is required"))?;
            println!(
                "{}",
                client::request(
                    &connection.endpoint(env)?,
                    "POST",
                    &format!("/v1/sessions/{id}/renew"),
                    Some(&serde_json::json!({"ttlMillis":ttl}))
                )?
            );
            Ok(0)
        }
        "diff" if command_tail.is_none() => {
            let mut replace = false;
            let mut positional = Vec::new();
            for item in rest {
                if item == "--replace" && !replace {
                    replace = true;
                } else if !item.starts_with('-') || item == "-" {
                    positional.push(item.as_str());
                } else {
                    return Err(config::invalid(
                        "Expected session diff [--socket PATH] SESSION_ID DESTINATION [--replace]",
                    ));
                }
            }
            let [id, destination] = positional.as_slice() else {
                return Err(config::invalid(
                    "Expected session diff [--socket PATH] SESSION_ID DESTINATION [--replace]",
                ));
            };
            if !sandcrab_core::uuid(id) {
                return Err(config::invalid(
                    "Expected session diff [--socket PATH] SESSION_ID DESTINATION [--replace]",
                ));
            }
            file_client::difference(
                &connection.endpoint(env)?,
                id,
                Path::new(destination),
                replace,
            )
        }
        "get" | "close" | "forget" if command_tail.is_none() => {
            let [id] = rest else {
                return Err(config::invalid(HELP));
            };
            if !sandcrab_core::uuid(id) {
                return Err(config::invalid(HELP));
            }
            let endpoint = connection.endpoint(env)?;
            let path = format!("/v1/sessions/{id}");
            if mode == "get" {
                println!("{}", client::request(&endpoint, "GET", &path, None)?);
                return Ok(0);
            }
            let result = client::request(
                &endpoint,
                "POST",
                &format!("{path}/{mode}"),
                Some(&serde_json::json!({})),
            )?;
            if mode == "close" {
                client::wait_session(&endpoint, id, false)
            } else {
                println!("{result}");
                Ok(0)
            }
        }
        _ => Err(config::invalid(HELP)),
    }
}

fn list_records(collection: &str, endpoint: &Endpoint, args: &[String]) -> io::Result<i32> {
    let path = match args {
        [] => format!("/v1/{collection}"),
        [flag, id] if flag == "--after" && sandcrab_core::uuid(id) => {
            format!("/v1/{collection}?after={id}")
        }
        _ => {
            return Err(config::invalid(
                "Expected list [--socket PATH] [--after UUID]",
            ));
        }
    };
    println!("{}", client::request(endpoint, "GET", &path, None)?);
    Ok(0)
}

fn session_exec_options(args: &[String]) -> io::Result<(&str, Option<u64>, bool, bool)> {
    let (mut id, mut timeout, mut streaming, mut keep_result) = (None, None, false, false);
    let mut values = args.iter();
    while let Some(key) = values.next() {
        match key.as_str() {
            "--stream" if !streaming => streaming = true,
            "--keep-result" if !keep_result => keep_result = true,
            "--timeout-ms" | "--timeout" if timeout.is_none() => {
                let raw = values
                    .next()
                    .ok_or_else(|| config::invalid(format!("{key} requires a value")))?;
                timeout = Some(cli::parse_millis(raw)?);
            }
            _ if !key.starts_with('-') && id.is_none() && sandcrab_core::uuid(key) => {
                id = Some(key.as_str());
            }
            _ => {
                return Err(config::invalid(
                    "Expected SESSION_ID with unique --stream, --keep-result and --timeout-ms DURATION options",
                ));
            }
        }
    }
    Ok((
        id.ok_or_else(|| config::invalid("SESSION_ID must be a UUID"))?,
        timeout,
        streaming,
        keep_result,
    ))
}

fn volume(args: &[String], connection: &Connection, env: &Env) -> io::Result<i32> {
    let [mode, rest @ ..] = args else {
        return Err(config::invalid(HELP));
    };
    let endpoint = connection.endpoint(env)?;
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
        let byte_limit = options
            .get("--bytes")
            .map(|v| cli::parse_bytes(v).map_err(|_| config::invalid("Invalid volume limit")))
            .transpose()?;
        let inode_limit = options
            .get("--inodes")
            .map(|v| {
                v.parse::<u64>()
                    .map_err(|_| config::invalid("Invalid volume limit"))
            })
            .transpose()?;
        let plan = storage::Plan {
            id: match options.get("--id") {
                Some(id) => id.to_string(),
                None => sandcrab_core::new_uuid()?,
            },
            profile: cli::resolve_profile(options.get("--profile").copied(), env)?,
            clone_from: options.get("--clone-from").map(|s| s.to_string()),
            byte_limit,
            inode_limit,
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

const FILE_HELP: &str = "\nFiles:\n  sandcrab files put [--socket PATH] SESSION_ID LOCAL_FILE WORKSPACE_PATH [--tar] [--replace] [--parents] [--id UUID] [--mode OCTAL] [--keep-result]\n  sandcrab files get [--socket PATH] SESSION_ID WORKSPACE_PATH LOCAL_FILE [--tar] [--replace]\n  sandcrab files read [--socket PATH] SESSION_ID WORKSPACE_PATH [LOCAL_FILE] [--bytes RANGE | --offset LINE [--limit LINES]] [--replace]\n  sandcrab files mkdir [--socket PATH] SESSION_ID WORKSPACE_PATH [--mode OCTAL]\n  sandcrab files ls [--socket PATH] SESSION_ID [WORKSPACE_PATH] [--depth N]\n  sandcrab files search [--socket PATH] SESSION_ID PATTERN [--path WORKSPACE_PATH]\n  sandcrab files rm [--socket PATH] SESSION_ID WORKSPACE_PATH [--recursive]\n  sandcrab files status|cancel|forget [--socket PATH] UPLOAD_ID\n  sandcrab files list [--socket PATH] [--after UUID]\n\nRaw put streams one request; --parents creates missing workspace directories. --id, --keep-result or --tar selects staged upload.\nread defaults LOCAL_FILE to - (stdout); get writes raw bytes to stdout when LOCAL_FILE is -. Existing destinations require --replace.\n";

fn parse_octal_mode(value: &str) -> io::Result<u32> {
    u32::from_str_radix(value, 8)
        .ok()
        .filter(|m| *m <= 0o777)
        .ok_or_else(|| config::invalid("--mode must be 000..777"))
}

fn parse_read_args(
    rest: &[String],
) -> io::Result<(String, String, PathBuf, file_client::ReadOptions)> {
    let (mut bytes, mut offset, mut limit, mut replace) = (None, None, None, false);
    let mut positional = Vec::new();
    let mut iter = rest.iter();
    let mut seen = std::collections::BTreeSet::new();
    while let Some(item) = iter.next() {
        if item.starts_with("--") {
            if !seen.insert(item.as_str()) {
                return Err(config::invalid("Repeated file option"));
            }
            match item.as_str() {
                "--replace" => replace = true,
                "--bytes" => {
                    bytes = Some(
                        iter.next()
                            .ok_or_else(|| config::invalid("--bytes requires START-END"))?
                            .clone(),
                    );
                }
                "--offset" => {
                    let raw = iter.next().ok_or_else(|| {
                        config::invalid("--offset requires a positive line number")
                    })?;
                    offset = Some(
                        raw.parse::<u64>()
                            .ok()
                            .filter(|n| *n >= 1)
                            .ok_or_else(|| config::invalid("--offset must be >= 1"))?,
                    );
                }
                "--limit" => {
                    let raw = iter
                        .next()
                        .ok_or_else(|| config::invalid("--limit requires a positive line count"))?;
                    limit = Some(
                        raw.parse::<u64>()
                            .ok()
                            .filter(|n| *n >= 1)
                            .ok_or_else(|| config::invalid("--limit must be >= 1"))?,
                    );
                }
                _ => return Err(config::invalid("Unknown file option")),
            }
        } else if item.starts_with('-') && item != "-" {
            return Err(config::invalid("Unknown file option"));
        } else {
            positional.push(item.as_str());
        }
    }
    let (session, path, destination) = match positional.as_slice() {
        [session, path] => (*session, *path, PathBuf::from("-")),
        [session, path, destination] => (*session, *path, PathBuf::from(destination)),
        _ => return Err(config::invalid(FILE_HELP)),
    };
    if !sandcrab_core::uuid(session) {
        return Err(config::invalid(FILE_HELP));
    }
    Ok((
        session.into(),
        path.into(),
        destination,
        file_client::ReadOptions {
            bytes,
            offset,
            limit,
            replace,
        },
    ))
}

fn file_command(args: &[String], connection: &Connection, env: &Env) -> io::Result<i32> {
    use file_io::Format;
    if matches!(args, [flag] if ["--help", "-h"].contains(&flag.as_str())) {
        print!("{FILE_HELP}");
        return Ok(0);
    }
    let [mode, rest @ ..] = args else {
        return Err(config::invalid(FILE_HELP));
    };
    let endpoint = connection.endpoint(env)?;
    match (mode.as_str(), rest) {
        ("status" | "cancel" | "forget", [id]) if sandcrab_core::uuid(id) => {
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
                client::request(&endpoint, method, &path, body.as_ref())?
            );
            Ok(0)
        }
        ("list", rest) => {
            let path = match rest {
                [] => "/v1/uploads".into(),
                [flag, id] if flag == "--after" && sandcrab_core::uuid(id) => {
                    format!("/v1/uploads?after={id}")
                }
                _ => return Err(config::invalid("Expected optional --after UUID")),
            };
            println!("{}", client::request(&endpoint, "GET", &path, None)?);
            Ok(0)
        }
        ("read", rest) => {
            let (session, path, destination, options) = parse_read_args(rest)?;
            file_client::read(&endpoint, &session, &path, &destination, options)
        }
        ("mkdir", rest) => {
            let mut permissions = None;
            let mut positional = Vec::new();
            let mut iter = rest.iter();
            while let Some(item) = iter.next() {
                if item == "--mode" && permissions.is_none() {
                    let value = iter
                        .next()
                        .ok_or_else(|| config::invalid("--mode requires octal permissions"))?;
                    permissions = Some(parse_octal_mode(value)?);
                } else if !item.starts_with('-') {
                    positional.push(item.as_str());
                } else {
                    return Err(config::invalid(FILE_HELP));
                }
            }
            let [session, path] = positional.as_slice() else {
                return Err(config::invalid(FILE_HELP));
            };
            if !sandcrab_core::uuid(session) {
                return Err(config::invalid(FILE_HELP));
            }
            file_client::mkdir(&endpoint, session, path, permissions)
        }
        ("ls", rest) => {
            let mut depth = None;
            let mut positional = Vec::new();
            let mut iter = rest.iter();
            while let Some(item) = iter.next() {
                if item == "--depth" && depth.is_none() {
                    let value = iter
                        .next()
                        .ok_or_else(|| config::invalid("--depth requires 0..64"))?;
                    depth = Some(
                        value
                            .parse::<usize>()
                            .ok()
                            .filter(|n| *n <= 64)
                            .ok_or_else(|| config::invalid("--depth must be 0..64"))?,
                    );
                } else if !item.starts_with('-') {
                    positional.push(item.as_str());
                } else {
                    return Err(config::invalid(FILE_HELP));
                }
            }
            let (session, path) = match positional.as_slice() {
                [session] => (*session, "."),
                [session, path] => (*session, *path),
                _ => return Err(config::invalid(FILE_HELP)),
            };
            if !sandcrab_core::uuid(session) {
                return Err(config::invalid(FILE_HELP));
            }
            file_client::ls(&endpoint, session, path, depth)
        }
        ("search", rest) => {
            let mut dir = None;
            let mut positional = Vec::new();
            let mut iter = rest.iter();
            while let Some(item) = iter.next() {
                if item == "--path" && dir.is_none() {
                    dir = Some(
                        iter.next()
                            .ok_or_else(|| config::invalid("--path requires a directory"))?
                            .as_str(),
                    );
                } else if !item.starts_with('-') {
                    positional.push(item.as_str());
                } else {
                    return Err(config::invalid(FILE_HELP));
                }
            }
            let [session, pattern] = positional.as_slice() else {
                return Err(config::invalid(FILE_HELP));
            };
            if !sandcrab_core::uuid(session) {
                return Err(config::invalid(FILE_HELP));
            }
            file_client::search(&endpoint, session, dir.unwrap_or("."), pattern)
        }
        ("rm", rest) => {
            let mut recursive = false;
            let mut positional = Vec::new();
            for item in rest {
                if (item == "--recursive" || item == "-r") && !recursive {
                    recursive = true;
                } else if !item.starts_with('-') {
                    positional.push(item.as_str());
                } else {
                    return Err(config::invalid(FILE_HELP));
                }
            }
            let [session, path] = positional.as_slice() else {
                return Err(config::invalid(FILE_HELP));
            };
            if !sandcrab_core::uuid(session) {
                return Err(config::invalid(FILE_HELP));
            }
            file_client::rm(&endpoint, session, path, recursive)
        }
        ("put" | "get", rest) => {
            let (mut format, mut replace, mut parents, mut keep, mut id, mut permissions) =
                (Format::Raw, false, false, false, None, None);
            let mut positional = Vec::new();
            let mut iter = rest.iter();
            let mut seen = std::collections::BTreeSet::new();
            while let Some(item) = iter.next() {
                if item.starts_with("--") {
                    if !seen.insert(item.as_str()) {
                        return Err(config::invalid("Repeated file option"));
                    }
                    match item.as_str() {
                        "--tar" => format = Format::Tar,
                        "--replace" => replace = true,
                        "--parents" if mode == "put" => parents = true,
                        "--keep-result" if mode == "put" => keep = true,
                        "--id" if mode == "put" => {
                            id = Some(
                                iter.next()
                                    .filter(|s| sandcrab_core::uuid(s))
                                    .ok_or_else(|| config::invalid("--id requires a UUID"))?
                                    .clone(),
                            );
                        }
                        "--mode" if mode == "put" => {
                            let value = iter.next().ok_or_else(|| {
                                config::invalid("--mode requires octal permissions")
                            })?;
                            permissions = Some(parse_octal_mode(value)?);
                        }
                        _ => return Err(config::invalid("Unknown file option")),
                    }
                } else if item.starts_with('-') && item != "-" {
                    return Err(config::invalid("Unknown file option"));
                } else {
                    positional.push(item.as_str());
                }
            }
            let [session, source, destination] = positional.as_slice() else {
                return Err(config::invalid(FILE_HELP));
            };
            if !sandcrab_core::uuid(session) {
                return Err(config::invalid(FILE_HELP));
            }
            if mode == "put" {
                file_client::put(
                    &endpoint,
                    session,
                    Path::new(source),
                    destination,
                    file_client::Put {
                        id,
                        format,
                        replace,
                        parents,
                        mode: permissions,
                        keep_result: keep,
                    },
                )
            } else {
                file_client::get(
                    &endpoint,
                    session,
                    source,
                    Path::new(destination),
                    file_client::Get { format, replace },
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

#[cfg(test)]
mod tests {
    use super::*;

    fn vec_args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn install_and_guest_call_options_accept_any_order() {
        assert_eq!(
            parse_install_flags(&vec_args(&["--upgrade", "--dry-run"]), true).unwrap(),
            (true, true)
        );
        assert!(parse_install_flags(&vec_args(&["--upgrade"]), false).is_err());
        assert_eq!(
            parse_guest_call(&vec_args(&["--timeout", "15s", "-"])).unwrap(),
            ("-", 15_000)
        );
        assert_eq!(
            parse_guest_call(&vec_args(&["request.bin", "--timeout-ms", "2500"])).unwrap(),
            ("request.bin", 2_500)
        );
    }

    #[test]
    fn session_exec_options_accept_reordered_flags() {
        let id = "01234567-89ab-4def-8012-3456789abcde";
        let args = vec_args(&["--stream", "--timeout", "30s", id, "--keep-result"]);
        assert_eq!(
            session_exec_options(&args).unwrap(),
            (id, Some(30_000), true, true)
        );
    }

    #[test]
    fn file_read_options_default_to_stdout_and_accept_reordered_ranges() {
        let id = "01234567-89ab-4def-8012-3456789abcde";
        let (session, path, dest, opts) = parse_read_args(&vec_args(&[
            "--offset",
            "2",
            "--limit",
            "5",
            id,
            "src/app.py",
        ]))
        .unwrap();
        assert_eq!((session.as_str(), path.as_str()), (id, "src/app.py"));
        assert_eq!(dest, PathBuf::from("-"));
        assert_eq!(
            (opts.offset, opts.limit, opts.replace),
            (Some(2), Some(5), false)
        );
        let (_, _, dest2, opts2) = parse_read_args(&vec_args(&[
            id,
            "out.bin",
            "local.bin",
            "--bytes",
            "0-15",
            "--replace",
        ]))
        .unwrap();
        assert_eq!(dest2, PathBuf::from("local.bin"));
        assert_eq!(opts2.bytes.as_deref(), Some("0-15"));
        assert!(opts2.replace);
    }
}
