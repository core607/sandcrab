#![forbid(unsafe_code)]
//! Native Sandcrab service and client; consumer-specific identities and extensions are absent.
mod client;
mod config;
mod runtime;
mod server;
mod service;
mod sessions;
mod spec;
mod storage;
mod volumes;

use std::{
    io,
    path::Path,
    process::ExitCode,
    sync::{Arc, atomic::AtomicBool},
};

const HELP: &str = "Sandcrab\n\nCommands:\n  sandcrab serve --config FILE\n  sandcrab check --config FILE\n  sandcrab info --socket PATH\n  sandcrab run --socket PATH --profile NAME [--timeout-ms N] -- COMMAND [ARG...]\n  sandcrab get|cancel|forget --socket PATH RUN_ID\n  sandcrab session open --socket PATH --profile NAME [--ttl-ms N] [--volume UUID]\n  sandcrab session exec --socket PATH SESSION_ID [--timeout-ms N] -- SHELL_SOURCE\n  sandcrab session get|close|forget --socket PATH SESSION_ID\n  sandcrab session renew --socket PATH SESSION_ID --ttl-ms N\n  sandcrab volume create --socket PATH --profile NAME [--id UUID] [--clone-from UUID] [--bytes N] [--inodes N]\n  sandcrab volume list --socket PATH [--after UUID]\n  sandcrab volume get|delete|forget --socket PATH VOLUME_ID\n\nserve requires root and the configured systemd unit. run uses the profile's isolated execution account.\n";

fn execute(args: &[String]) -> io::Result<i32> {
    match args {
        [] => {
            print!("{HELP}");
            Ok(0)
        }
        [flag] if ["--help", "-h"].contains(&flag.as_str()) => {
            print!("{HELP}");
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
        [mode, flag, path] if mode == "info" && flag == "--socket" => {
            println!(
                "{}",
                client::request(Path::new(path), "GET", "/v1/info", None)?
            );
            Ok(0)
        }
        [mode, flag, path, id]
            if ["get", "cancel", "forget"].contains(&mode.as_str()) && flag == "--socket" =>
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
                client::request(Path::new(path), method, &route, body.as_ref())?
            );
            Ok(0)
        }
        [mode, rest @ ..] if mode == "run" => run(rest),
        [mode, rest @ ..] if mode == "session" => session(rest),
        [mode, rest @ ..] if mode == "volume" => volume(rest),
        _ => Err(config::invalid(HELP)),
    }
}
fn run(args: &[String]) -> io::Result<i32> {
    let split = args
        .iter()
        .position(|s| s == "--")
        .ok_or_else(|| config::invalid("run requires -- before COMMAND"))?;
    let (options, command) = (&args[..split], &args[split + 1..]);
    let (mut socket, mut profile, mut timeout) = (None, None, None);
    for pair in options.chunks(2) {
        let [key, value] = pair else {
            return Err(config::invalid("Every run option needs a value"));
        };
        match key.as_str() {
            "--socket" if socket.is_none() => socket = Some(value),
            "--profile" if profile.is_none() => profile = Some(value),
            "--timeout-ms" if timeout.is_none() => {
                timeout = Some(
                    value
                        .parse()
                        .map_err(|_| config::invalid("Invalid timeout"))?,
                )
            }
            _ => {
                return Err(config::invalid(format!(
                    "Unknown or repeated option: {key}"
                )));
            }
        }
    }
    if command.is_empty() {
        return Err(config::invalid("COMMAND is required"));
    }
    client::run(
        Path::new(socket.ok_or_else(|| config::invalid("--socket is required"))?),
        profile.ok_or_else(|| config::invalid("--profile is required"))?,
        command,
        timeout,
    )
}
fn session(args: &[String]) -> io::Result<i32> {
    match args {
        [mode, socket_flag, socket, profile_flag, profile, rest @ ..]
            if mode == "open" && socket_flag == "--socket" && profile_flag == "--profile" =>
        {
            let (mut ttl, mut volume) = (None, None);
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
                    _ => {
                        return Err(config::invalid(
                            "Expected unique --ttl-ms N and --volume UUID options",
                        ));
                    }
                }
            }
            client::open_session(Path::new(socket), profile, ttl, volume)
        }
        [mode, flag, socket, id, rest @ ..] if flag == "--socket" && sandcrab_core::uuid(id) => {
            let path = format!("/v1/sessions/{id}");
            match mode.as_str() {
                "exec" => {
                    let split = rest.iter().position(|v| v == "--").ok_or_else(|| {
                        config::invalid("session exec requires -- before one shell source argument")
                    })?;
                    let [source] = &rest[split + 1..] else {
                        return Err(config::invalid("Pass one quoted shell source argument"));
                    };
                    client::execute_session(
                        Path::new(socket),
                        id,
                        source,
                        numeric_option(&rest[..split], "--timeout-ms")?,
                    )
                }
                "renew" => {
                    let ttl = numeric_option(rest, "--ttl-ms")?
                        .ok_or_else(|| config::invalid("--ttl-ms is required"))?;
                    println!(
                        "{}",
                        client::request(
                            Path::new(socket),
                            "POST",
                            &format!("{path}/renew"),
                            Some(&serde_json::json!({"ttlMillis":ttl}))
                        )?
                    );
                    Ok(0)
                }
                "get" if rest.is_empty() => {
                    println!(
                        "{}",
                        client::request(Path::new(socket), "GET", &path, None)?
                    );
                    Ok(0)
                }
                "close" | "forget" if rest.is_empty() => {
                    let result = client::request(
                        Path::new(socket),
                        "POST",
                        &format!("{path}/{mode}"),
                        Some(&serde_json::json!({})),
                    )?;
                    if mode == "close" {
                        client::wait_session(Path::new(socket), id, false)
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
fn volume(args: &[String]) -> io::Result<i32> {
    let [mode, flag, socket, rest @ ..] = args else {
        return Err(config::invalid(HELP));
    };
    if flag != "--socket" {
        return Err(config::invalid(HELP));
    }
    let socket = Path::new(socket);
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

fn main() -> ExitCode {
    match execute(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok(code) => ExitCode::from(code as u8),
        Err(error) => {
            eprintln!("sandcrab: {error}");
            ExitCode::FAILURE
        }
    }
}
