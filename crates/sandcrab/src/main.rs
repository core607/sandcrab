#![forbid(unsafe_code)]
//! Native Sandcrab service and client; consumer-specific identities and extensions are absent.
mod client;
mod config;
mod runtime;
mod server;
mod service;

use std::{
    io,
    path::Path,
    process::ExitCode,
    sync::{Arc, atomic::AtomicBool},
};

const HELP: &str = "Sandcrab\n\nCommands:\n  sandcrab serve --config FILE\n  sandcrab check --config FILE\n  sandcrab info --socket PATH\n  sandcrab run --socket PATH --profile NAME [--timeout-ms N] -- COMMAND [ARG...]\n  sandcrab get|cancel|forget --socket PATH RUN_ID\n\nserve requires root and the configured systemd unit. run uses the profile's isolated execution account.\n";

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
        [mode, path] if mode == "__launch" => {
            runtime::launch(Path::new(path))?;
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
fn main() -> ExitCode {
    match execute(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok(code) => ExitCode::from(code as u8),
        Err(error) => {
            eprintln!("sandcrab: {error}");
            ExitCode::FAILURE
        }
    }
}
