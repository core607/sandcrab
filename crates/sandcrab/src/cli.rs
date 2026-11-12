//! CLI flag extraction, environment variable defaults and human-readable quantity parsing.
use crate::{
    client::Endpoint,
    config::{self, invalid},
    sdk_types,
};
use std::{ffi::OsString, io, path::PathBuf};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Env {
    pub socket: Option<String>,
    pub endpoint: Option<String>,
    pub profile: Option<String>,
    pub token_file: Option<PathBuf>,
}

fn non_empty_utf8(name: &str, value: Option<OsString>) -> io::Result<Option<String>> {
    let Some(raw) = value.filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    raw.into_string()
        .map(Some)
        .map_err(|_| invalid(format!("{name} must be valid UTF-8")))
}

impl Env {
    pub fn from_process() -> io::Result<Self> {
        Ok(Self {
            socket: non_empty_utf8("SANDCRAB_SOCKET", std::env::var_os("SANDCRAB_SOCKET"))?,
            endpoint: non_empty_utf8("SANDCRAB_ENDPOINT", std::env::var_os("SANDCRAB_ENDPOINT"))?,
            profile: non_empty_utf8("SANDCRAB_PROFILE", std::env::var_os("SANDCRAB_PROFILE"))?,
            token_file: std::env::var_os("SANDCRAB_TOKEN_FILE")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Connection {
    flag: Option<(String, String)>,
    token_file: Option<PathBuf>,
}

impl Connection {
    pub fn resolve_spec(&self, env: &Env) -> io::Result<(&str, String, Option<PathBuf>)> {
        let token_file = self.token_file.clone().or_else(|| env.token_file.clone());
        if let Some((flag, value)) = &self.flag {
            return Ok((flag.as_str(), value.clone(), token_file));
        }
        match (&env.socket, &env.endpoint) {
            (Some(_), Some(_)) => Err(invalid(
                "Both SANDCRAB_SOCKET and SANDCRAB_ENDPOINT are set; pass --socket or --endpoint explicitly",
            )),
            (Some(socket), None) => Ok(("--socket", socket.clone(), token_file)),
            (None, Some(endpoint)) => Ok(("--endpoint", endpoint.clone(), token_file)),
            (None, None) => Err(invalid(
                "Pass --socket PATH or --endpoint URL, or set SANDCRAB_SOCKET or SANDCRAB_ENDPOINT",
            )),
        }
    }

    pub fn endpoint(&self, env: &Env) -> io::Result<Endpoint> {
        let (flag, value, token_file) = self.resolve_spec(env)?;
        Endpoint::parse(flag, &value, token_file.as_deref())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ClientArgs<'a> {
    pub connection: Connection,
    pub args: Vec<String>,
    pub command: Option<&'a [String]>,
}

impl<'a> ClientArgs<'a> {
    pub fn parse(raw: &'a [String]) -> io::Result<Self> {
        let (head, command) = match raw.iter().position(|arg| arg == "--") {
            Some(split) => (&raw[..split], Some(&raw[split + 1..])),
            None => (raw, None),
        };
        let mut connection = Connection::default();
        let mut args = Vec::with_capacity(head.len());
        let mut iter = head.iter();
        while let Some(item) = iter.next() {
            match item.as_str() {
                "--token-file" => {
                    if connection.token_file.is_some() {
                        return Err(invalid("Repeated --token-file option"));
                    }
                    let path = iter
                        .next()
                        .ok_or_else(|| invalid("--token-file requires a file path"))?;
                    connection.token_file = Some(PathBuf::from(path));
                }
                "--socket" | "--endpoint" => {
                    if connection.flag.is_some() {
                        return Err(invalid("Pass at most one --socket or --endpoint option"));
                    }
                    let value = iter
                        .next()
                        .ok_or_else(|| invalid(format!("{item} requires a value")))?;
                    connection.flag = Some((item.clone(), value.clone()));
                }
                _ => args.push(item.clone()),
            }
        }
        Ok(Self {
            connection,
            args,
            command,
        })
    }
}

pub fn resolve_profile(explicit: Option<&str>, env: &Env) -> io::Result<String> {
    if let Some(profile) = explicit {
        return Ok(profile.to_string());
    }
    env.profile
        .clone()
        .ok_or_else(|| invalid("--profile NAME or SANDCRAB_PROFILE is required"))
}

fn digits(value: &str) -> Option<u64> {
    (!value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
}

pub fn parse_bytes(value: &str) -> io::Result<u64> {
    for (suffix, multiplier) in [
        ("KiB", 1u64 << 10),
        ("MiB", 1 << 20),
        ("GiB", 1 << 30),
        ("TiB", 1 << 40),
        ("Ki", 1 << 10),
        ("Mi", 1 << 20),
        ("Gi", 1 << 30),
        ("Ti", 1 << 40),
        ("k", 1_000),
        ("M", 1_000_000),
        ("G", 1_000_000_000),
        ("T", 1_000_000_000_000),
        ("B", 1),
    ] {
        if let Some(number) = value.strip_suffix(suffix) {
            return digits(number)
                .and_then(|n| n.checked_mul(multiplier))
                .ok_or_else(|| invalid(format!("Invalid byte quantity: {value}")));
        }
    }
    digits(value).ok_or_else(|| invalid(format!("Invalid byte quantity: {value}")))
}

pub fn parse_millis(value: &str) -> io::Result<u64> {
    for (suffix, multiplier) in [
        ("ms", 1u64),
        ("s", 1_000),
        ("m", 60_000),
        ("h", 3_600_000),
        ("d", 86_400_000),
    ] {
        if let Some(number) = value.strip_suffix(suffix) {
            return digits(number)
                .and_then(|n| n.checked_mul(multiplier))
                .ok_or_else(|| invalid(format!("Invalid duration: {value}")));
        }
    }
    digits(value).ok_or_else(|| invalid(format!("Invalid duration: {value}")))
}

pub fn parse_cpu_percent(key: &str, value: &str) -> io::Result<u64> {
    match key {
        "--cpu-percent" => {
            let number = value.strip_suffix('%').unwrap_or(value);
            digits(number).ok_or_else(|| invalid(format!("Invalid value for {key}")))
        }
        "--cpu" => sdk_types::cpu(value).ok_or_else(|| invalid(format!("Invalid value for {key}"))),
        _ => Err(invalid(format!("Unknown CPU option: {key}"))),
    }
}

pub fn resource_option(
    resources: &mut config::Resources,
    key: &str,
    value: &str,
) -> io::Result<bool> {
    match key {
        "--memory-bytes" | "--memory" => {
            if resources.memory_bytes.is_some() {
                return Err(invalid(format!("Repeated resource option: {key}")));
            }
            resources.memory_bytes = Some(parse_bytes(value)?);
            Ok(true)
        }
        "--cpu-percent" | "--cpu" => {
            if resources.cpu_quota_percent.is_some() {
                return Err(invalid(format!("Repeated resource option: {key}")));
            }
            resources.cpu_quota_percent = Some(parse_cpu_percent(key, value)?);
            Ok(true)
        }
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vec_args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn extracts_connection_and_token_anywhere_before_double_dash_only() {
        let raw = vec_args(&[
            "run",
            "--profile",
            "default",
            "--endpoint",
            "http://127.0.0.1:9011",
            "--token-file",
            "/tmp/client.token",
            "--",
            "python3",
            "--socket",
            "literal",
            "--token-file",
            "literal2",
        ]);
        let parsed = ClientArgs::parse(&raw).unwrap();
        assert_eq!(parsed.args, vec_args(&["run", "--profile", "default"]));
        assert_eq!(
            parsed.command,
            Some(
                vec_args(&["python3", "--socket", "literal", "--token-file", "literal2"])
                    .as_slice()
            )
        );
        let env = Env::default();
        let (flag, addr, token) = parsed.connection.resolve_spec(&env).unwrap();
        assert_eq!(flag, "--endpoint");
        assert_eq!(addr, "http://127.0.0.1:9011");
        assert_eq!(token, Some(PathBuf::from("/tmp/client.token")));
    }

    #[test]
    fn env_defaults_respect_explicit_flags_and_reject_ambiguous_transports() {
        let raw = vec_args(&["info"]);
        let parsed = ClientArgs::parse(&raw).unwrap();

        let both = Env {
            socket: Some("/run/sandcrab.sock".into()),
            endpoint: Some("127.0.0.1:9011".into()),
            profile: Some("default".into()),
            token_file: Some(PathBuf::from("/tmp/tok")),
        };
        assert!(parsed.connection.resolve_spec(&both).is_err());

        let explicit_raw = vec_args(&["info", "--socket", "/explicit.sock"]);
        let explicit = ClientArgs::parse(&explicit_raw).unwrap();
        let (flag, addr, _) = explicit.connection.resolve_spec(&both).unwrap();
        assert_eq!((flag, addr.as_str()), ("--socket", "/explicit.sock"));

        let tcp_only = Env {
            socket: None,
            endpoint: Some("127.0.0.1:9011".into()),
            profile: Some("python".into()),
            token_file: Some(PathBuf::from("/tmp/tok")),
        };
        let (flag, addr, tok) = parsed.connection.resolve_spec(&tcp_only).unwrap();
        assert_eq!(flag, "--endpoint");
        assert_eq!(addr, "127.0.0.1:9011");
        assert_eq!(tok, Some(PathBuf::from("/tmp/tok")));
        assert_eq!(resolve_profile(None, &tcp_only).unwrap(), "python");
        assert_eq!(
            resolve_profile(Some("override"), &tcp_only).unwrap(),
            "override"
        );
    }

    #[test]
    fn duplicate_or_conflicting_connection_flags_fail() {
        for bad in [
            &["--socket", "/a", "--socket", "/b", "info"][..],
            &[
                "--socket",
                "/a",
                "--endpoint",
                "http://127.0.0.1:9011",
                "info",
            ][..],
            &["--token-file", "/a", "info", "--token-file", "/b"][..],
            &["info", "--socket"][..],
            &["info", "--token-file"][..],
        ] {
            assert!(
                ClientArgs::parse(&vec_args(bad)).is_err(),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn byte_duration_and_cpu_quantities_parse_exact_values_and_refuse_overflow() {
        assert_eq!(parse_bytes("33554432").unwrap(), 33_554_432);
        assert_eq!(parse_bytes("512B").unwrap(), 512);
        assert_eq!(parse_bytes("32Mi").unwrap(), 32 * 1024 * 1024);
        assert_eq!(parse_bytes("32MiB").unwrap(), 32 * 1024 * 1024);
        assert_eq!(parse_bytes("2Gi").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_bytes("2GiB").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_bytes("64Ki").unwrap(), 64 * 1024);
        assert_eq!(parse_bytes("10M").unwrap(), 10_000_000);
        for bad in ["", "Mi", "-1", "1.5Gi", "32MB", "18446744073709551615Gi"] {
            assert!(parse_bytes(bad).is_err(), "accepted {bad}");
        }

        assert_eq!(parse_millis("5000").unwrap(), 5_000);
        assert_eq!(parse_millis("250ms").unwrap(), 250);
        assert_eq!(parse_millis("30s").unwrap(), 30_000);
        assert_eq!(parse_millis("5m").unwrap(), 300_000);
        assert_eq!(parse_millis("2h").unwrap(), 7_200_000);
        assert_eq!(parse_millis("1d").unwrap(), 86_400_000);
        for bad in ["", "s", "-5s", "1.5s", "10w", "18446744073709551615d"] {
            assert!(parse_millis(bad).is_err(), "accepted {bad}");
        }

        let mut res = config::Resources::default();
        assert!(resource_option(&mut res, "--memory", "64Mi").unwrap());
        assert!(resource_option(&mut res, "--cpu", "0.5").unwrap());
        assert_eq!(res.memory_bytes, Some(64 * 1024 * 1024));
        assert_eq!(res.cpu_quota_percent, Some(50));
        assert!(resource_option(&mut res, "--memory-bytes", "1024").is_err());
        assert!(resource_option(&mut res, "--cpu-percent", "50").is_err());
    }
}
