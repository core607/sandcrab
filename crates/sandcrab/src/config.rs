//! Operator-owned profiles; callers choose a name and may only lower execution limits.
use sandcrab_core::fs::{normal, protected_directory, protected_file};
use sandcrab_daemon::install::{execution_account, unit_name};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
};
pub(crate) const MAX_OUTPUT: usize = 1_048_576;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub service: Service,
    pub profiles: BTreeMap<String, Profile>,
    pub storage: Option<Storage>,
    pub tcp: Option<Tcp>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tcp {
    pub listen: String,
    pub token_file: PathBuf,
    #[serde(skip)]
    pub token: Option<crate::auth::Token>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    #[serde(default)]
    pub opensandbox: bool,
    pub runtime_root: PathBuf,
    pub socket: PathBuf,
    pub client_uid: u32,
    pub client_gid: u32,
    pub resource_slice: String,
    pub supervisor_unit: String,
    pub unit_prefix: String,
    pub max_sandboxes: usize,
    pub max_records: usize,
    pub max_output_bytes: usize,
    #[serde(default = "file_records")]
    pub max_file_records: usize,
    #[serde(default = "file_transfers")]
    pub max_file_transfers: usize,
    #[serde(default = "connections")]
    pub max_connections: usize,
    #[serde(default = "event_streams")]
    pub max_event_streams: usize,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Storage {
    pub root: PathBuf,
    pub pool_bytes: u64,
    pub max_volume_bytes: u64,
    pub max_volume_inodes: u64,
    pub max_volumes: usize,
    pub max_records: usize,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub exec_user: String,
    pub tools: PathBuf,
    pub read_only: Vec<PathBuf>,
    pub memory_bytes: u64,
    pub temporary_bytes: u64,
    pub temporary_inodes: u64,
    pub tasks_max: u64,
    pub cpu_quota_percent: u64,
    pub timeout_millis: u64,
    pub session_ttl_millis: u64,
    pub output_limit_bytes: usize,
    pub network: String,
    #[serde(default)]
    pub host_calls: bool,
    #[serde(default = "transfer_bytes")]
    pub transfer_bytes: u64,
    #[serde(skip)]
    pub uid: u32,
    #[serde(skip)]
    pub gid: u32,
}

#[derive(Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Resources {
    pub memory_bytes: Option<u64>,
    pub cpu_quota_percent: Option<u64>,
}
impl Profile {
    pub fn minimum_memory(&self) -> u64 {
        self.temporary_bytes.max(16 * 1024 * 1024)
    }

    pub fn with_resources(&self, resources: Option<&Resources>) -> Result<Self, &'static str> {
        let mut profile = self.clone();
        if let Some(resources) = resources {
            if let Some(memory) = resources.memory_bytes {
                if !(self.minimum_memory()..=self.memory_bytes).contains(&memory) {
                    return Err("PROFILE_LIMIT");
                }
                profile.memory_bytes = memory;
            }
            if let Some(cpu) = resources.cpu_quota_percent {
                if !(1..=self.cpu_quota_percent).contains(&cpu) {
                    return Err("PROFILE_LIMIT");
                }
                profile.cpu_quota_percent = cpu;
            }
        }
        Ok(profile)
    }
}
fn file_records() -> usize {
    256
}
fn connections() -> usize {
    32
}
fn event_streams() -> usize {
    16
}
fn file_transfers() -> usize {
    2
}
fn transfer_bytes() -> u64 {
    32 * 1024 * 1024
}
fn host_call_mount(path: &Path) -> bool {
    [
        "/sandcrab",
        "/sandcrab-driver",
        crate::host_calls::DIRECTORY,
    ]
    .iter()
    .any(|reserved| path.starts_with(reserved))
}

pub fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

pub fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 48
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl Config {
    pub fn parse(text: &str) -> io::Result<Self> {
        if text.len() > 65536 {
            return Err(invalid("Configuration exceeds 65536 bytes"));
        }
        // Display includes source excerpts, which can disclose a misplaced inline secret.
        let config: Self = toml::from_str(text)
            .map_err(|e: toml::de::Error| invalid(format!("Invalid TOML: {}", e.message())))?;
        config.validate()?;
        Ok(config)
    }

    pub fn load(path: &Path) -> io::Result<Self> {
        protected_directory(
            path.parent()
                .ok_or_else(|| invalid("Configuration needs a parent directory"))?,
        )?;
        let bytes = protected_file(path, 65536)?;
        let mut config = Self::parse(
            std::str::from_utf8(&bytes).map_err(|_| invalid("Configuration is not UTF-8"))?,
        )?;
        if let Some(tcp) = &mut config.tcp {
            tcp.token = Some(crate::auth::read_token(&tcp.token_file, 0)?);
        }
        for profile in config.profiles.values_mut() {
            (profile.uid, profile.gid) = execution_account(
                &profile.exec_user,
                config.service.client_uid,
                config.service.client_gid,
            )?;
            protected_directory(&profile.tools)?;
            sandcrab_launch::verify_tools(&profile.tools).map_err(io::Error::other)?;
            for path in &profile.read_only {
                let resolved = path.canonicalize()?;
                if profile.host_calls && host_call_mount(&resolved) {
                    return Err(invalid(
                        "Read mount resolves into a reserved host-call path",
                    ));
                }
                if resolved.starts_with(&config.service.runtime_root)
                    || config.service.runtime_root.starts_with(&resolved)
                {
                    return Err(invalid("Read mount resolves into runtime storage"));
                }
                if config.storage.as_ref().is_some_and(|storage| {
                    resolved.starts_with(&storage.root) || storage.root.starts_with(&resolved)
                }) {
                    return Err(invalid("Read mount resolves into volume storage"));
                }
                if config
                    .tcp
                    .as_ref()
                    .is_some_and(|tcp| tcp.token_file.starts_with(&resolved))
                {
                    return Err(invalid("Read mount exposes the TCP token file"));
                }
                let parent = if resolved.is_dir() {
                    resolved.as_path()
                } else {
                    resolved
                        .parent()
                        .ok_or_else(|| invalid("Mount has no parent"))?
                };
                protected_directory(parent)?;
            }
        }
        if let Some(storage) = &config.storage {
            crate::storage::verify_pool(storage)?;
        }
        Ok(config)
    }

    fn validate(&self) -> io::Result<()> {
        let service = &self.service;
        if let Some(tcp) = &self.tcp {
            crate::transport::local_address(&tcp.listen)?;
            if !normal(&tcp.token_file)
                || tcp.token_file.starts_with(&service.runtime_root)
                || self
                    .storage
                    .as_ref()
                    .is_some_and(|s| tcp.token_file.starts_with(&s.root))
            {
                return Err(invalid(
                    "TCP token file must be a normalized absolute path outside runtime and volume storage",
                ));
            }
            if self.profiles.values().any(|p| {
                tcp.token_file.starts_with(&p.tools)
                    || p.read_only
                        .iter()
                        .any(|mount| tcp.token_file.starts_with(mount))
            }) {
                return Err(invalid("Read mount exposes the TCP token file"));
            }
        }
        if !normal(&service.runtime_root)
            || !normal(&service.socket)
            || service.socket.parent() != Some(service.runtime_root.as_path())
        {
            return Err(invalid(
                "service.socket must be inside a normalized absolute runtime_root",
            ));
        }
        if !unit_name(&service.resource_slice)
            || !service.resource_slice.ends_with(".slice")
            || !unit_name(&service.supervisor_unit)
            || !service.supervisor_unit.ends_with(".service")
            || !service
                .unit_prefix
                .strip_prefix("sandcrab-")
                .and_then(|s| s.strip_suffix('-'))
                .is_some_and(name)
        {
            return Err(invalid(
                "Service requires slice/service names and a sandcrab-NAME- unit_prefix",
            ));
        }
        if service.unit_prefix
            != format!("{}-", service.supervisor_unit.trim_end_matches(".service"))
        {
            return Err(invalid(
                "unit_prefix must be the supervisor unit name followed by '-'",
            ));
        }
        crate::session_resources::validate(service)?;
        if !(8..=256).contains(&service.max_connections)
            || !(1..=service.max_connections.saturating_sub(4).min(128))
                .contains(&service.max_event_streams)
        {
            return Err(invalid(
                "Use 8..256 max_connections and 1..min(128, max_connections-4) max_event_streams; reserve four control connections",
            ));
        }
        if service.opensandbox && self.tcp.is_none() {
            return Err(invalid("OpenSandbox requires authenticated loopback TCP"));
        }
        if !(1..=64).contains(&service.max_sandboxes)
            || !(service.max_sandboxes..=1024).contains(&service.max_records)
            || !(65536..=64 * 1024 * 1024).contains(&service.max_output_bytes)
            || self.profiles.is_empty()
            || self.profiles.len() > 32
            || !(1..=1024).contains(&service.max_file_records)
            || !(1..=16).contains(&service.max_file_transfers)
        {
            return Err(invalid(
                "Use 1..64 max_sandboxes, max_sandboxes..1024 max_records and 1..32 profiles",
            ));
        }
        if let Some(storage) = &self.storage
            && (!normal(&storage.root)
                || storage.root.starts_with(&service.runtime_root)
                || service.runtime_root.starts_with(&storage.root)
                || !(1_048_576..=storage.pool_bytes).contains(&storage.max_volume_bytes)
                || !storage.max_volume_bytes.is_multiple_of(1024)
                || storage.pool_bytes > 1 << 50
                || !(32..=1_000_000).contains(&storage.max_volume_inodes)
                || !(1..=1024).contains(&storage.max_volumes)
                || !(storage.max_volumes..=4096).contains(&storage.max_records))
        {
            return Err(invalid(
                "Invalid storage root, pool, quota or record limits",
            ));
        }
        for (key, profile) in &self.profiles {
            if !name(key)
                || !unit_name(&profile.exec_user)
                || !normal(&profile.tools)
                || profile.tools.starts_with(&service.runtime_root)
                || service.runtime_root.starts_with(&profile.tools)
                || self.storage.as_ref().is_some_and(|s| {
                    profile.tools.starts_with(&s.root) || s.root.starts_with(&profile.tools)
                })
                || profile.network != "none"
            {
                return Err(invalid(format!(
                    "Profile {key} needs a name, execution account, absolute tools path and network=none"
                )));
            }
            if profile.host_calls
                && (host_call_mount(&profile.tools)
                    || profile.read_only.iter().any(|path| host_call_mount(path)))
            {
                return Err(invalid(
                    "Host-call profiles cannot mount /sandcrab, /sandcrab-driver or /sandcrab-calls",
                ));
            }
            if profile.read_only.is_empty()
                || profile.read_only.len() > 32
                || profile.read_only.iter().any(|p| {
                    !normal(p)
                        || p.starts_with(&service.runtime_root)
                        || service.runtime_root.starts_with(p)
                        || self
                            .storage
                            .as_ref()
                            .is_some_and(|s| p.starts_with(&s.root) || s.root.starts_with(p))
                        || p.starts_with("/workspace")
                        || p.starts_with("/tmp")
                })
            {
                return Err(invalid(format!(
                    "Profile {key} read_only paths must exclude runtime_root, /workspace and /tmp"
                )));
            }
            if !(16 * 1024 * 1024..=1 << 40).contains(&profile.memory_bytes)
                || !(1024..=1_073_741_824).contains(&profile.transfer_bytes)
                || !(1024 * 1024..=profile.memory_bytes).contains(&profile.temporary_bytes)
                || !(32..=1_000_000).contains(&profile.temporary_inodes)
                || !(16..=4096).contains(&profile.tasks_max)
                || !(1..=10000).contains(&profile.cpu_quota_percent)
                || !(1..=300_000).contains(&profile.timeout_millis)
                || !(100..=86_400_000).contains(&profile.session_ttl_millis)
                || !(1..=MAX_OUTPUT.min(service.max_output_bytes))
                    .contains(&profile.output_limit_bytes)
            {
                return Err(invalid(format!(
                    "Profile {key} has an invalid resource, timeout or output limit"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const EXAMPLE: &str = include_str!("../config.example.toml");
    #[test]
    fn example_has_no_consumer_identity_or_signing_key() {
        let config = Config::parse(EXAMPLE).unwrap();
        assert!(config.profiles.contains_key("python"));
        assert_eq!(config.profiles["python"].network, "none");
    }
    #[test]
    fn requested_resources_preserve_operator_mounts_identity_and_hard_caps() {
        let config = Config::parse(EXAMPLE).unwrap();
        let profile = &config.profiles["python"];
        let limited = profile
            .with_resources(Some(&Resources {
                memory_bytes: Some(32 * 1024 * 1024),
                cpu_quota_percent: Some(25),
            }))
            .unwrap();
        assert_eq!(limited.memory_bytes, 32 * 1024 * 1024);
        assert_eq!(limited.cpu_quota_percent, 25);
        assert_eq!(limited.exec_user, profile.exec_user);
        assert_eq!(limited.read_only, profile.read_only);
        assert_eq!(limited.tasks_max, profile.tasks_max);
        assert_eq!(limited.temporary_bytes, profile.temporary_bytes);
        for resource in [
            Resources {
                memory_bytes: Some(profile.memory_bytes + 1),
                cpu_quota_percent: None,
            },
            Resources {
                memory_bytes: Some(profile.minimum_memory() - 1),
                cpu_quota_percent: None,
            },
            Resources {
                memory_bytes: None,
                cpu_quota_percent: Some(profile.cpu_quota_percent + 1),
            },
            Resources {
                memory_bytes: None,
                cpu_quota_percent: Some(0),
            },
        ] {
            assert!(matches!(
                profile.with_resources(Some(&resource)),
                Err("PROFILE_LIMIT")
            ));
        }
        assert!(serde_json::from_str::<Resources>(r#"{"memoryBytes":33554432,"uid":0}"#).is_err());
    }
    #[test]
    fn unknown_fields_unsafe_mounts_and_unbounded_resources_fail() {
        for input in [
            EXAMPLE.replace("network = \"none\"", "network = \"host\""),
            EXAMPLE.replace("memory_bytes = 134217728", "memory_bytes = 0"),
            EXAMPLE.replace("max_sandboxes = 2", "max_sandboxes = 0"),
            EXAMPLE.replace("max_connections = 32", "max_connections = 7"),
            EXAMPLE.replace("max_event_streams = 16", "max_event_streams = 29"),
            EXAMPLE.replace("max_event_streams = 16", "max_event_streams = 0"),
            EXAMPLE.replace("\"/usr\"", "\"/run\""),
            EXAMPLE.replace("\"/usr\"", "\"/tmp/data\""),
            EXAMPLE.replace("\"/usr\"", "\"/usr/../etc\""),
            EXAMPLE.replace("network = \"none\"", "network = \"none\"\nuid = 0"),
        ] {
            assert!(Config::parse(&input).is_err(), "accepted {input}");
        }
    }
    #[test]
    fn tcp_requires_a_local_listener_and_an_unmounted_credential_path() {
        assert!(Config::parse(EXAMPLE).unwrap().tcp.is_none());
        let enabled = format!(
            "{EXAMPLE}\n[tcp]\nlisten = \"127.0.0.1:9011\"\ntoken_file = \"/etc/sandcrab-demo/token\"\n"
        );
        assert!(Config::parse(&enabled).unwrap().tcp.is_some());
        for input in [
            enabled.replace("127.0.0.1:9011", "0.0.0.0:9011"),
            enabled.replace("127.0.0.1:9011", "localhost:9011"),
            enabled.replace("/etc/sandcrab-demo/token", "/run/sandcrab-demo/token"),
            enabled.replace("/etc/sandcrab-demo/token", "/usr/token"),
            enabled.replace("/etc/sandcrab-demo/token", "/opt/sandcrab/tools/token"),
            enabled.replace("/etc/sandcrab-demo/token", "token"),
        ] {
            assert!(Config::parse(&input).is_err());
        }
        let secret = "abcdef0123456789".repeat(4);
        let misplaced = format!("{enabled}token = \"{secret}\"\n");
        assert!(
            !Config::parse(&misplaced)
                .err()
                .unwrap()
                .to_string()
                .contains(&secret)
        );
    }
}
