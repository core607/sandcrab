//! Operator-owned profiles; callers choose a name and may only lower execution limits.
use sandcrab_core::fs::{normal, protected_directory, protected_file};
use sandcrab_daemon::install::{execution_account, unit_name};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub service: Service,
    pub profiles: BTreeMap<String, Profile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
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
    #[serde(skip)]
    pub uid: u32,
    #[serde(skip)]
    pub gid: u32,
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
        let config: Self =
            toml::from_str(text).map_err(|e| invalid(format!("Invalid TOML: {e}")))?;
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
                if resolved.starts_with(&config.service.runtime_root)
                    || config.service.runtime_root.starts_with(&resolved)
                {
                    return Err(invalid("Read mount resolves into runtime storage"));
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
        Ok(config)
    }

    fn validate(&self) -> io::Result<()> {
        let service = &self.service;
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
        if !(1..=64).contains(&service.max_sandboxes)
            || !(service.max_sandboxes..=1024).contains(&service.max_records)
            || !(65536..=64 * 1024 * 1024).contains(&service.max_output_bytes)
            || self.profiles.is_empty()
            || self.profiles.len() > 32
        {
            return Err(invalid(
                "Use 1..64 max_sandboxes, max_sandboxes..1024 max_records and 1..32 profiles",
            ));
        }
        for (key, profile) in &self.profiles {
            if !name(key)
                || !unit_name(&profile.exec_user)
                || !normal(&profile.tools)
                || profile.tools.starts_with(&service.runtime_root)
                || service.runtime_root.starts_with(&profile.tools)
                || profile.network != "none"
            {
                return Err(invalid(format!(
                    "Profile {key} needs a name, execution account, absolute tools path and network=none"
                )));
            }
            if profile.read_only.is_empty()
                || profile.read_only.len() > 32
                || profile.read_only.iter().any(|p| {
                    !normal(p)
                        || p.starts_with(&service.runtime_root)
                        || service.runtime_root.starts_with(p)
                        || p.starts_with("/workspace")
                        || p.starts_with("/tmp")
                })
            {
                return Err(invalid(format!(
                    "Profile {key} read_only paths must exclude runtime_root, /workspace and /tmp"
                )));
            }
            if !(16 * 1024 * 1024..=1 << 40).contains(&profile.memory_bytes)
                || !(1024 * 1024..=profile.memory_bytes).contains(&profile.temporary_bytes)
                || !(32..=1_000_000).contains(&profile.temporary_inodes)
                || !(16..=4096).contains(&profile.tasks_max)
                || !(1..=10000).contains(&profile.cpu_quota_percent)
                || !(1..=300_000).contains(&profile.timeout_millis)
                || !(100..=86_400_000).contains(&profile.session_ttl_millis)
                || !(1..=1_048_576.min(service.max_output_bytes))
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
    fn unknown_fields_unsafe_mounts_and_unbounded_resources_fail() {
        for input in [
            EXAMPLE.replace("network = \"none\"", "network = \"host\""),
            EXAMPLE.replace("memory_bytes = 134217728", "memory_bytes = 0"),
            EXAMPLE.replace("max_sandboxes = 2", "max_sandboxes = 0"),
            EXAMPLE.replace("\"/usr\"", "\"/run\""),
            EXAMPLE.replace("\"/usr\"", "\"/tmp/data\""),
            EXAMPLE.replace("\"/usr\"", "\"/usr/../etc\""),
            EXAMPLE.replace("network = \"none\"", "network = \"none\"\nuid = 0"),
        ] {
            assert!(Config::parse(&input).is_err(), "accepted {input}");
        }
    }
}
