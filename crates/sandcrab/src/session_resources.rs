//! A session's slice bounds all of its shells and survives until their containment.
use crate::config::{Profile, Service, invalid};
use sandcrab_core::unit::{checked, empty_group};
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone)]
pub struct Group {
    pub unit: String,
    pub cgroup: PathBuf,
}
fn family(service: &Service) -> String {
    // IDs are caller-selected. Include the operator namespace so another daemon
    // using the same pool and ID cannot acquire or stop this session's slice.
    format!(
        "{}-sandcrab{:x}",
        service.resource_slice.trim_end_matches(".slice"),
        Sha256::digest(service.unit_prefix.as_bytes())
    )
}
pub fn validate(service: &Service) -> io::Result<()> {
    if family(service).len() + 32 + ".slice".len() > 240 {
        return Err(invalid(
            "resource_slice is too long for a session child slice",
        ));
    }
    Ok(())
}
fn run(args: &[String]) -> io::Result<std::process::Output> {
    checked(args, Duration::from_secs(15))
}
fn memory_limit(profile: &Profile) -> u64 {
    let page = rustix::param::page_size() as u64;
    profile.memory_bytes / page * page
}
impl Group {
    pub fn owns(service: &Service, unit: &str) -> bool {
        unit.strip_prefix(&family(service))
            .and_then(|value| value.strip_suffix(".slice"))
            .is_some_and(|identity| {
                identity.len() == 32
                    && identity
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
    }
    pub fn new(service: &Service, pool: &Path, id: &str) -> io::Result<Self> {
        validate(service)?;
        if !sandcrab_core::uuid(id) {
            return Err(invalid("Invalid session resource identity"));
        }
        let unit = format!("{}{}.slice", family(service), id.replace('-', ""));
        Ok(Self {
            cgroup: pool.join(&unit),
            unit,
        })
    }
    /// A failed start may have created the slice; the owner must still stop it.
    pub fn start(&self, service: &Service, profile: &Profile) -> io::Result<()> {
        let properties = [
            vec![
                "Description".into(),
                "s".into(),
                "Sandcrab session resources".into(),
            ],
            vec![
                "MemoryMax".into(),
                "t".into(),
                memory_limit(profile).to_string(),
            ],
            vec!["MemorySwapMax".into(), "t".into(), "0".into()],
            vec![
                "CPUQuotaPerSecUSec".into(),
                "t".into(),
                (profile.cpu_quota_percent * 10000).to_string(),
            ],
            vec!["TasksMax".into(), "t".into(), profile.tasks_max.to_string()],
            vec![
                "BindsTo".into(),
                "as".into(),
                "1".into(),
                service.supervisor_unit.clone(),
            ],
            vec![
                "After".into(),
                "as".into(),
                "1".into(),
                service.supervisor_unit.clone(),
            ],
            vec![
                "CollectMode".into(),
                "s".into(),
                "inactive-or-failed".into(),
            ],
        ];
        let mut args = vec![
            "busctl".into(),
            "--timeout=15s".into(),
            "call".into(),
            "org.freedesktop.systemd1".into(),
            "/org/freedesktop/systemd1".into(),
            "org.freedesktop.systemd1.Manager".into(),
            "StartTransientUnit".into(),
            "ssa(sv)a(sa(sv))".into(),
            self.unit.clone(),
            "fail".into(),
            properties.len().to_string(),
        ];
        args.extend(properties.into_iter().flatten());
        args.push("0".into());
        run(&args)?;
        // StartTransientUnit returns a job, not readiness. Join that job before
        // reading the kernel limits or launching any caller-controlled code.
        run(&["systemctl".into(), "start".into(), self.unit.clone()])?;
        for (file, expected) in [
            ("memory.max", memory_limit(profile)),
            ("memory.swap.max", 0),
            ("pids.max", profile.tasks_max),
        ] {
            if fs::read_to_string(self.cgroup.join(file))?
                .trim()
                .parse::<u64>()
                .ok()
                != Some(expected)
            {
                return Err(invalid("Session resource limits were not applied"));
            }
        }
        let cpu = fs::read_to_string(self.cgroup.join("cpu.max"))?;
        let limits = cpu
            .split_whitespace()
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid("Session CPU limit was not applied"))?;
        if limits.len() != 2
            || limits.contains(&0)
            || limits[0] as u128 * 100 != limits[1] as u128 * profile.cpu_quota_percent as u128
        {
            return Err(invalid("Session CPU limit was not applied"));
        }
        Ok(())
    }
    pub fn stop(&self) -> io::Result<()> {
        if let Err(error) = run(&["systemctl".into(), "stop".into(), self.unit.clone()]) {
            let state = run(&[
                "systemctl".into(),
                "show".into(),
                self.unit.clone(),
                "-p".into(),
                "LoadState".into(),
                "-p".into(),
                "ActiveState".into(),
            ])?;
            let state = String::from_utf8_lossy(&state.stdout);
            if !state.lines().any(|line| line == "LoadState=not-found")
                || !state.lines().any(|line| line == "ActiveState=inactive")
            {
                return Err(error);
            }
        }
        empty_group(&self.cgroup)
    }
    pub fn recover(service: &Service, pool: &Path) -> io::Result<()> {
        let family = family(service);
        let units = run(&[
            "systemctl".into(),
            "list-units".into(),
            "--all".into(),
            "--full".into(),
            "--plain".into(),
            "--no-legend".into(),
            format!("{family}*.slice"),
        ])?;
        for line in String::from_utf8_lossy(&units.stdout).lines() {
            let unit = line
                .split_whitespace()
                .next()
                .ok_or_else(|| invalid("Invalid session slice"))?;
            if !Self::owns(service, unit) {
                return Err(invalid("Unexpected session slice"));
            }
            Self {
                unit: unit.into(),
                cgroup: pool.join(unit),
            }
            .stop()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_caller_id_does_not_alias_another_operator_namespace() {
        let mut config =
            crate::config::Config::parse(include_str!("../config.example.toml")).unwrap();
        let pool = Path::new("/sys/fs/cgroup/sandcrab.slice");
        let id = "00000000-0000-0000-0000-000000000001";
        let first = Group::new(&config.service, pool, id).unwrap();
        config.service.unit_prefix = "sandcrab-other-".into();
        config.service.supervisor_unit = "sandcrab-other.service".into();
        let other = Group::new(&config.service, pool, id).unwrap();
        assert_ne!(first.unit, other.unit);
        assert!(Group::owns(&config.service, &other.unit));
        assert!(!Group::owns(&config.service, &first.unit));
        assert_eq!(first.cgroup.parent(), Some(pool));
        assert_eq!(other.cgroup.parent(), Some(pool));
        assert!(sandcrab_daemon::install::unit_name(&first.unit));
        assert!(Group::new(&config.service, pool, "../foreign").is_err());
        config.service.resource_slice = format!("{}.slice", "a".repeat(200));
        assert!(validate(&config.service).is_err());
    }
}
