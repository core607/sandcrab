//! One protected runtime lock owns a namespace in the operator's delegated tree.
use crate::config::{Service, invalid};
use sandcrab_core::{cgroup::Cgroup, fs::protected_file, uuid};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::Duration,
};

pub struct Delegation {
    pool: Cgroup,
    pub workloads: Cgroup,
    _namespace: Cgroup,
    _daemon: Cgroup,
}

#[derive(Clone, Copy)]
enum Role {
    Namespace,
    Workloads,
    Session,
    Leaf,
}

fn child_role(role: Role, name: &str) -> io::Result<Role> {
    match role {
        Role::Namespace if name == "daemon" => Ok(Role::Leaf),
        Role::Namespace if name == "workloads" => Ok(Role::Workloads),
        Role::Workloads if name.strip_prefix("session-").is_some_and(uuid) => Ok(Role::Session),
        Role::Workloads
            if ["run-", "file-", "copy-", "overlay-"]
                .iter()
                .any(|prefix| name.strip_prefix(prefix).is_some_and(uuid)) =>
        {
            Ok(Role::Leaf)
        }
        Role::Session if name.strip_prefix("run-").is_some_and(uuid) => Ok(Role::Leaf),
        _ => Err(invalid("Unexpected child in owned cgroup namespace")),
    }
}

fn inventory(group: &Cgroup, role: Role, collected: &mut Vec<Cgroup>) -> io::Result<()> {
    let own_pid = std::process::id().to_string();
    if group
        .value("cgroup.procs")?
        .lines()
        .any(|pid| pid == own_pid)
    {
        return Err(invalid(
            "Start the daemon outside its old workload namespace",
        ));
    }
    for name in group.children()? {
        let next = Cgroup::open(&group.path().join(&name))?;
        inventory(&next, child_role(role, &name)?, collected)?;
    }
    collected.push(group.clone());
    Ok(())
}

fn clear(group: &Cgroup, role: Role, remove_root: bool) -> io::Result<()> {
    let mut owned = Vec::new();
    // Validate the whole namespace before killing anything. A matching prefix
    // alone does not authorize adopting a foreign nested cgroup.
    inventory(group, role, &mut owned)?;
    group.kill_and_wait(Duration::from_secs(15))?;
    for current in owned {
        if remove_root || current.path() != group.path() {
            current.remove_empty()?;
        }
    }
    Ok(())
}

pub fn namespace(runtime: &Path) -> String {
    format!(
        "sandcrab-{:x}",
        Sha256::digest(runtime.as_os_str().as_encoded_bytes())
    )
}

impl Delegation {
    /// The caller holds this runtime's exclusive lock before entering here.
    /// Old leaves are contained before creating a supervisor leaf or new epoch.
    pub fn start(service: &Service) -> io::Result<Self> {
        let pool = Cgroup::open(&service.cgroup_root)?;
        verify_pool(&pool)?;
        let name = namespace(&service.runtime_root);
        let expected = serde_json::json!({"version":1,"root":service.cgroup_root,"namespace":name});
        let marker = service.runtime_root.join("cgroup-owner.json");
        if marker.try_exists()? {
            let actual: serde_json::Value =
                sandcrab_core::parse(&protected_file(&marker, 8192)?)
                    .map_err(|_| invalid("Invalid cgroup ownership record"))?;
            if actual != expected {
                return Err(invalid("Runtime belongs to another cgroup delegation"));
            }
        } else {
            let mut occupied = pool.path().join(&name).try_exists()?;
            for directory in ["jobs", "records", "file-ops", "helper-jobs"] {
                occupied |= fs::read_dir(service.runtime_root.join(directory))?
                    .next()
                    .transpose()?
                    .is_some();
            }
            if occupied {
                return Err(invalid("Use a fresh runtime_root for delegated cgroups"));
            }
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(&marker)?;
            file.write_all(&serde_json::to_vec(&expected)?)?;
            file.sync_all()?;
        }
        let previous = pool.path().join(&name);
        if previous.try_exists()? {
            clear(&Cgroup::open(&previous)?, Role::Namespace, true)?;
        }
        let owned = pool.create_child(&name)?;
        let daemon = owned.create_child("daemon")?;
        // A delegated service may initially contain the daemon itself. Moving
        // it first satisfies the kernel's no-internal-process rule without
        // moving another process or changing the parent's aggregate limits.
        daemon.place_current_process()?;
        pool.enable_children()?;
        owned.enable_children()?;
        daemon.set_supervisor_limits(service.daemon_memory_bytes, service.daemon_tasks_max)?;
        let workloads = owned.create_child("workloads")?;
        workloads.enable_children()?;
        Ok(Self {
            pool,
            workloads,
            _namespace: owned,
            _daemon: daemon,
        })
    }

    pub fn verify(&self) -> io::Result<()> {
        verify_pool(&self.pool)
    }

    pub fn cleanup(&self) -> io::Result<()> {
        clear(&self.workloads, Role::Workloads, false)
    }
}

pub(crate) fn verify_pool(group: &Cgroup) -> io::Result<()> {
    let (mut memory, mut tasks, mut cpu, mut no_swap) = (false, false, false, false);
    let mut ancestor = Some(group.clone());
    while let Some(parent) = ancestor {
        for (name, present) in [("memory.max", &mut memory), ("pids.max", &mut tasks)] {
            match parent.value(name) {
                Ok(value) if value.trim() == "max" => {}
                Ok(value) => {
                    let bound = value
                        .trim()
                        .parse::<u64>()
                        .map_err(|_| invalid("Invalid pool limit"))?;
                    if bound == 0 {
                        return Err(invalid("Pool limit cannot be zero"));
                    }
                    *present = true;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        match parent.value("memory.swap.max") {
            Ok(value) => {
                if value.trim() != "max" && value.trim().parse::<u64>().is_err() {
                    return Err(invalid("Invalid pool swap limit"));
                }
                no_swap |= value.trim() == "0";
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let cpu_value = match parent.value("cpu.max") {
            Ok(value) => Some(value),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if let Some(value) = cpu_value {
            let parts = value.split_whitespace().collect::<Vec<_>>();
            if parts.len() != 2 || parts[1].parse::<u64>().ok().is_none_or(|n| n == 0) {
                return Err(invalid("Invalid pool CPU limit"));
            }
            if parts[0] != "max" {
                if parts[0].parse::<u64>().ok().is_none_or(|n| n == 0) {
                    return Err(invalid("Invalid pool CPU quota"));
                }
                cpu = true;
            }
        }
        ancestor = parent.parent()?;
    }
    if !(memory && tasks && cpu && no_swap) {
        return Err(invalid(
            "Delegated pool requires finite memory, tasks and CPU limits with swap disabled",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_does_not_adopt_foreign_children() {
        let id = "00000000-0000-4000-8000-000000000001";
        assert!(child_role(Role::Workloads, &format!("session-{id}")).is_ok());
        assert!(child_role(Role::Session, &format!("run-{id}")).is_ok());
        for name in ["foreign", "session-../foreign", "run-not-a-uuid"] {
            assert!(child_role(Role::Workloads, name).is_err());
        }
        assert!(child_role(Role::Leaf, "daemon").is_err());
        assert_ne!(
            namespace(Path::new("/run/first")),
            namespace(Path::new("/run/second"))
        );
    }
}
