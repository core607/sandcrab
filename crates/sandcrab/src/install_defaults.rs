//! Defaults for a fresh installation. Reinstallation keeps the operator's saved configuration.
use crate::config::invalid;
use std::{fs, io, path::Path};

const MIB: u64 = 1024 * 1024;
const DATA: &str = "/var/lib/sandcrab/storage/data";

struct Capacity {
    sandboxes: u64,
    pool: u64,
    volume_bytes: u64,
    volumes: u64,
}
impl Capacity {
    fn new(memory: u64, available: u64) -> Self {
        let sandboxes = (memory.saturating_sub(128 * MIB) / (64 * MIB)).clamp(1, 64);
        let pool = (available / (4 * MIB)).clamp(1, 8192) * MIB;
        let volume_bytes = pool.min(64 * MIB);
        let volumes = (pool / volume_bytes).min(4 * sandboxes).clamp(1, 128);
        Self {
            sandboxes,
            pool,
            volume_bytes,
            volumes,
        }
    }
}

fn effective_memory() -> io::Result<u64> {
    let meminfo = fs::read_to_string("/proc/meminfo")?;
    let mut memory = meminfo
        .lines()
        .find_map(|line| {
            line.strip_prefix("MemTotal:")?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()?
                .checked_mul(1024)
        })
        .ok_or_else(|| invalid("Missing MemTotal in /proc/meminfo"))?;
    let groups = fs::read_to_string("/proc/self/cgroup")?;
    let relative = groups
        .lines()
        .find_map(|line| line.strip_prefix("0::/"))
        .ok_or_else(|| invalid("Installation requires cgroup v2"))?;
    let relative = Path::new(relative);
    if relative
        .components()
        .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(invalid("Invalid cgroup v2 process path"));
    }
    for parent in relative.ancestors() {
        let file = Path::new("/sys/fs/cgroup").join(parent).join("memory.max");
        match fs::read_to_string(file) {
            Ok(limit) if limit.trim() != "max" => {
                memory = memory.min(
                    limit
                        .trim()
                        .parse()
                        .map_err(|_| invalid("Invalid cgroup memory.max"))?,
                );
            }
            Ok(_) => (),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
    }
    Ok(memory)
}

fn available_disk() -> io::Result<u64> {
    for parent in Path::new(DATA).ancestors() {
        match rustix::fs::statvfs(parent) {
            Ok(stat) => return Ok(stat.f_bavail.saturating_mul(stat.f_frsize)),
            Err(rustix::io::Errno::NOENT) => (),
            Err(e) => return Err(e.into()),
        }
    }
    Err(invalid("Cannot determine space on the storage filesystem"))
}

fn client_ids(setting: &str) -> io::Result<(u32, u32)> {
    let (uid, gid) = setting
        .split_once(':')
        .ok_or_else(|| invalid("Use UID:GID for SANDCRAB_CONTAINER_CLIENT"))?;
    let number = |value: &str| {
        value
            .parse::<u32>()
            .ok()
            .filter(|id| *id != u32::MAX)
            .ok_or_else(|| invalid("Use numeric IDs for SANDCRAB_CONTAINER_CLIENT"))
    };
    Ok((number(uid)?, number(gid)?))
}

pub fn render(group: &str, container: bool) -> io::Result<String> {
    let memory = effective_memory()?;
    // The installed systemd slice also enforces MemoryMax=1G. Docker supplies its own ceiling.
    let capacity = Capacity::new(
        if container {
            memory
        } else {
            memory.min(1024 * MIB)
        },
        available_disk()?,
    );
    let mut mounts: Vec<_> = ["/usr", "/bin", "/lib", "/lib64", "/etc/ld.so.cache"]
        .into_iter()
        .filter(|s| Path::new(s).exists())
        .map(|s| format!("\"{s}\""))
        .collect();
    let profile = include_str!("../install/profile.toml");
    let offline = profile.replace("@MOUNTS@", &mounts.join(", "));
    let ca = "/etc/ssl/certs/ca-certificates.crt";
    if Path::new(ca).is_file() {
        mounts.push(format!("\"{ca}\""));
    }
    let packages = profile.replace("@MOUNTS@", &mounts.join(", "));
    let client = match (container, std::env::var_os("SANDCRAB_CONTAINER_CLIENT")) {
        (true, Some(setting)) => Some(client_ids(
            setting
                .to_str()
                .ok_or_else(|| invalid("Invalid container client IDs"))?,
        )?),
        _ => None,
    };
    let socket = if client.is_some() {
        "/var/lib/sandcrab/runtime.client/control.sock"
    } else {
        "/var/lib/sandcrab/runtime/control.sock"
    };
    let (uid, gid) = client.unwrap_or((0, 0));
    Ok(include_str!("../install/default.toml")
        .replace("@CGROUP@", group)
        .replace("@SANDBOXES@", &capacity.sandboxes.to_string())
        .replace("@POOL@", &capacity.pool.to_string())
        .replace("@VOLUME_BYTES@", &capacity.volume_bytes.to_string())
        .replace("@VOLUMES@", &capacity.volumes.to_string())
        .replace("@OFFLINE_PROFILE@", &offline)
        .replace("@PACKAGE_PROFILE@", &packages)
        .replace("@SOCKET@", socket)
        .replace("@CLIENT_UID@", &uid.to_string())
        .replace("@CLIENT_GID@", &gid.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counts_follow_effective_memory_and_storage_bounds() {
        let small = Capacity::new(512 * MIB, 128 * MIB);
        assert_eq!(
            (
                small.sandboxes,
                small.pool,
                small.volume_bytes,
                small.volumes
            ),
            (6, 32 * MIB, 32 * MIB, 1)
        );
        let large = Capacity::new(16384 * MIB, 65536 * MIB);
        assert_eq!(
            (
                large.sandboxes,
                large.pool,
                large.volume_bytes,
                large.volumes
            ),
            (64, 8192 * MIB, 64 * MIB, 128)
        );
        let low = Capacity::new(MIB, MIB);
        assert_eq!((low.sandboxes, low.pool, low.volumes), (1, MIB, 1));
    }
    #[test]
    fn shared_client_requires_both_numeric_ids() {
        assert_eq!(client_ids("1001:1002").unwrap(), (1001, 1002));
        for value in ["", "1001", "1001:daemon", "1001:2:3", "4294967295:1"] {
            assert!(client_ids(value).is_err());
        }
    }
}
