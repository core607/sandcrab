//! Direct cgroup v2 operations. Callers own placement, process handles and admission.
//! No operation invokes a service manager or falls back to an uncontained process.
use crate::fs::protected_directory;
use rustix::fs::{Mode, OFlags, fstat, fstatfs, open, openat};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{self, Read, Write},
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

const CGROUP2_MAGIC: u64 = 0x6367_7270;
const CONTROLLERS: [&str; 3] = ["cpu", "memory", "pids"];

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// A protected cgroup directory retained by descriptor across child processes.
/// Dropping this handle makes no containment claim and does not remove the group.
#[derive(Clone)]
pub struct Cgroup {
    path: PathBuf,
    directory: Arc<OwnedFd>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub memory_bytes: u64,
    pub tasks_max: u64,
    pub cpu_quota_percent: u64,
    pub oom_group: bool,
}

impl Limits {
    fn values(self) -> io::Result<(u64, u64)> {
        let page = rustix::param::page_size() as u64;
        let memory = self.memory_bytes / page * page;
        let quota = self.cpu_quota_percent.checked_mul(1000);
        if memory == 0 || self.tasks_max == 0 || quota.is_none_or(|q| q == 0) {
            return Err(invalid("Cgroup limits must be positive and representable"));
        }
        Ok((memory, quota.unwrap()))
    }
}

fn component(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
}

fn field(text: &str, key: &str) -> io::Result<u64> {
    let mut found = None;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some(key) {
            continue;
        }
        let value = parts
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|_| parts.next().is_none())
            .ok_or_else(|| invalid("Invalid cgroup counter"))?;
        if found.replace(value).is_some() {
            return Err(invalid("Duplicate cgroup counter"));
        }
    }
    found.ok_or_else(|| invalid("Required cgroup counter is unavailable"))
}

fn observation(reader: impl Read, name: &str) -> io::Result<String> {
    // PID lists must fit the supported task ceilings even with ten-digit PIDs.
    // Counters and limits keep the smaller control-file observation bound.
    let limit = if name == "cgroup.procs" {
        131_072
    } else {
        16_384
    };
    let mut text = String::new();
    reader.take(limit + 1).read_to_string(&mut text)?;
    if text.len() as u64 > limit {
        return Err(invalid("Cgroup observation exceeds its bound"));
    }
    Ok(text)
}

impl Cgroup {
    /// Require root-owned, nonsymlink ancestors and the actual cgroup v2 filesystem.
    /// A directory containing files with cgroup-like names is never sufficient.
    pub fn open(path: &Path) -> io::Result<Self> {
        protected_directory(path)?;
        let directory = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        if fstatfs(&directory)?.f_type as u64 != CGROUP2_MAGIC {
            return Err(invalid("Delegation must use the cgroup v2 filesystem"));
        }
        let group = Self {
            path: path.into(),
            directory: Arc::new(directory),
        };
        match group.read("cgroup.type") {
            Ok(kind) if kind.trim() == "domain" => {}
            // The actual hierarchy root has neither type nor events. A cgroup
            // namespace root can be a non-root group and still exposes both.
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                group.read("cgroup.controllers")?;
                if !matches!(group.read("cgroup.events"), Err(error)
                    if error.kind() == io::ErrorKind::NotFound)
                {
                    return Err(invalid("Cgroup domain type is unavailable"));
                }
            }
            Ok(_) => return Err(invalid("Sandcrab requires a domain cgroup")),
            Err(error) => return Err(error),
        }
        Ok(group)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Lend the verified kernel directory to an atomic clone-time placement.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.directory.as_fd()
    }

    pub fn require_current_process(&self) -> io::Result<()> {
        let pid = std::process::id().to_string();
        if self.read("cgroup.procs")?.lines().any(|line| line == pid) {
            Ok(())
        } else {
            Err(invalid("Launcher was not created in its configured cgroup"))
        }
    }

    /// Stop only at the cgroup filesystem boundary. Permission or observation
    /// failures inside that filesystem cannot hide an effective ancestor cap.
    pub fn parent(&self) -> io::Result<Option<Self>> {
        let Some(path) = self.path.parent() else {
            return Ok(None);
        };
        protected_directory(path)?;
        let directory = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        if fstatfs(&directory)?.f_type as u64 != CGROUP2_MAGIC {
            return Ok(None);
        }
        Self::open(path).map(Some)
    }

    /// Kernel value for an existing interface; this does not substitute a default
    /// when the controller or observation is unavailable.
    pub fn value(&self, name: &str) -> io::Result<String> {
        if ![
            "memory.max",
            "memory.swap.max",
            "pids.max",
            "cpu.max",
            "cgroup.procs",
        ]
        .contains(&name)
        {
            return Err(invalid("Unsupported cgroup observation"));
        }
        self.read(name)
    }

    /// Enumerate children only after confirming that the path still names this
    /// descriptor. The caller decides which names belong to its recovery scope.
    pub fn children(&self) -> io::Result<Vec<String>> {
        self.verify_path()?;
        let mut children = Vec::new();
        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                children.push(
                    entry
                        .file_name()
                        .into_string()
                        .map_err(|_| invalid("Invalid cgroup child name"))?,
                );
            }
        }
        children.sort();
        Ok(children)
    }

    /// Bound the supervisor leaf while retaining the pool's inherited CPU cap.
    /// Sandbox leaves use set_limits, which also requires a finite CPU quota.
    pub fn set_supervisor_limits(&self, memory: u64, tasks: u64) -> io::Result<()> {
        let page = rustix::param::page_size() as u64;
        let memory = memory / page * page;
        if memory == 0 || tasks == 0 {
            return Err(invalid("Supervisor limits must be positive"));
        }
        for (name, expected) in [
            ("memory.max", memory.to_string()),
            ("memory.swap.max", "0".into()),
            ("pids.max", tasks.to_string()),
            ("memory.oom.group", "1".into()),
        ] {
            self.write(name, &expected)?;
            if self.read(name)?.trim() != expected {
                return Err(invalid("Supervisor cgroup limit was not applied"));
            }
        }
        Ok(())
    }

    fn read(&self, name: &str) -> io::Result<String> {
        let file = File::from(openat(
            &*self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        observation(file, name)
    }

    fn write(&self, name: &str, value: &str) -> io::Result<()> {
        File::from(openat(
            &*self.directory,
            name,
            OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?)
        .write_all(value.as_bytes())
    }

    /// Create a new owned child without adopting an existing directory.
    /// Apply and verify limits before placing any sandbox process in it.
    pub fn create_child(&self, name: &str) -> io::Result<Self> {
        if !component(name) {
            return Err(invalid("Invalid cgroup child name"));
        }
        self.verify_path()?;
        let path = self.path.join(name);
        fs::create_dir(&path)?;
        match Self::open(&path) {
            Ok(group) => Ok(group),
            Err(error) => {
                // No process has been placed through this handle. If another
                // privileged actor populated the group, rmdir fails and retains it.
                let _ = fs::remove_dir(&path);
                Err(error)
            }
        }
    }

    /// Enable domain controllers after the caller has moved internal processes
    /// to leaves. Kernel refusal is fatal; no controller or process is bypassed.
    pub fn enable_children(&self) -> io::Result<()> {
        let available = self.read("cgroup.controllers")?;
        let available: BTreeSet<_> = available.split_whitespace().collect();
        if CONTROLLERS.iter().any(|name| !available.contains(name)) {
            return Err(invalid("Delegate cpu, memory and pids controllers"));
        }
        let enabled = self.read("cgroup.subtree_control")?;
        let enabled: BTreeSet<_> = enabled.split_whitespace().collect();
        if CONTROLLERS.iter().any(|name| !enabled.contains(name)) {
            self.write("cgroup.subtree_control", "+cpu +memory +pids")?;
        }
        let actual = self.read("cgroup.subtree_control")?;
        let actual: BTreeSet<_> = actual.split_whitespace().collect();
        if CONTROLLERS.iter().any(|name| !actual.contains(name)) {
            return Err(invalid("Delegated controllers were not enabled"));
        }
        Ok(())
    }

    /// Read back the actual limits, including page rounding, before execution.
    /// Leaf OOM kills all its descendants; a shared session parent allows the
    /// kernel to select a leaf without killing every independent shell.
    pub fn set_limits(&self, limits: Limits) -> io::Result<()> {
        let (memory, quota) = limits.values()?;
        for (name, expected) in [
            ("memory.max", memory.to_string()),
            ("memory.swap.max", "0".into()),
            ("pids.max", limits.tasks_max.to_string()),
            ("cpu.max", format!("{quota} 100000")),
            ("memory.oom.group", u8::from(limits.oom_group).to_string()),
        ] {
            self.write(name, &expected)?;
            if self.read(name)?.trim() != expected {
                return Err(invalid("Cgroup limit was not applied"));
            }
        }
        // Both interfaces are required, even if the current workload never OOMs.
        self.oom_kills()?;
        self.populated()?;
        let _ = openat(
            &*self.directory,
            "cgroup.kill",
            OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(())
    }

    /// Trusted child entry only: join before UID/GID drop or untrusted execution.
    /// The caller must also retain the child handle until placement or containment.
    pub fn place_current_process(&self) -> io::Result<()> {
        self.write("cgroup.procs", "0")?;
        let pid = std::process::id().to_string();
        if !self.read("cgroup.procs")?.lines().any(|line| line == pid) {
            return Err(invalid("Launcher did not enter its cgroup"));
        }
        Ok(())
    }

    pub fn oom_kills(&self) -> io::Result<u64> {
        field(&self.read("memory.events")?, "oom_kill")
    }

    pub fn populated(&self) -> io::Result<bool> {
        match field(&self.read("cgroup.events")?, "populated")? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid("Invalid cgroup populated state")),
        }
    }

    /// Pause or resume the owned subtree and confirm the kernel transition.
    /// Callers serialize temporary freezes with longer-lived admission pauses.
    pub fn set_frozen(&self, frozen: bool, timeout: Duration) -> io::Result<()> {
        self.write("cgroup.freeze", if frozen { "1" } else { "0" })?;
        let deadline = Instant::now() + timeout;
        loop {
            if field(&self.read("cgroup.events")?, "frozen")? == u64::from(frozen) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Cgroup freeze transition remains unconfirmed",
                ));
            }
            thread::sleep(Duration::from_millis(2));
        }
    }

    /// Fence and reap any launcher that could still join before invoking this.
    /// A successful kill write alone is not proof that descendants have exited.
    pub fn kill_and_wait(&self, timeout: Duration) -> io::Result<()> {
        self.kill()?;
        let deadline = Instant::now() + timeout;
        while self.populated()? {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Cgroup containment remains unconfirmed",
                ));
            }
            thread::sleep(Duration::from_millis(2));
        }
        Ok(())
    }

    /// Request a kernel-wide descendant kill; callers must still observe emptiness.
    pub fn kill(&self) -> io::Result<()> {
        self.write("cgroup.kill", "1")
    }

    fn verify_path(&self) -> io::Result<()> {
        let named = open(
            &self.path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let actual = fstat(named)?;
        let held = fstat(&*self.directory)?;
        if (actual.st_dev, actual.st_ino) != (held.st_dev, held.st_ino) {
            return Err(invalid("Owned cgroup path was replaced"));
        }
        Ok(())
    }

    /// Only an empty leaf can be removed. Children are not recursively adopted.
    pub fn remove_empty(&self) -> io::Result<()> {
        if self.populated()? {
            return Err(invalid("Cannot remove a populated cgroup"));
        }
        self.verify_path()?;
        fs::remove_dir(&self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hierarchy_root_is_readable_with_implicit_or_explicit_domain_type() {
        let root = Path::new("/sys/fs/cgroup");
        assert!(root.join("cgroup.controllers").is_file());
        let group = Cgroup::open(root).unwrap();
        assert!(group.parent().unwrap().is_none());
    }

    #[test]
    fn recovery_can_observe_the_supported_task_population_without_unbounding_counters() {
        let pids = (2_000_000_000_u32..2_000_008_192)
            .map(|pid| format!("{pid}\n"))
            .collect::<String>();
        assert_eq!(observation(pids.as_bytes(), "cgroup.procs").unwrap(), pids);
        assert!(observation(pids.as_bytes(), "memory.events").is_err());
        assert!(observation("1\n".repeat(70_000).as_bytes(), "cgroup.procs").is_err());
    }

    #[test]
    fn observation_errors_never_mean_zero_oom_or_empty() {
        for text in [
            "",
            "oom 0\n",
            "oom_kill max\n",
            "oom_kill 0 1\n",
            "oom_kill 0\noom_kill 1\n",
        ] {
            assert!(field(text, "oom_kill").is_err(), "{text}");
        }
        assert_eq!(
            field("oom 2\noom_kill 3\nfuture 9\n", "oom_kill").unwrap(),
            3
        );
    }

    #[test]
    fn limits_reject_zero_and_overflow_and_round_memory_down() {
        let page = rustix::param::page_size() as u64;
        let valid = Limits {
            memory_bytes: page * 2 + 1,
            tasks_max: 64,
            cpu_quota_percent: 200,
            oom_group: true,
        };
        assert_eq!(valid.values().unwrap(), (page * 2, 200_000));
        for invalid in [
            Limits {
                memory_bytes: page - 1,
                ..valid
            },
            Limits {
                tasks_max: 0,
                ..valid
            },
            Limits {
                cpu_quota_percent: 0,
                ..valid
            },
            Limits {
                cpu_quota_percent: u64::MAX,
                ..valid
            },
        ] {
            assert!(invalid.values().is_err());
        }
    }

    #[test]
    fn a_child_name_cannot_escape_or_select_kernel_interfaces() {
        for name in [
            "",
            ".",
            "..",
            "../foreign",
            "a/b",
            "cgroup.procs",
            "cgroup.kill",
            "a\0b",
        ] {
            assert!(!component(name), "{name}");
        }
        assert!(component("session-00000000-0000-4000-8000-000000000001"));
    }

    #[test]
    fn ordinary_directory_is_not_a_cgroup() {
        assert!(Cgroup::open(Path::new("/usr")).is_err());
    }
}
