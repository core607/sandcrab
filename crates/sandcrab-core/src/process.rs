//! A single trusted launcher and its delegated cgroup share one cleanup lifetime.
//! Clone-time placement precedes the trusted child's identity/mount setup and
//! workload exec. The child handle remains owned before and after exec.
use crate::cgroup::Cgroup;
pub use sandcrab_spawn::{Child, Input, private_mount_namespace};
use std::{
    io,
    os::unix::process::ExitStatusExt,
    path::Path,
    process::ExitStatus,
    thread,
    time::{Duration, Instant},
};

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Fresh, single-threaded trusted child entry. Verify its parent-configured leaf,
/// clear supplementary groups, drop all three UID/GID values and set NNP/umask.
/// UID zero is only for trusted internal helpers whose mount/capability boundary
/// is established before their operation; workload profiles must forbid it.
pub fn enter(group: &Cgroup, uid: u32, gid: u32, parent_pid: u32) -> io::Result<()> {
    use rustix::{
        fs::{Gid, Mode, Uid},
        process::{Signal, geteuid, getppid, set_parent_process_death_signal, umask},
        thread::{set_no_new_privs, set_thread_groups, set_thread_res_gid, set_thread_res_uid},
    };
    let tasks = std::fs::read_dir("/proc/self/task")?.collect::<io::Result<Vec<_>>>()?;
    if !geteuid().is_root() || tasks.len() != 1 || parent_pid == 0 {
        return Err(invalid("Cgroup entry requires a fresh privileged launcher"));
    }
    let guard_parent = || -> io::Result<()> {
        set_parent_process_death_signal(Some(Signal::KILL))?;
        if getppid().and_then(|pid| u32::try_from(pid.as_raw_pid()).ok()) != Some(parent_pid) {
            return Err(invalid("Launcher parent exited before execution"));
        }
        Ok(())
    };
    guard_parent()?;
    group.require_current_process()?;
    // The daemon may be protected from OOM selection. Per-operation systemd
    // units did not inherit that preference; keep workloads and helpers neutral.
    std::fs::write("/proc/self/oom_score_adj", "0")?;
    umask(Mode::from_bits_truncate(0o077));
    set_no_new_privs(true)?;
    set_thread_groups(&[])?;
    let uid = Uid::from_raw(uid);
    let gid = Gid::from_raw(gid);
    set_thread_res_gid(gid, gid, gid)?;
    set_thread_res_uid(uid, uid, uid)?;
    // Credential changes clear PDEATHSIG. Re-arm it and close the parent-loss
    // race before returning to code that can execute the workload. The owning
    // spawning thread must live as long as this child, not merely its daemon TGID.
    guard_parent()
}

pub struct Launch {
    arguments: Vec<String>,
    group: Cgroup,
    oom_before: u64,
    attempted: bool,
    child_pid: Option<u32>,
    finished: bool,
}

/// Observed after launcher reaping and descendant containment, before cgroup removal.
#[derive(Debug)]
pub struct Exit {
    pub status: Option<ExitStatus>,
    pub oom_kills: u64,
}
impl Exit {
    pub fn code(&self) -> Option<i32> {
        self.status.map(|status| {
            status
                .code()
                .or_else(|| status.signal().map(|signal| 128 + signal))
                .unwrap_or(-1)
        })
    }
}

impl Launch {
    /// `arguments` names an absolute, already-verified trusted child entry.
    /// That entry must verify `group` and the intended parent before any
    /// workload can run; this type does not authorize arbitrary host commands.
    pub fn new(arguments: Vec<String>, group: Cgroup) -> io::Result<Self> {
        if arguments
            .first()
            .is_none_or(|path| !Path::new(path).is_absolute())
            || arguments.iter().any(|part| part.contains('\0'))
        {
            return Err(invalid("Invalid trusted launcher arguments"));
        }
        let oom_before = group.oom_kills()?;
        Ok(Self {
            arguments,
            group,
            oom_before,
            attempted: false,
            child_pid: None,
            finished: false,
        })
    }

    pub fn group(&self) -> &Cgroup {
        &self.group
    }

    /// One attempt only, including a failed spawn. Keep the returned Child until
    /// `finish` confirms containment; a missing result never authorizes a retry.
    pub fn spawn(&mut self, input: Input) -> io::Result<Child> {
        if self.attempted || self.finished {
            return Err(invalid("Launcher has already been attempted"));
        }
        self.attempted = true;
        let child = sandcrab_spawn::spawn(
            Path::new(&self.arguments[0]),
            &self.arguments[1..],
            self.group.as_fd(),
            input,
        )?;
        self.child_pid = Some(child.id());
        Ok(child)
    }

    fn owns(&self, child: &Child) -> io::Result<()> {
        if self.child_pid != Some(child.id()) || self.finished {
            return Err(invalid("Launcher process does not belong to this boundary"));
        }
        Ok(())
    }

    /// Interrupt both the owned launcher and its descendants, including a child
    /// still preparing to exec. Final cleanup also requires child reaping.
    pub fn interrupt(&self, child: &mut Child) -> io::Result<()> {
        self.owns(child)?;
        if child.try_wait()?.is_none() {
            // After UID drop, a restricted controller may lack permission to
            // signal the child directly. Its cgroup kill still applies; only
            // finish's observations can establish containment.
            let _ = child.kill();
        }
        self.group.kill()
    }

    /// Kill/reap the known launcher, then confirm all cgroup descendants are gone.
    /// A failure retains the cgroup and makes no admission-release claim. A missing
    /// Child is allowed only when no spawn succeeded. Kernel counters, never exit
    /// status 137 alone, identify OOM. Read them before removing the empty leaf.
    pub fn finish(&mut self, mut child: Option<&mut Child>, timeout: Duration) -> io::Result<Exit> {
        if self.finished {
            return Err(invalid("Launcher boundary has already been finished"));
        }
        match child.as_deref() {
            Some(child) => self.owns(child)?,
            None if self.child_pid.is_some() => {
                return Err(invalid("Launcher handle is required for containment"));
            }
            None => {}
        }
        let deadline = Instant::now() + timeout;
        let status = loop {
            let status = match child.as_deref_mut() {
                Some(child) => {
                    if child.try_wait()?.is_none() {
                        let _ = child.kill();
                    }
                    child.try_wait()?
                }
                None => None,
            };
            self.group.kill()?;
            let populated = self.group.populated()?;
            if (child.is_none() || status.is_some()) && !populated {
                break status;
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Launcher or cgroup containment remains unconfirmed",
                ));
            }
            thread::sleep(Duration::from_millis(2));
        };
        let oom_kills = self
            .group
            .oom_kills()?
            .checked_sub(self.oom_before)
            .ok_or_else(|| invalid("Cgroup OOM observation regressed"))?;
        self.group.remove_empty()?;
        self.finished = true;
        Ok(Exit { status, oom_kills })
    }
}
