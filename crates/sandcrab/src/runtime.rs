//! A generic run owns one quota-bounded workspace, one unit and its protected launch records.
//! No workspace or record is removed until the unit's containment is confirmed.
use crate::config::{Config, Profile, invalid};
use rustix::fs::{Gid, OFlags, Uid, chown};
use sandcrab_core::{
    fs::{mounted, protected_directory},
    unit::{Launch, checked, empty_group},
    uuid,
};
use sandcrab_daemon::{install, job};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::Duration,
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    root: PathBuf,
    tools: PathBuf,
    settings: PathBuf,
    uid: u32,
    command: Vec<String>,
}

fn command(args: &[String]) -> io::Result<std::process::Output> {
    checked(args, Duration::from_secs(15))
}
fn call(args: &[&str]) -> io::Result<std::process::Output> {
    command(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
}
fn owned(path: &Path, uid: u32, gid: u32, mode: u32) -> io::Result<()> {
    chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}
fn directory(path: &Path, mode: u32) -> io::Result<()> {
    match DirBuilder::new().mode(mode).create(path) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
        _ => {}
    }
    protected_directory(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}
fn create(path: &Path, value: &impl Serialize, gid: u32) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    file.write_all(&serde_json::to_vec(value)?)?;
    owned(path, 0, gid, 0o440)
}

pub struct Runtime {
    pub config: Config,
    pool: PathBuf,
    executable: PathBuf,
    _lock: fs::File,
}

impl Runtime {
    pub fn start(config: Config) -> io::Result<Self> {
        let executable = std::env::current_exe()?.canonicalize()?;
        sandcrab_launch::trusted_executable(&executable).map_err(io::Error::other)?;
        let pool = install::resource_pool(&config.service.resource_slice)?;
        let pid = call(&[
            "systemctl",
            "show",
            &config.service.supervisor_unit,
            "-p",
            "MainPID",
            "--value",
        ])?;
        if String::from_utf8_lossy(&pid.stdout)
            .trim()
            .parse::<u32>()
            .ok()
            != Some(std::process::id())
        {
            return Err(invalid("Run serve as the configured supervisor_unit"));
        }
        let root = &config.service.runtime_root;
        protected_directory(
            root.parent()
                .ok_or_else(|| invalid("Runtime root needs a parent"))?,
        )?;
        directory(root, 0o751)?;
        let lock = install::runtime_lock(root)?;
        directory(&root.join("jobs"), 0o711)?;
        directory(&root.join("records"), 0o711)?;
        let runtime = Self {
            config,
            pool,
            executable,
            _lock: lock,
        };
        runtime.cleanup()?;
        Ok(runtime)
    }

    pub fn cleanup(&self) -> io::Result<()> {
        let prefix = &self.config.service.unit_prefix;
        let units = call(&[
            "systemctl",
            "list-units",
            "--all",
            "--plain",
            "--no-legend",
            &format!("{prefix}*"),
        ])?;
        for line in String::from_utf8_lossy(&units.stdout).lines() {
            let unit = line.split_whitespace().next().unwrap_or_default();
            if !unit
                .strip_prefix(prefix)
                .and_then(|s| s.strip_suffix(".service"))
                .is_some_and(uuid)
            {
                return Err(invalid("Unexpected unit in Sandcrab namespace"));
            }
            call(&["systemctl", "stop", unit])?;
            empty_group(&self.pool.join(unit))?;
            let _ = call(&["systemctl", "reset-failed", unit]);
        }
        let root = &self.config.service.runtime_root;
        for entry in fs::read_dir(root.join("jobs"))? {
            let entry = entry?;
            if !entry.file_name().to_str().is_some_and(uuid) {
                return Err(invalid("Unexpected workspace entry"));
            }
            release(&entry.path(), &[])?;
        }
        for entry in fs::read_dir(root.join("records"))? {
            let entry = entry?;
            let name = entry.file_name();
            if !name
                .to_str()
                .and_then(|s| {
                    s.strip_suffix(".launch.json")
                        .or_else(|| s.strip_suffix(".policy.json"))
                })
                .is_some_and(uuid)
                || !entry.file_type()?.is_file()
            {
                return Err(invalid("Unexpected launch record"));
            }
            fs::remove_file(entry.path())?;
        }
        Ok(())
    }

    pub fn run(
        &self,
        id: &str,
        profile: &Profile,
        argv: &[String],
        timeout: u64,
        limit: usize,
        cancelled: &AtomicBool,
    ) -> (io::Result<job::Finished>, io::Result<()>) {
        let root = self.config.service.runtime_root.join("jobs").join(id);
        if let Err(e) = DirBuilder::new().mode(0o750).create(&root) {
            return (Err(e), Ok(()));
        }
        let records = ["launch", "policy"].map(|kind| {
            self.config
                .service
                .runtime_root
                .join("records")
                .join(format!("{id}.{kind}.json"))
        });
        let (result, contained) = match self.prepare(id, &root, &records, profile, argv, timeout) {
            Ok(launch) => job::run(&launch, cancelled, Duration::from_millis(timeout), limit),
            Err(error) => (Err(error), Ok(())),
        };
        let cleanup = contained.and_then(|()| release(&root, &records));
        (result, cleanup)
    }

    fn prepare(
        &self,
        id: &str,
        root: &Path,
        records: &[PathBuf; 2],
        profile: &Profile,
        argv: &[String],
        timeout: u64,
    ) -> io::Result<Launch> {
        sandcrab_core::unit::verify_resource_pool(&self.pool)?;
        let options = format!(
            "size={},nr_inodes={},mode=0750,nosuid,nodev",
            profile.temporary_bytes, profile.temporary_inodes
        );
        call(&[
            "mount",
            "-t",
            "tmpfs",
            "-o",
            &options,
            "tmpfs",
            &root.to_string_lossy(),
        ])?;
        owned(root, 0, profile.gid, 0o750)?;
        directory(&root.join("bootstrap"), 0o555)?;
        directory(&root.join("work"), 0o750)?;
        owned(&root.join("work"), profile.uid, profile.gid, 0o750)?;
        let [record, settings] = records;
        create(
            record,
            &Record {
                root: root.into(),
                tools: profile.tools.clone(),
                settings: settings.clone(),
                uid: profile.uid,
                command: argv.into(),
            },
            profile.gid,
        )?;
        let mut read = profile.read_only.clone();
        for path in [&profile.tools, &root.join("bootstrap")] {
            if !read.contains(path) {
                read.push(path.clone());
            }
        }
        create(
            settings,
            &json!({"network":{"allowedDomains":[],"deniedDomains":[],"allowAllUnixSockets":false},
            "filesystem":{"denyRead":["/","/sys"],"allowRead":read,"allowWrite":["/tmp"],"denyWrite":[]},"enableWeakerNestedSandbox":false}),
            profile.gid,
        )?;
        let unit = format!("{}{id}", self.config.service.unit_prefix);
        let limits = sandcrab_core::unit::Profile {
            tools: profile.tools.clone(),
            launcher: self.executable.clone(),
            exec_user: profile.exec_user.clone(),
            resource_slice: self.config.service.resource_slice.clone(),
            supervisor_unit: self.config.service.supervisor_unit.clone(),
            cpu_quota_percent: profile.cpu_quota_percent,
            memory_bytes: profile.memory_bytes,
            tasks_max: profile.tasks_max,
            temporary_bytes: profile.temporary_bytes,
            temporary_inodes: profile.temporary_inodes,
        };
        let mut command = limits.command(&unit, record, settings, root, Some(timeout));
        command.insert(command.len() - 1, "__launch".into());
        Ok(Launch {
            command,
            cgroup: self.pool.join(format!("{unit}.service")),
            unit,
        })
    }
}

fn release(root: &Path, records: &[PathBuf]) -> io::Result<()> {
    if !fs::symlink_metadata(root)?.is_dir() {
        return Err(invalid("Invalid workspace directory"));
    }
    if mounted(root)? {
        call(&["umount", &root.to_string_lossy()])?;
    }
    // A failed unmount or an unexpected nonempty directory is never recursively removed.
    fs::remove_dir(root)?;
    for record in records {
        match fs::remove_file(record) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    Ok(())
}

fn launch_file(path: &Path) -> io::Result<Vec<u8>> {
    protected_directory(
        path.parent()
            .ok_or_else(|| invalid("Record needs a parent"))?,
    )?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    let info = file.metadata()?;
    if !info.is_file()
        || info.uid() != 0
        || info.mode() & 0o022 != 0
        || info.nlink() != 1
        || info.len() > 65536
    {
        return Err(invalid(
            "Launch record must be a protected root-owned regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(invalid("Launch record too large"));
    }
    Ok(bytes)
}

/// Internal entry point reached only after systemd changes to the profile's execution user.
pub fn launch(path: &Path) -> io::Result<()> {
    let value =
        sandcrab_core::parse(&launch_file(path)?).map_err(|_| invalid("Invalid launch JSON"))?;
    let record: Record = serde_json::from_value(value)?;
    if record.uid == 0 || rustix::process::geteuid().as_raw() != record.uid {
        return Err(invalid("Wrong execution account"));
    }
    let (bwrap, seccomp) =
        sandcrab_launch::verify_tools(&record.tools).map_err(io::Error::other)?;
    let policy: Value = sandcrab_core::parse(&launch_file(&record.settings)?)
        .map_err(|_| invalid("Invalid policy JSON"))?;
    sandcrab_launch::enter_bootstrap(&record.root).map_err(io::Error::other)?;
    let mut args = sandcrab_launch::sandbox_arguments(&bwrap, &seccomp, &policy, &record.command)
        .map_err(io::Error::other)?;
    let separator = args
        .iter()
        .position(|s| s == "--remount-ro")
        .ok_or_else(|| invalid("Missing sandbox root protection"))?;
    args.splice(
        separator..separator,
        [
            "--bind".into(),
            record.root.join("work").to_string_lossy().into(),
            "/workspace".into(),
            "--chdir".into(),
            "/workspace".into(),
        ],
    );
    let environment = vec![
        ("HOME".into(), "/workspace".into()),
        ("TMPDIR".into(), "/tmp".into()),
        (
            "PATH".into(),
            format!("{}:/usr/bin:/bin", record.tools.display()),
        ),
        ("SANDBOX_RUNTIME".into(), "1".into()),
    ];
    Err(io::Error::other(sandcrab_launch::exec(&args, &environment)))
}
