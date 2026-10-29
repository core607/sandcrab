//! A generic run owns one quota-bounded workspace, one unit and its protected launch records.
//! No workspace or record is removed until the unit's containment is confirmed.
use crate::{
    config::{Config, Profile, invalid},
    storage::{Attachment, Store},
};
use rustix::fs::{Gid, OFlags, Uid, chown};
use sandcrab_core::{
    command::{Channel, EndReason, Request as CommandRequest},
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
    process::{Command, Stdio},
    sync::{Arc, atomic::AtomicBool},
    thread,
    time::{Duration, Instant},
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    root: PathBuf,
    tools: PathBuf,
    settings: PathBuf,
    uid: u32,
    command: Vec<String>,
    shell: bool,
    workspace: PathBuf,
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
fn create(path: &Path, value: &impl Serialize, gid: u32, mode: u32) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    file.write_all(&serde_json::to_vec(value)?)?;
    owned(path, 0, gid, mode)
}

pub struct Runtime {
    pub files: crate::file_records::Store,
    pub storage: Option<Arc<Store>>,
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
        directory(&root.join("file-ops"), 0o700)?;
        let storage = config.storage.clone().map(|s| Store::open(s, json!({"version":1,
            "runtimeRoot":config.service.runtime_root,"resourceSlice":config.service.resource_slice,"unitPrefix":config.service.unit_prefix}))).transpose()?;
        let runtime = Self {
            files: crate::file_records::Store::open(&config)?,
            storage,
            config,
            pool,
            executable,
            _lock: lock,
        };
        runtime.cleanup()?;
        for stage in runtime.files.pending_stages() {
            runtime.clean_stage(&stage)?;
        }
        runtime.files.recovered()?;
        if let Some(storage) = &runtime.storage {
            storage.recover()?;
        }
        Ok(runtime)
    }

    pub fn cleanup(&self) -> io::Result<()> {
        let prefix = &self.config.service.unit_prefix;
        let units = call(&[
            "systemctl",
            "list-units",
            "--all",
            "--full",
            "--plain",
            "--no-legend",
            &format!("{prefix}*"),
        ])?;
        for line in String::from_utf8_lossy(&units.stdout).lines() {
            let unit = line.split_whitespace().next().unwrap_or_default();
            if !unit
                .strip_prefix(prefix)
                .and_then(|s| s.strip_suffix(".service"))
                .is_some_and(|s| {
                    uuid(s)
                        || s.strip_prefix("volume-").is_some_and(uuid)
                        || s.strip_prefix("file-").is_some_and(uuid)
                })
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
        for entry in fs::read_dir(root.join("file-ops"))? {
            let entry = entry?;
            if !entry
                .file_name()
                .to_str()
                .and_then(|s| s.strip_suffix(".json"))
                .is_some_and(uuid)
            {
                return Err(invalid("Unexpected file operation record"));
            }
            sandcrab_core::fs::protected_file(&entry.path(), 16384)?;
            fs::remove_file(entry.path())?;
        }
        Ok(())
    }

    pub fn file_helper(
        &self,
        job: &crate::file_io::Job,
        profile: &Profile,
        cancelled: &AtomicBool,
        input: Stdio,
    ) -> (io::Result<Value>, bool) {
        let execute = || -> io::Result<(io::Result<Value>, bool)> {
            sandcrab_core::unit::verify_resource_pool(&self.pool)?;
            let operation = sandcrab_core::new_uuid()?;
            let record = self
                .config
                .service
                .runtime_root
                .join("file-ops")
                .join(format!("{operation}.json"));
            create(&record, job, 0, 0o400)?;
            let unit = format!("{}file-{operation}", self.config.service.unit_prefix);
            let limits = sandcrab_core::unit::Profile {
                tools: profile.tools.clone(),
                launcher: self.executable.clone(),
                exec_user: "root".into(),
                resource_slice: self.config.service.resource_slice.clone(),
                supervisor_unit: self.config.service.supervisor_unit.clone(),
                cpu_quota_percent: profile.cpu_quota_percent,
                memory_bytes: profile.memory_bytes,
                tasks_max: profile.tasks_max,
                temporary_bytes: profile.temporary_bytes,
                temporary_inodes: profile.temporary_inodes,
            };
            let mut readonly = vec![record.as_path()];
            let mut writable = vec![job.stage.as_path()];
            if job.action == "snapshot" {
                readonly.push(&job.workspace);
            }
            // Renaming across two bind mounts fails with EXDEV even on the same
            // filesystem. Publication binds their protected common parent once.
            if job.action == "publish" {
                writable = vec![
                    job.stage
                        .parent()
                        .ok_or_else(|| invalid("Missing file stage parent"))?,
                ];
            }
            let timeout = if job.action == "cleanup" {
                10000
            } else {
                30000
            };
            let command = limits.command_with_args(
                &unit,
                &readonly,
                &writable,
                &[
                    self.executable.to_string_lossy().into(),
                    "__file".into(),
                    record.to_string_lossy().into(),
                ],
                Some(timeout),
                &[
                    "OOMPolicy=kill".into(),
                    "ProtectSystem=strict".into(),
                    format!(
                        "ReadWritePaths={}",
                        writable
                            .iter()
                            .map(|p| p.to_string_lossy())
                            .collect::<Vec<_>>()
                            .join(" ")
                    ),
                    "PrivateNetwork=yes".into(),
                    "PrivateDevices=yes".into(),
                    "CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER".into(),
                ],
            );
            let (finished, contained) = job::run_input(
                &Launch {
                    command,
                    unit: unit.clone(),
                    cgroup: self.pool.join(format!("{unit}.service")),
                },
                cancelled,
                Duration::from_millis(timeout),
                16384,
                input,
            );
            if contained.is_ok() {
                fs::remove_file(record)?;
            }
            let value = finished.and_then(|f| {
                if f.end != job::End::Normal {
                    return Err(invalid(match f.end {
                        job::End::Cancelled => "FILE_CANCELLED",
                        job::End::ResourceLimit => "FILE_RESOURCE_LIMIT",
                        _ => "FILE_HELPER_FAILED",
                    }));
                }
                let value: Value = serde_json::from_slice(&f.output[0])?;
                if f.exit_code != 0 {
                    return Err(invalid(
                        value["error"]
                            .as_str()
                            .filter(|s| {
                                s.len() <= 64
                                    && s.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
                            })
                            .unwrap_or("FILE_FAILED"),
                    ));
                }
                Ok(value)
            });
            Ok((value, contained.is_ok()))
        };
        match execute() {
            Ok(value) => value,
            Err(error) => (Err(error), true),
        }
    }

    pub fn clean_stage(&self, stage: &crate::file_records::Stage) -> io::Result<()> {
        if let Some(path) = self.files.validate_stage(stage, &self.config)? {
            let profile = self
                .config
                .profiles
                .get(&stage.profile)
                .ok_or_else(|| invalid("File recovery profile unavailable"))?;
            let job = crate::file_io::Job {
                action: "cleanup".into(),
                workspace: stage.workspace(&self.config)?,
                stage: path,
                path: "unused".into(),
                format: crate::file_io::Format::Raw,
                bytes: 0,
                sha256: String::new(),
                replace: false,
                mode: 0o600,
                uid: stage.uid,
                gid: stage.gid,
                byte_limit: profile.transfer_bytes,
                entry_limit: 10000,
            };
            let (result, contained) =
                self.file_helper(&job, profile, &AtomicBool::new(false), Stdio::null());
            if !contained {
                return Err(invalid("File cleanup containment unconfirmed"));
            }
            result?;
            self.files.validate_stage(stage, &self.config)?;
            fs::remove_file(job.stage.join("owner.json"))?;
            fs::remove_dir(&job.stage)?;
            fs::File::open(job.stage.parent().unwrap())?.sync_all()?;
        }
        self.files.finish_stage(&stage.id)
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
        let (result, contained) =
            match self.prepare(&root, &records, profile, argv, Some(timeout), None) {
                Ok(launch) => job::run(&launch, cancelled, Duration::from_millis(timeout), limit),
                Err(error) => (Err(error), Ok(())),
            };
        let cleanup = contained.and_then(|()| release(&root, &records));
        (result, cleanup)
    }

    /// Prepare a persistent shell. Failed cleanup holds the caller's admission until restart.
    pub fn open_shell(
        &self,
        request: &crate::sessions::Open,
        profile: &Profile,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Shell, OpenError> {
        let id = request.id.as_str();
        let volume = request.volume_id.as_deref();
        let mut attachment = match volume {
            Some(volume) => Some(
                self.storage
                    .as_ref()
                    .ok_or(OpenError {
                        code: "VOLUMES_DISABLED",
                        contained: true,
                    })?
                    .bind(volume, id, profile)
                    .map_err(|e| OpenError {
                        code: e.code,
                        contained: true,
                    })?,
            ),
            None => None,
        };
        let root = self.config.service.runtime_root.join("jobs").join(id);
        if DirBuilder::new().mode(0o750).create(&root).is_err() {
            return Err(OpenError {
                code: "SESSION_UNAVAILABLE",
                contained: true,
            });
        }
        let records = ["launch", "policy"].map(|kind| {
            self.config
                .service
                .runtime_root
                .join("records")
                .join(format!("{id}.{kind}.json"))
        });
        let launch = match self.prepare(
            &root,
            &records,
            profile,
            &[],
            None,
            attachment.as_ref().map(Attachment::path).as_deref(),
        ) {
            Ok(launch) => launch,
            Err(_) => {
                return Err(OpenError {
                    code: "SESSION_UNAVAILABLE",
                    contained: release(&root, &records).is_ok(),
                });
            }
        };
        let child = match Command::new(&launch.command[0])
            .args(&launch.command[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(_) => {
                return Err(OpenError {
                    code: "SESSION_UNAVAILABLE",
                    contained: release(&root, &records).is_ok(),
                });
            }
        };
        // Once launched, a failed owner must retain volume ownership until restart cleanup.
        if let Some(attachment) = &mut attachment {
            attachment.launched();
        }
        let channel = Channel::new(child).map_err(|_| OpenError {
            code: "CONTAINMENT_UNCONFIRMED",
            contained: false,
        })?;
        Ok(Shell {
            files: crate::file_access::Access::new(
                request,
                profile.clone(),
                attachment
                    .as_ref()
                    .map(Attachment::path)
                    .unwrap_or_else(|| root.join("work")),
                launch.cgroup.clone(),
                cancelled,
            ),
            channel,
            launch,
            root,
            records,
            attachment,
        })
    }

    pub fn clone_volume(
        &self,
        operation: &str,
        source: &Path,
        destination: &Path,
        profile: &Profile,
        stopped: &AtomicBool,
    ) -> (io::Result<job::Finished>, io::Result<()>) {
        if let Err(error) = sandcrab_core::unit::verify_resource_pool(&self.pool) {
            return (Err(error), Ok(()));
        }
        let storage = self.storage.as_ref().expect("configured volume store");
        let unit = format!("{}volume-{operation}", self.config.service.unit_prefix);
        let limits = sandcrab_core::unit::Profile {
            tools: profile.tools.clone(),
            launcher: self.executable.clone(),
            exec_user: "root".into(),
            resource_slice: self.config.service.resource_slice.clone(),
            supervisor_unit: self.config.service.supervisor_unit.clone(),
            cpu_quota_percent: profile.cpu_quota_percent,
            memory_bytes: profile.memory_bytes,
            tasks_max: profile.tasks_max,
            temporary_bytes: profile.temporary_bytes,
            temporary_inodes: profile.temporary_inodes,
        };
        let argv = vec![
            self.executable.to_string_lossy().into(),
            "__copy-tree".into(),
            source.to_string_lossy().into(),
            destination.to_string_lossy().into(),
            storage.config.root.join("data").to_string_lossy().into(),
        ];
        let command = limits.command_with_args(
            &unit,
            &[source],
            &[destination],
            &argv,
            Some(profile.timeout_millis),
            &[
                "OOMPolicy=kill".into(),
                "ProtectSystem=strict".into(),
                format!("ReadWritePaths={}", destination.display()),
                "PrivateNetwork=yes".into(),
                "PrivateDevices=yes".into(),
                "CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER".into(),
            ],
        );
        job::run(
            &Launch {
                command,
                unit: unit.clone(),
                cgroup: self.pool.join(format!("{unit}.service")),
            },
            stopped,
            Duration::from_millis(profile.timeout_millis),
            65536,
        )
    }

    fn prepare(
        &self,
        root: &Path,
        records: &[PathBuf; 2],
        profile: &Profile,
        argv: &[String],
        timeout: Option<u64>,
        workspace: Option<&Path>,
    ) -> io::Result<Launch> {
        let id = root
            .file_name()
            .and_then(|s| s.to_str())
            .filter(|s| uuid(s))
            .ok_or_else(|| invalid("Invalid workspace identity"))?;
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
                shell: timeout.is_none(),
                workspace: workspace.unwrap_or(&root.join("work")).into(),
            },
            profile.gid,
            0o440,
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
            0o440,
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
        let mut writable = vec![root];
        if let Some(workspace) = workspace {
            writable.push(workspace);
        }
        // One OOM ends the session, including its shell and background processes.
        // Do not inherit the host's DefaultOOMPolicy.
        let command = limits.command_with_args(
            &unit,
            &[record, settings],
            &writable,
            &[
                self.executable.to_string_lossy().into(),
                "__launch".into(),
                record.to_string_lossy().into(),
            ],
            timeout,
            &["OOMPolicy=kill".into()],
        );
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
    let command = if record.shell {
        vec![
            "/sandcrab-driver".into(),
            "__shell".into(),
            "/workspace".into(),
        ]
    } else {
        record.command
    };
    let mut args = sandcrab_launch::sandbox_arguments(&bwrap, &seccomp, &policy, &command)
        .map_err(io::Error::other)?;
    let separator = args
        .iter()
        .position(|s| s == "--remount-ro")
        .ok_or_else(|| invalid("Missing sandbox root protection"))?;
    if record.shell {
        let binary = std::env::current_exe()?.canonicalize()?;
        sandcrab_launch::trusted_executable(&binary).map_err(io::Error::other)?;
        args.splice(
            separator..separator,
            [
                "--ro-bind".into(),
                binary.to_string_lossy().into(),
                "/sandcrab-driver".into(),
            ],
        );
    }
    args.splice(
        separator..separator,
        [
            "--bind".into(),
            record.workspace.to_string_lossy().into(),
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

/// Owns one persistent unit. Storage can be released only after its launcher and cgroup stop.
pub struct OpenError {
    pub code: &'static str,
    pub contained: bool,
}
pub struct Shell {
    pub files: Arc<crate::file_access::Access>,
    pub channel: Channel,
    launch: Launch,
    root: PathBuf,
    records: [PathBuf; 2],
    attachment: Option<Attachment>,
}
impl Shell {
    pub fn ready(&mut self, cancelled: &AtomicBool) -> bool {
        let id = match sandcrab_core::new_uuid() {
            Ok(id) => id,
            Err(_) => return false,
        };
        let result = self.channel.execute(
            CommandRequest {
                execution: &id,
                command: ":",
                timeout: Duration::from_secs(15),
                output_limit: 4096,
            },
            cancelled,
            || {},
        );
        result.reason.is_none() && !result.shell_exited && result.exit_code == 0
    }

    pub fn close(mut self) -> io::Result<()> {
        self.files.stop();
        let deadline = Instant::now() + Duration::from_secs(15);
        while self.channel.process().try_wait()?.is_none() {
            let _ = call(&[
                "systemctl",
                "kill",
                "--kill-who=all",
                "--signal=KILL",
                &self.launch.unit,
            ]);
            self.channel.drain()?;
            if Instant::now() >= deadline {
                return Err(invalid("Session launcher containment unconfirmed"));
            }
            thread::sleep(Duration::from_millis(50));
        }
        if let Err(error) = call(&["systemctl", "stop", &self.launch.unit]) {
            // Successful transient units may already be collected. A completed launcher
            // plus a witnessed ready frame rules out a registration still in flight.
            if !self.channel.ready()
                || !call(&[
                    "systemctl",
                    "show",
                    &self.launch.unit,
                    "-p",
                    "LoadState",
                    "-p",
                    "ActiveState",
                ])
                .is_ok_and(|state| {
                    state
                        .stdout
                        .split(|b| *b == b'\n')
                        .any(|line| line == b"LoadState=not-found")
                        && state
                            .stdout
                            .split(|b| *b == b'\n')
                            .any(|line| line == b"ActiveState=inactive")
                })
            {
                return Err(error);
            }
        }
        empty_group(&self.launch.cgroup)?;
        self.files.wait()?;
        let _ = call(&["systemctl", "reset-failed", &self.launch.unit]);
        release(&self.root, &self.records)?;
        if let Some(attachment) = self.attachment.take() {
            attachment.release();
        }
        Ok(())
    }

    pub fn execute(
        &mut self,
        id: &str,
        command: &str,
        timeout: u64,
        limit: usize,
        cancelled: &AtomicBool,
    ) -> (job::Finished, bool) {
        let result = self.channel.execute(
            CommandRequest {
                execution: id,
                command,
                timeout: Duration::from_millis(timeout),
                output_limit: limit,
            },
            cancelled,
            || {},
        );
        let end = match result.reason {
            Some(EndReason::Timeout) => job::End::Timeout,
            Some(EndReason::OutputLimit) => job::End::OutputLimit,
            Some(EndReason::Cancelled) => job::End::Cancelled,
            _ if fs::read_to_string(self.launch.cgroup.join("memory.events")).is_ok_and(
                |events| {
                    events.lines().any(|line| {
                        line.split_once(' ').is_some_and(|(key, value)| {
                            key == "oom_kill" && value.trim().parse::<u64>().is_ok_and(|n| n > 0)
                        })
                    })
                },
            ) || (result.shell_exited
                && call(&[
                    "systemctl",
                    "show",
                    &self.launch.unit,
                    "-p",
                    "Result",
                    "--value",
                ])
                .is_ok_and(|value| value.stdout == b"oom-kill\n")) =>
            {
                job::End::ResourceLimit
            }
            _ => job::End::Normal,
        };
        (
            job::Finished {
                exit_code: i32::from(result.exit_code),
                output: result.captured.output,
                truncated: result.captured.truncated.into_iter().any(|t| t),
                end,
            },
            !result.shell_exited && end == job::End::Normal,
        )
    }
}
