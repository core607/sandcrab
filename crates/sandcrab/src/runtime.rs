//! A generic run owns a bounded workspace, a cgroup and protected launch records.
//! No workspace or record is removed before launcher and descendant containment.
use crate::{
    config::{Config, Profile, invalid},
    storage::{Attachment, Store},
};
use rustix::fs::{Gid, OFlags, Uid, chown};
use sandcrab_core::{
    cgroup::{Cgroup, Limits},
    command::{Channel, EndReason, Request as CommandRequest},
    fs::{mounted, protected_directory},
    process::{Child, Input, Launch},
    unit::checked,
    uuid,
};
use sandcrab_core::{install, job};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    root: PathBuf,
    tools: PathBuf,
    settings: PathBuf,
    uid: u32,
    gid: u32,
    parent_pid: u32,
    cgroup: PathBuf,
    command: Vec<String>,
    shell: bool,
    workspace: PathBuf,
    rootfs: Option<PathBuf>,
    host_calls: bool,
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
    pub templates: Arc<crate::templates::Store>,
    pub storage: Option<Arc<Store>>,
    workspaces: Arc<crate::workspaces::Store>,
    pub config: Config,
    resources: crate::delegation::Delegation,
    executable: PathBuf,
    _lock: fs::File,
}
pub struct Control<'a> {
    pub cancelled: &'a AtomicBool,
    pub calls: Option<Arc<crate::host_calls::Calls>>,
}

pub(crate) struct SetupError {
    pub error: io::Error,
    pub contained: bool,
}
impl From<io::Error> for SetupError {
    fn from(error: io::Error) -> Self {
        Self {
            error,
            contained: true,
        }
    }
}

pub(crate) fn prepare_launch(
    parent: &Cgroup,
    name: &str,
    profile: &Profile,
    arguments: Vec<String>,
) -> Result<Launch, SetupError> {
    let group = parent.create_child(name)?;
    let result = (|| {
        group.set_limits(Limits {
            memory_bytes: profile.memory_bytes,
            tasks_max: profile.tasks_max,
            cpu_quota_percent: profile.cpu_quota_percent,
            oom_group: true,
        })?;
        Launch::new(arguments, group.clone())
    })();
    result.map_err(|error| SetupError {
        error,
        contained: group
            .kill_and_wait(Duration::from_secs(15))
            .and_then(|()| group.remove_empty())
            .is_ok(),
    })
}

impl Runtime {
    pub fn start(config: Config) -> io::Result<Self> {
        let executable = std::env::current_exe()?.canonicalize()?;
        sandcrab_launch::trusted_executable(&executable).map_err(io::Error::other)?;
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
        directory(&root.join("helper-jobs"), 0o700)?;
        let resources = crate::delegation::Delegation::start(&config.service)?;
        let storage = config
            .storage
            .clone()
            .map(|s| {
                Store::open(
                    s,
                    json!({"version":2,
            "runtimeRoot":config.service.runtime_root,"cgroupRoot":config.service.cgroup_root}),
                )
            })
            .transpose()?;
        let runtime = Self {
            files: crate::file_records::Store::open(&config)?,
            templates: crate::templates::Store::open(
                root,
                json!({"version":1,"runtimeRoot":root,"cgroupRoot":config.service.cgroup_root}),
                config.service.max_templates,
                config.service.template_pool_bytes,
            )?,
            workspaces: crate::workspaces::Store::open(
                root,
                json!({"version":1,
                "runtimeRoot":config.service.runtime_root,"cgroupRoot":config.service.cgroup_root}),
            )?,
            storage,
            config,
            resources,
            executable,
            _lock: lock,
        };
        runtime.cleanup()?;
        runtime.templates.recover()?;
        for stage in runtime.files.pending_stages() {
            runtime.clean_stage(&stage)?;
        }
        runtime.files.recovered()?;
        if let Some(storage) = &runtime.storage {
            storage.recover()?;
        }
        runtime.workspaces.probe_overlay(
            runtime
                .config
                .profiles
                .values()
                .next()
                .expect("validated profile"),
            &crate::helper::Context {
                runtime_root: &runtime.config.service.runtime_root,
                executable: &runtime.executable,
                workloads: &runtime.resources.workloads,
            },
        )?;
        Ok(runtime)
    }

    pub fn cleanup(&self) -> io::Result<()> {
        self.resources.cleanup()?;
        let root = &self.config.service.runtime_root;
        for entry in fs::read_dir(root.join("jobs"))? {
            let entry = entry?;
            if !entry.file_name().to_str().is_some_and(uuid) {
                return Err(invalid("Unexpected workspace entry"));
            }
            release(&entry.path(), &[])?;
        }
        for entry in fs::read_dir(root.join("helper-jobs"))? {
            let entry = entry?;
            if !entry.file_name().to_str().is_some_and(|name| {
                ["file-", "copy-", "overlay-"]
                    .iter()
                    .any(|prefix| name.strip_prefix(prefix).is_some_and(uuid))
            }) {
                return Err(invalid("Unexpected helper workspace entry"));
            }
            release(&entry.path(), &[])?;
        }
        self.workspaces.recover()?;
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
        input: Input,
    ) -> (io::Result<Value>, bool) {
        let execute = || -> io::Result<(io::Result<Value>, bool)> {
            self.resources.verify()?;
            let operation = sandcrab_core::new_uuid()?;
            let record = self
                .config
                .service
                .runtime_root
                .join("file-ops")
                .join(format!("{operation}.json"));
            create(&record, job, 0, 0o400)?;
            let mut readonly = vec![record.as_path()];
            let mut writable = vec![job.stage.as_path()];
            if ["snapshot", "sdk-query"].contains(&job.action.as_str()) {
                readonly.push(&job.workspace);
            }
            // Renaming across two bind mounts fails with EXDEV even on the same
            // filesystem. Publication binds their protected common parent once.
            if ["publish", "stream-publish", "sdk-publish", "sdk-mutate"]
                .contains(&job.action.as_str())
            {
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
            let (finished, contained) = crate::helper::Context {
                runtime_root: &self.config.service.runtime_root,
                executable: &self.executable,
                workloads: &self.resources.workloads,
            }
            .run(
                profile,
                cancelled,
                input,
                crate::helper::Request {
                    kind: "file",
                    overlay: None,
                    id: &operation,
                    argv: vec![
                        self.executable.to_string_lossy().into(),
                        "__file".into(),
                        record.to_string_lossy().into(),
                    ],
                    read_only: readonly.into_iter().map(Path::to_path_buf).collect(),
                    writable: writable.into_iter().map(Path::to_path_buf).collect(),
                    timeout: Duration::from_millis(timeout),
                    output_limit: if ["sdk-query", "sdk-mutate"].contains(&job.action.as_str()) {
                        65536
                    } else {
                        16384
                    },
                },
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
                multipart: None,
                selection: None,
            };
            let (result, contained) =
                self.file_helper(&job, profile, &AtomicBool::new(false), Input::Null);
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
        (timeout, limit): (u64, usize),
        control: Control<'_>,
        on_output: impl FnMut(usize, &[u8]),
    ) -> (io::Result<job::Finished>, io::Result<()>) {
        let Control { cancelled, calls } = control;
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
                Ok((mut launch, mailbox)) => {
                    match start_calls(calls.as_ref(), mailbox.as_ref(), id) {
                        Ok(mut guard) => {
                            let (result, contained) = job::run(
                                &mut launch,
                                cancelled,
                                Duration::from_millis(timeout),
                                limit,
                                on_output,
                            );
                            let ended = guard.as_mut().map(|g| g.finish()).transpose().map(|_| ());
                            let closed = mailbox.map(|m| m.close()).transpose().map(|_| ());
                            (result, contained.and(ended).and(closed))
                        }
                        Err(error) => (
                            Err(error),
                            launch
                                .finish(None, Duration::from_secs(15))
                                .map(|_| ())
                                .and(mailbox.map(|m| m.close()).transpose().map(|_| ())),
                        ),
                    }
                }
                Err(error) => (
                    Err(error.error),
                    if error.contained {
                        Ok(())
                    } else {
                        Err(invalid("Launch setup containment unconfirmed"))
                    },
                ),
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
        shared: Option<crate::file_access::ShellLease>,
    ) -> Result<Shell, OpenError> {
        match self.prepare_shell(request, profile, cancelled, shared.as_ref()) {
            Ok(mut shell) => {
                shell.shared = shared;
                Ok(shell)
            }
            Err(error) => {
                if let Some(shared) = shared {
                    shared.finish(error.contained);
                }
                Err(error)
            }
        }
    }

    fn prepare_shell(
        &self,
        request: &crate::sessions::Open,
        profile: &Profile,
        cancelled: Arc<AtomicBool>,
        shared: Option<&crate::file_access::ShellLease>,
    ) -> Result<Shell, OpenError> {
        let id = request.id.as_str();
        let resources = shared
            .map(|s| Ok(s.access.resources.clone()))
            .unwrap_or_else(|| crate::session_resources::Group::new(&self.resources.workloads, id))
            .map_err(|_| OpenError {
                code: "SESSION_UNAVAILABLE",
                contained: true,
            })?;
        let volume = request.volume_id.as_deref().filter(|_| shared.is_none());
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
        let cleanup_root = || {
            if shared.is_none() {
                resources.stop()?;
            }
            release(&root, &records)
        };
        if shared.is_none() && resources.start(profile).is_err() {
            return Err(OpenError {
                code: "SESSION_UNAVAILABLE",
                contained: cleanup_root().is_ok(),
            });
        }
        let disk = if shared.is_none() && attachment.is_none() {
            let prepared = if let Some(template_id) = &request.template_id {
                let template = match self.templates.acquire(template_id, profile) {
                    Ok(template) => template,
                    Err((_, code)) => {
                        return Err(OpenError {
                            code,
                            contained: cleanup_root().is_ok(),
                        });
                    }
                };
                self.workspaces.create_template(
                    id,
                    profile,
                    &cancelled,
                    template,
                    &crate::helper::Context {
                        runtime_root: &self.config.service.runtime_root,
                        executable: &self.executable,
                        workloads: &self.resources.workloads,
                    },
                )
            } else {
                self.workspaces.create(id, profile, &cancelled)
            };
            match prepared {
                Ok(disk) => Some(disk),
                Err(error) => {
                    eprintln!("Workspace setup failed: {}", error.error);
                    return Err(OpenError {
                        code: "SESSION_UNAVAILABLE",
                        contained: error.contained && cleanup_root().is_ok(),
                    });
                }
            }
        } else {
            None
        };
        let cleanup = || {
            cleanup_root()?;
            disk.as_ref()
                .map_or(Ok(()), crate::workspaces::Workspace::remove)
        };
        if request.rootfs
            && let Some(disk) = &disk
        {
            let prepared = (|| -> io::Result<()> {
                crate::rootfs::prepare(&disk.path(), profile)?;
                disk.usage.refresh(true, &cancelled);
                disk.usage.allow_growth().map_err(invalid)
            })();
            if let Err(error) = prepared {
                eprintln!("Rootfs setup failed: {error}");
                return Err(OpenError {
                    code: "ROOTFS_UNAVAILABLE",
                    contained: cleanup().is_ok(),
                });
            }
        }
        let workspace = shared
            .map(|s| s.access.workspace.clone())
            .or_else(|| attachment.as_ref().map(Attachment::path))
            .or_else(|| {
                disk.as_ref().map(|disk| {
                    let path = disk.path();
                    if request.rootfs {
                        path.join("workspace")
                    } else {
                        path
                    }
                })
            })
            .expect("Parent session has a volume or disk workspace");
        let (mut launch, mailbox) = match self.prepare(
            &root,
            &records,
            profile,
            &[],
            None,
            Some((&workspace, &resources, request.rootfs)),
        ) {
            Ok(launch) => launch,
            Err(error) => {
                return Err(OpenError {
                    code: "SESSION_UNAVAILABLE",
                    contained: error.contained && cleanup().is_ok(),
                });
            }
        };
        let child = match launch.spawn(Input::Pipe) {
            Ok(child) => child,
            Err(_) => {
                return Err(OpenError {
                    code: "SESSION_UNAVAILABLE",
                    contained: launch.finish(None, Duration::from_secs(15)).is_ok()
                        && cleanup().is_ok(),
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
            files: shared.map(|s| s.access.clone()).unwrap_or_else(|| {
                crate::file_access::Access::new(
                    request,
                    profile.clone(),
                    workspace,
                    resources.clone(),
                    cancelled,
                    request
                        .volume_id
                        .as_deref()
                        .and_then(|id| self.storage.as_ref().and_then(|store| store.usage(id)))
                        .or_else(|| disk.as_ref().map(|disk| disk.usage.clone())),
                    request
                        .volume_id
                        .as_ref()
                        .and_then(|_| self.storage.as_ref().and_then(|store| store.pool_usage())),
                )
            }),
            channel,
            launch,
            root,
            records,
            attachment,
            mailbox,
            resources,
            shared: None,
            disk,
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
        if let Err(error) = self.resources.verify() {
            return (Err(error), Ok(()));
        }
        let storage = self.storage.as_ref().expect("configured volume store");
        let pool = storage.config.root.join("data");
        crate::helper::Context {
            runtime_root: &self.config.service.runtime_root,
            executable: &self.executable,
            workloads: &self.resources.workloads,
        }
        .run(
            profile,
            stopped,
            Input::Null,
            crate::helper::Request {
                kind: "copy",
                overlay: None,
                id: operation,
                argv: vec![
                    self.executable.to_string_lossy().into(),
                    "__copy-tree".into(),
                    source.to_string_lossy().into(),
                    destination.to_string_lossy().into(),
                    pool.to_string_lossy().into(),
                ],
                read_only: vec![pool],
                writable: vec![destination.into()],
                timeout: Duration::from_millis(profile.timeout_millis),
                output_limit: 65536,
            },
        )
    }

    fn prepare(
        &self,
        root: &Path,
        records: &[PathBuf; 2],
        profile: &Profile,
        argv: &[String],
        timeout: Option<u64>,
        session: Option<(&Path, &crate::session_resources::Group, bool)>,
    ) -> Result<(Launch, Option<Arc<sandcrab_core::mailbox::Mailbox>>), SetupError> {
        let workspace = session.map(|(workspace, _, _)| workspace);
        let rootfs = session
            .filter(|(_, _, rootfs)| *rootfs)
            .map(|(workspace, _, _)| {
                workspace
                    .parent()
                    .map(Path::to_path_buf)
                    .ok_or_else(|| invalid("Missing rootfs workspace parent"))
            })
            .transpose()?;
        let parent = match session {
            Some((_, resources, _)) => resources.kernel()?,
            None => self.resources.workloads.clone(),
        };
        let id = root
            .file_name()
            .and_then(|s| s.to_str())
            .filter(|s| uuid(s))
            .ok_or_else(|| invalid("Invalid workspace identity"))?;
        self.resources.verify()?;
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
        directory(&root.join("tmp"), 0o755)?;
        call(&[
            "mount",
            "-t",
            "tmpfs",
            "-o",
            &format!(
                "size={},nr_inodes={},mode=1777,nosuid,nodev",
                profile.temporary_bytes, profile.temporary_inodes
            ),
            "tmpfs",
            &root.join("tmp").to_string_lossy(),
        ])?;
        directory(&root.join("bootstrap"), 0o555)?;
        directory(&root.join("work"), 0o750)?;
        owned(&root.join("work"), profile.uid, profile.gid, 0o750)?;
        let mailbox = if profile.host_calls {
            Some(Arc::new(sandcrab_core::mailbox::Mailbox::create(
                &root.join("calls"),
                profile.gid,
                &["call"],
            )?))
        } else {
            None
        };
        let [record, settings] = records;
        create(
            record,
            &Record {
                root: root.into(),
                tools: profile.tools.clone(),
                settings: settings.clone(),
                uid: profile.uid,
                gid: profile.gid,
                parent_pid: std::process::id(),
                cgroup: parent.path().join(format!("run-{id}")),
                command: argv.into(),
                shell: timeout.is_none(),
                workspace: workspace.unwrap_or(&root.join("work")).into(),
                rootfs: rootfs.clone(),
                host_calls: profile.host_calls,
            },
            profile.gid,
            0o440,
        )?;
        let mut read = Vec::new();
        if rootfs.is_none() {
            read = profile.read_only.clone();
            for path in [&profile.tools, &root.join("bootstrap")] {
                if !read.contains(path) {
                    read.push(path.clone());
                }
            }
        }
        create(
            settings,
            &json!({"network":{"allowedDomains":[],"deniedDomains":[],"allowAllUnixSockets":false},
            "filesystem":{"denyRead":["/","/sys"],"allowRead":read,"allowWrite":[],"denyWrite":[]},"enableWeakerNestedSandbox":false}),
            profile.gid,
            0o440,
        )?;
        let launch = prepare_launch(
            &parent,
            &format!("run-{id}"),
            profile,
            vec![
                self.executable.to_string_lossy().into(),
                "__launch".into(),
                record.to_string_lossy().into(),
            ],
        )?;
        Ok((launch, mailbox))
    }
}

fn start_calls(
    calls: Option<&Arc<crate::host_calls::Calls>>,
    mailbox: Option<&Arc<sandcrab_core::mailbox::Mailbox>>,
    execution: &str,
) -> io::Result<Option<crate::host_calls::Guard>> {
    let result = match (calls, mailbox) {
        (Some(calls), Some(mailbox)) => calls.start(mailbox.clone(), execution).map(Some),
        (None, None) => Ok(None),
        _ => Err(invalid("Host-call profile mismatch")),
    };
    if result.is_err()
        && let Some(calls) = calls
    {
        calls.fail("HOST_CALL_UNAVAILABLE");
    }
    result
}

pub(crate) fn release(root: &Path, records: &[PathBuf]) -> io::Result<()> {
    if !fs::symlink_metadata(root)?.is_dir() {
        return Err(invalid("Invalid workspace directory"));
    }
    let temporary = root.join("tmp");
    if mounted(&temporary)? {
        if !fs::symlink_metadata(&temporary)?.is_dir() {
            return Err(invalid("Invalid private temporary directory"));
        }
        call(&["umount", &temporary.to_string_lossy()])?;
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

/// Trusted child joins its configured cgroup and drops identity before sandbox setup.
pub fn launch(path: &Path) -> io::Result<()> {
    let value =
        sandcrab_core::parse(&launch_file(path)?).map_err(|_| invalid("Invalid launch JSON"))?;
    let record: Record = serde_json::from_value(value)?;
    if record.uid == 0 || record.gid == 0 {
        return Err(invalid("Wrong execution account"));
    }
    sandcrab_core::process::enter(
        &Cgroup::open(&record.cgroup)?,
        record.uid,
        record.gid,
        record.parent_pid,
    )?;
    let bwrap = sandcrab_launch::verify_bundled_bwrap(&std::env::current_exe()?)
        .map_err(io::Error::other)?;
    let seccomp = sandcrab_launch::Seccomp::new().map_err(io::Error::other)?;
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
    if let Some(rootfs) = &record.rootfs {
        if record.workspace != rootfs.join("workspace") {
            return Err(invalid("Rootfs workspace identity changed"));
        }
        crate::rootfs::mount(&mut args, rootfs)?;
    }
    let separator = args
        .iter()
        .position(|s| {
            s == if record.rootfs.is_some() {
                "--seccomp"
            } else {
                "--remount-ro"
            }
        })
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
    if record.host_calls {
        let binary = std::env::current_exe()?.canonicalize()?;
        sandcrab_launch::trusted_executable(&binary).map_err(io::Error::other)?;
        args.splice(
            separator..separator,
            [
                "--dir".into(),
                "/sandcrab".into(),
                "--ro-bind".into(),
                binary.to_string_lossy().into(),
                "/sandcrab/sandcrab".into(),
                "--bind".into(),
                record.root.join("calls").to_string_lossy().into(),
                crate::host_calls::DIRECTORY.into(),
            ],
        );
    }
    let mut mounts = vec![
        "--bind".into(),
        record.root.join("tmp").to_string_lossy().into(),
        "/tmp".into(),
    ];
    if record.rootfs.is_none() {
        mounts.extend([
            "--bind".into(),
            record.workspace.to_string_lossy().into(),
            "/workspace".into(),
        ]);
    }
    mounts.extend(["--chdir".into(), "/workspace".into()]);
    args.splice(separator..separator, mounts);
    let path = if record.rootfs.is_some() {
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into()
    } else {
        format!("{}:/usr/bin:/bin", record.tools.display())
    };
    let mut environment = vec![
        ("HOME".into(), "/workspace".into()),
        ("TMPDIR".into(), "/tmp".into()),
        (
            "PATH".into(),
            format!(
                "{}{}",
                if record.host_calls { "/sandcrab:" } else { "" },
                path
            ),
        ),
        ("SANDBOX_RUNTIME".into(), "1".into()),
    ];
    if record.host_calls && !record.shell {
        environment.push((
            "SANDBOX_EXECUTION_ID".into(),
            record.root.file_name().unwrap().to_string_lossy().into(),
        ));
    }
    Err(io::Error::other(sandcrab_launch::exec(
        &args,
        &environment,
        &seccomp,
    )))
}

/// Owns one persistent shell. Storage can be released only after its launcher and cgroup stop.
pub struct OpenError {
    pub code: &'static str,
    pub contained: bool,
}
pub struct Shell {
    pub files: Arc<crate::file_access::Access>,
    pub channel: Channel<Child>,
    launch: Launch,
    root: PathBuf,
    records: [PathBuf; 2],
    attachment: Option<Attachment>,
    mailbox: Option<Arc<sandcrab_core::mailbox::Mailbox>>,
    resources: crate::session_resources::Group,
    shared: Option<crate::file_access::ShellLease>,
    disk: Option<crate::workspaces::Workspace>,
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
            |_, _| {},
        );
        result.reason.is_none() && !result.shell_exited && result.exit_code == 0
    }

    pub fn close(mut self) -> io::Result<()> {
        if self.shared.is_none() {
            self.files.stop();
        }
        self.launch
            .finish(Some(self.channel.process()), Duration::from_secs(15))?;
        if self.shared.is_none() {
            self.files.wait()?;
        }
        if let Some(mailbox) = &self.mailbox {
            mailbox.close()?;
        }
        if self.shared.is_none() {
            self.resources.stop()?;
        }
        release(&self.root, &self.records)?;
        if let Some(disk) = self.disk.take() {
            disk.remove()?;
        }
        if let Some(attachment) = self.attachment.take() {
            attachment.release();
        }
        if let Some(shared) = self.shared.take() {
            shared.finish(true);
        }
        Ok(())
    }

    pub fn execute(
        &mut self,
        id: &str,
        command: &str,
        timeout: u64,
        limit: usize,
        control: Control<'_>,
        on_output: impl FnMut(usize, &[u8]),
    ) -> (job::Finished, bool) {
        let Control { cancelled, calls } = control;
        let mut guard = match if self.mailbox.is_some() {
            sandcrab_core::unit::frozen(self.launch.group().path(), cancelled, || {
                start_calls(calls.as_ref(), self.mailbox.as_ref(), id)
            })
        } else {
            start_calls(calls.as_ref(), None, id)
        } {
            Ok(guard) => guard,
            Err(_) => {
                if let Some(calls) = &calls {
                    calls.fail("HOST_CALL_UNAVAILABLE");
                }
                return (
                    job::Finished {
                        exit_code: 1,
                        output: [Vec::new(), Vec::new()],
                        truncated: false,
                        end: job::End::Normal,
                    },
                    false,
                );
            }
        };
        let result = self.channel.execute(
            CommandRequest {
                execution: id,
                command,
                timeout: Duration::from_millis(timeout),
                output_limit: limit,
            },
            cancelled,
            || {},
            on_output,
        );
        let oom = self.launch.group().oom_kills();
        let observation_failed = oom.is_err();
        let end = match result.reason {
            Some(EndReason::Timeout) => job::End::Timeout,
            Some(EndReason::OutputLimit) => job::End::OutputLimit,
            Some(EndReason::Cancelled) => job::End::Cancelled,
            _ if oom.is_ok_and(|count| count > 0) => job::End::ResourceLimit,
            _ => job::End::Normal,
        };
        let mut reusable = !observation_failed && !result.shell_exited && end == job::End::Normal;
        if let Some(guard) = &mut guard {
            let ended = if reusable {
                sandcrab_core::unit::frozen(self.launch.group().path(), cancelled, || {
                    guard.finish()
                })
            } else {
                guard.finish()
            };
            if ended.is_err() {
                if let Some(calls) = &calls {
                    calls.fail("HOST_CALL_CLEANUP_FAILED");
                }
                reusable = false;
            }
        }
        (
            job::Finished {
                exit_code: i32::from(result.exit_code),
                output: result.captured.output,
                truncated: result.captured.truncated.into_iter().any(|t| t),
                end,
            },
            reusable,
        )
    }
}
