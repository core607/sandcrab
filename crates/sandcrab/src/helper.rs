//! Trusted root file helpers keep a bounded cgroup, private temporary storage and
//! a restricted bwrap view. They never run caller-selected programs as root.
use crate::{
    config::{Profile, invalid},
    runtime::{SetupError, prepare_launch, release},
};
use sandcrab_core::{
    cgroup::Cgroup,
    fs::{normal, protected_file},
    job,
    process::Input,
    unit::checked,
    uuid,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{DirBuilder, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::Duration,
};

pub struct Request<'a> {
    pub kind: &'a str,
    pub id: &'a str,
    pub argv: Vec<String>,
    pub read_only: Vec<PathBuf>,
    pub writable: Vec<PathBuf>,
    pub overlay: Option<crate::overlay::Spec>,
    pub timeout: Duration,
    pub output_limit: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    root: PathBuf,
    cgroup: PathBuf,
    parent_pid: u32,
    tools: PathBuf,
    executable: PathBuf,
    argv: Vec<String>,
    read_only: Vec<PathBuf>,
    writable: Vec<PathBuf>,
    overlay: Option<crate::overlay::Spec>,
}

pub struct Context<'a> {
    pub runtime_root: &'a Path,
    pub executable: &'a Path,
    pub workloads: &'a Cgroup,
}

fn mount(path: &Path, profile: &Profile, mode: &str) -> io::Result<()> {
    checked(
        &[
            "mount".into(),
            "-t".into(),
            "tmpfs".into(),
            "-o".into(),
            format!(
                "size={},nr_inodes={},mode={mode},nosuid,nodev",
                profile.temporary_bytes, profile.temporary_inodes
            ),
            "tmpfs".into(),
            path.to_string_lossy().into(),
        ],
        Duration::from_secs(15),
    )
    .map(|_| ())
}

impl Context<'_> {
    pub fn run(
        &self,
        profile: &Profile,
        cancelled: &AtomicBool,
        input: Input,
        request: Request<'_>,
    ) -> (io::Result<job::Finished>, io::Result<()>) {
        if !["file", "copy", "overlay"].contains(&request.kind) || !uuid(request.id) {
            return (Err(invalid("Invalid helper identity")), Ok(()));
        }
        let name = format!("{}-{}", request.kind, request.id);
        let root = self.runtime_root.join("helper-jobs").join(&name);
        if let Err(error) = DirBuilder::new().mode(0o700).create(&root) {
            return (Err(error), Ok(()));
        }
        let prepared = (|| -> Result<_, SetupError> {
            mount(&root, profile, "0700")?;
            DirBuilder::new()
                .mode(0o555)
                .create(root.join("bootstrap"))?;
            DirBuilder::new().mode(0o755).create(root.join("tmp"))?;
            mount(&root.join("tmp"), profile, "1777")?;
            let record = Record {
                root: root.clone(),
                cgroup: self.workloads.path().join(&name),
                parent_pid: std::process::id(),
                tools: profile.tools.clone(),
                executable: self.executable.into(),
                argv: request.argv,
                read_only: request.read_only,
                writable: request.writable,
                overlay: request.overlay,
            };
            let path = root.join("launch.json");
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(&path)?
                .write_all(&serde_json::to_vec(&record).map_err(io::Error::other)?)?;
            prepare_launch(
                self.workloads,
                &name,
                profile,
                vec![
                    self.executable.to_string_lossy().into(),
                    "__helper".into(),
                    path.to_string_lossy().into(),
                ],
            )
        })();
        let (result, contained) = match prepared {
            Ok(mut launch) => job::run_input(
                &mut launch,
                cancelled,
                request.timeout,
                request.output_limit,
                input,
                |_, _| {},
            ),
            Err(error) => (
                Err(error.error),
                if error.contained {
                    Ok(())
                } else {
                    Err(invalid("Helper setup containment unconfirmed"))
                },
            ),
        };
        (result, contained.and_then(|()| release(&root, &[])))
    }
}

/// This self-exec entry accepts only the daemon's protected helper record.
pub fn launch(path: &Path) -> io::Result<()> {
    let value = sandcrab_core::parse(&protected_file(path, 65536)?)
        .map_err(|_| invalid("Invalid helper launch record"))?;
    let record: Record = serde_json::from_value(value)?;
    let executable = std::env::current_exe()?.canonicalize()?;
    if path.parent() != Some(record.root.as_path())
        || record.executable != executable
        || record.argv.first().map(Path::new) != Some(executable.as_path())
        || !matches!(record.argv.get(1).map(String::as_str), Some("__file" | "__template-layer") if record.argv.len() == 3)
            && !matches!(record.argv.get(1).map(String::as_str), Some("__copy-tree") if record.argv.len() == 5)
            && !matches!(record.argv.get(1).map(String::as_str),Some("__overlay-export") if record.argv.len()==2)
        || record.overlay.is_some()
            != (record.argv.get(1).map(String::as_str) == Some("__overlay-export"))
        || record
            .read_only
            .iter()
            .chain(&record.writable)
            .any(|path| !normal(path))
    {
        return Err(invalid("Invalid trusted helper authority"));
    }
    sandcrab_core::process::enter(&Cgroup::open(&record.cgroup)?, 0, 0, record.parent_pid)?;
    if record.overlay.is_some() {
        let input = io::stdin();
        if rustix::net::sockopt::socket_type(&input)? != rustix::net::SocketType::DGRAM {
            return Err(invalid("Invalid overlay channel type"));
        }
        let peer = rustix::net::sockopt::socket_peercred(&input)?;
        if !peer.uid.is_root()
            || u32::try_from(peer.pid.as_raw_pid()).ok() != Some(record.parent_pid)
        {
            return Err(invalid("Invalid overlay channel owner"));
        }
    }
    sandcrab_launch::trusted_executable(&executable).map_err(io::Error::other)?;
    let bwrap = sandcrab_launch::verify_bundled_bwrap(&executable).map_err(io::Error::other)?;
    let seccomp = if record.overlay.is_some() {
        sandcrab_launch::Seccomp::for_overlay_export()
    } else {
        sandcrab_launch::Seccomp::new()
    }
    .map_err(io::Error::other)?;
    sandcrab_launch::enter_bootstrap(&record.root).map_err(io::Error::other)?;
    let mut read = ["/usr", "/bin", "/lib", "/lib64", "/etc/ld.so.cache"]
        .into_iter()
        .map(PathBuf::from)
        .filter(|path| path.exists())
        .collect::<Vec<_>>();
    read.extend([record.tools, executable]);
    let policy = serde_json::json!({"network":{"allowedDomains":[],"deniedDomains":[],"allowAllUnixSockets":false},
        "filesystem":{"denyRead":["/","/sys"],"allowRead":read,"allowWrite":[],"denyWrite":[]},
        "enableWeakerNestedSandbox":false});
    let mut arguments = sandcrab_launch::sandbox_arguments(
        &bwrap,
        &seccomp,
        &policy,
        &record.argv,
        sandcrab_launch::NamespaceMode::FileHelper,
    )
    .map_err(io::Error::other)?;
    let boundary = arguments
        .iter()
        .position(|argument| argument == "--remount-ro")
        .ok_or_else(|| invalid("Missing helper root boundary"))?;
    let mut grants = Vec::<String>::new();
    if record.argv.get(1).map(String::as_str) == Some("__template-layer") {
        grants.extend(["--cap-add".into(), "CAP_MKNOD".into()]);
    }
    if let Some(overlay) = &record.overlay {
        grants.extend(overlay.arguments()?);
    }
    for capability in ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER"] {
        grants.extend(["--cap-add".into(), capability.into()]);
    }
    for (flag, paths) in [("--ro-bind", record.read_only), ("--bind", record.writable)] {
        for path in paths {
            grants.extend([
                flag.into(),
                path.to_string_lossy().into(),
                path.to_string_lossy().into(),
            ]);
        }
    }
    grants.extend([
        "--bind".into(),
        record.root.join("tmp").to_string_lossy().into(),
        "/tmp".into(),
        "--chdir".into(),
        "/".into(),
    ]);
    arguments.splice(boundary..boundary, grants);
    Err(io::Error::other(sandcrab_launch::exec(
        &arguments,
        &[
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("TMPDIR".into(), "/tmp".into()),
        ],
        &seccomp,
    )))
}
