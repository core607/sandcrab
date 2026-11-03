//! Provision the default installation without replacing operator files or rotating its token.
use crate::{auth, config::invalid};
use sandcrab_core::fs::{normal, protected_directory, protected_file};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::Command,
};

pub const CONFIG: &str = "/etc/sandcrab/config.toml";
const USER: &str = "sandcrab-exec";
const TOKEN: &str = "/etc/sandcrab/token";
const SYSTEMD_GROUP: &str = "/sys/fs/cgroup/sandcrab.slice/sandcrab.service";
const APPARMOR: &str = "/etc/apparmor.d/sandcrab-service";
const POLICY: &str = include_str!("../install/sandcrab.apparmor");

fn metadata(path: &Path) -> io::Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(info) => Ok(Some(info)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

enum Action {
    Directory(&'static str, u32),
    Text(&'static str, u32, String),
    Token,
    Account,
    Command(&'static str, Vec<&'static str>),
    WaitForService,
}

fn checked_parent(path: &Path) -> io::Result<()> {
    // Planned directories may not exist during preflight. Existing ancestors may never be links.
    for parent in path.ancestors().skip(1) {
        if metadata(parent)?.is_some() {
            return protected_directory(parent);
        }
    }
    Err(invalid("Installation needs a protected parent directory"))
}

fn command(program: &str, args: &[&str]) -> io::Result<()> {
    if Command::new(program).args(args).status()?.success() {
        Ok(())
    } else {
        Err(invalid(format!("{program} {} failed", args.join(" "))))
    }
}

fn write_new(path: &Path, mode: u32, data: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| invalid("Missing parent"))?;
    protected_directory(parent)?;
    let tmp = parent.join(format!(".sandcrab-{}", sandcrab_core::new_uuid()?));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    let written = (|| {
        file.write_all(data)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            &tmp,
            rustix::fs::CWD,
            path,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        fs::File::open(parent)?.sync_all()
    })();
    if written.is_err() {
        let _ = fs::remove_file(tmp);
    }
    written
}

impl Action {
    fn perform(&self, write: bool, explain: bool) -> io::Result<()> {
        let show = |text: String| {
            if explain {
                println!("{text}");
            }
        };
        match self {
            Self::Directory(name, mode) => {
                let path = Path::new(name);
                checked_parent(path)?;
                if metadata(path)?.is_some() {
                    protected_directory(path)?;
                } else {
                    show(format!("create directory {name} ({mode:04o})"));
                    if write {
                        fs::DirBuilder::new().mode(*mode).create(path)?;
                        fs::set_permissions(path, fs::Permissions::from_mode(*mode))?;
                    }
                }
            }
            Self::Text(name, mode, text) => {
                let path = Path::new(name);
                checked_parent(path)?;
                if let Some(info) = metadata(path)? {
                    if *name == CONFIG {
                        if info.nlink() != 1 {
                            return Err(invalid("Use a singly linked Sandcrab configuration"));
                        }
                        let bytes = protected_file(path, 65536)?;
                        crate::config::Config::parse(
                            std::str::from_utf8(&bytes).map_err(io::Error::other)?,
                        )?;
                        show(format!("keep existing configuration {name}"));
                        return Ok(());
                    }
                    if !info.is_file()
                        || info.uid() != 0
                        || info.nlink() != 1
                        || info.mode() & 0o7777 != *mode
                        || info.len() != text.len() as u64
                        || fs::read(path)? != text.as_bytes()
                    {
                        return Err(invalid(format!(
                            "Existing {name} differs; no files were replaced. Manage this installation explicitly."
                        )));
                    }
                } else {
                    show(format!("create {name} ({mode:04o}):\n{text}"));
                    if write {
                        write_new(path, *mode, text.as_bytes())?;
                    }
                }
            }
            Self::Token => {
                let path = Path::new(TOKEN);
                checked_parent(path)?;
                if metadata(path)?.is_some() {
                    auth::read_token(path, 0)?;
                } else {
                    show(format!(
                        "generate a private random loopback token in {TOKEN} (0600)"
                    ));
                    if write {
                        write_new(path, 0o600, auth::Token::random()?.text().as_bytes())?;
                    }
                }
            }
            Self::Account => {
                let entry = Command::new("/usr/bin/getent")
                    .args(["passwd", USER])
                    .output()?;
                if entry.status.success() {
                    let passwd = std::str::from_utf8(&entry.stdout).map_err(io::Error::other)?;
                    let fields: Vec<_> = passwd.trim_end().split(':').collect();
                    let groups = Command::new("/usr/bin/id").args(["-Gn", USER]).output()?;
                    if fields.len() != 7
                        || fields[0] != USER
                        || fields[5] != "/nonexistent"
                        || fields[6] != "/usr/sbin/nologin"
                        || !groups.status.success()
                        || groups.stdout != format!("{USER}\n").as_bytes()
                    {
                        return Err(invalid(
                            "sandcrab-exec is already in use as another account",
                        ));
                    }
                    sandcrab_core::install::execution_account(USER, 0, 0)?;
                } else if entry.status.code() == Some(2) {
                    let args = [
                        "--system",
                        "--user-group",
                        "--no-create-home",
                        "--home-dir",
                        "/nonexistent",
                        "--shell",
                        "/usr/sbin/nologin",
                        USER,
                    ];
                    show(format!("/usr/sbin/useradd {}", args.join(" ")));
                    if write {
                        command("/usr/sbin/useradd", &args)?;
                    }
                } else {
                    return Err(invalid("Cannot look up the execution account"));
                }
            }
            Self::Command(program, args) => {
                show(format!("{program} {}", args.join(" ")));
                if write {
                    command(program, args)?;
                }
            }
            Self::WaitForService => {
                show("wait for authenticated service discovery".into());
                if write {
                    let cfg = crate::config::Config::load(Path::new(CONFIG))?;
                    crate::doctor::wait_for_service(&cfg)?;
                }
            }
        }
        Ok(())
    }
}

fn default_config(group: &str) -> String {
    let mounts = ["/usr", "/bin", "/lib", "/lib64", "/etc/ld.so.cache"]
        .into_iter()
        .filter(|s| Path::new(s).exists())
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(", ");
    include_str!("../install/default.toml")
        .replace("@CGROUP@", group)
        .replace("@MOUNTS@", &mounts)
}

pub fn install(dry_run: bool, container: bool) -> io::Result<()> {
    let exe = std::env::current_exe()?;
    if !dry_run && rustix::process::geteuid().as_raw() != 0 {
        return Err(invalid("Run install as root or use --dry-run"));
    }
    if !normal(&exe) {
        return Err(invalid("Install the release at a protected, absolute path"));
    }
    sandcrab_launch::trusted_executable(&exe).map_err(io::Error::other)?;
    sandcrab_launch::verify_bundled_bwrap(&exe).map_err(io::Error::other)?;
    for name in ["/usr/bin/python3", "/bin/bash", "/usr/sbin/nologin"] {
        if !Path::new(name).is_file() {
            return Err(invalid(format!(
                "Install the host package providing {name}"
            )));
        }
    }
    if container {
        let group = sandcrab_core::cgroup::Cgroup::open(Path::new("/sys/fs/cgroup"))?;
        if std::process::id() != 1
            || fs::read_to_string("/proc/self/cgroup")?.trim() != "0::/"
            || !group.path().join("memory.max").is_file()
        {
            return Err(invalid(
                "Container startup requires PID 1 in a bounded private cgroup namespace",
            ));
        }
        crate::delegation::verify_pool(&group)?;
    }
    let group = if container {
        "/sys/fs/cgroup"
    } else {
        SYSTEMD_GROUP
    };
    let config = default_config(group);
    crate::config::Config::parse(&config)?;
    use Action::*;
    let mut steps = vec![
        Directory("/etc/sandcrab", 0o700),
        Directory("/var/lib/sandcrab", 0o755),
        Directory("/var/lib/sandcrab/tools", 0o755),
        Directory("/var/lib/sandcrab/storage", 0o755),
        Directory("/var/lib/sandcrab/storage/data", 0o711),
        Account,
        Token,
        Text(CONFIG, 0o600, config),
    ];
    if !container {
        let restricted =
            match fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") {
                Ok(v) => v.trim() == "1",
                Err(e) if e.kind() == io::ErrorKind::NotFound => false,
                Err(e) => return Err(e),
            };
        // A systemd container inherits its host-selected profile. Never load policy into a shared host kernel from it.
        let system_container =
            Path::new("/run/systemd/container").exists() || Path::new("/.dockerenv").exists();
        let restricted = restricted && !system_container;
        if restricted {
            if !Path::new("/usr/sbin/apparmor_parser").is_file() {
                return Err(invalid(
                    "Install apparmor to permit user namespaces for the Sandcrab service",
                ));
            }
            steps.extend([
                Text(APPARMOR, 0o644, POLICY.into()),
                Command("/usr/sbin/apparmor_parser", vec!["-r", APPARMOR]),
            ]);
        }
        let unit = include_str!("../install/sandcrab.service")
            .replace("@EXECUTABLE@", exe.to_str().unwrap())
            .replace(
                "@APPARMOR@",
                if restricted {
                    "AppArmorProfile=sandcrab-service"
                } else {
                    ""
                },
            );
        steps.extend([
            Text(
                "/etc/systemd/system/sandcrab.slice",
                0o644,
                include_str!("../install/sandcrab.slice").into(),
            ),
            Text("/etc/systemd/system/sandcrab.service", 0o644, unit),
            Command("/usr/bin/systemctl", vec!["daemon-reload"]),
            Command(
                "/usr/bin/systemctl",
                vec!["enable", "--now", "sandcrab.service"],
            ),
            WaitForService,
        ]);
    }
    for step in &steps {
        step.perform(false, !container)?;
    }
    if !dry_run {
        for step in &steps {
            step.perform(true, false)?;
        }
    }
    Ok(())
}
