//! Provision, upgrade and remove the service installation without rotating operator secrets.
use crate::{auth, config::invalid};
use rustix::fs::{CWD, Gid, OFlags, RenameFlags, Uid, fchown, renameat_with};
use sandcrab_core::fs::{normal, protected_directory, protected_file};
use sandcrab_core::install::{execution_account, unit_name};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::Command,
};

pub const CONFIG: &str = "/etc/sandcrab/config.toml";
const USER: &str = "sandcrab-exec";
const TOKEN: &str = "/etc/sandcrab/token";
const BIN_LINK: &str = "/usr/local/bin/sandcrab";
const DEFAULT_RELEASE_EXE: &str = "/var/lib/sandcrab-release/sandcrab";
const SYSTEMD_SLICE: &str = "/etc/systemd/system/sandcrab.slice";
const SYSTEMD_SERVICE: &str = "/etc/systemd/system/sandcrab.service";
const SYSTEMD_GROUP: &str = "/sys/fs/cgroup/sandcrab.slice/sandcrab.service";
const APPARMOR: &str = "/etc/apparmor.d/sandcrab-service";
const POLICY: &str = include_str!("../install/sandcrab.apparmor");
const CLIENT_TOKEN_HELP: &str =
    "Usage: sandcrab client-token --user USER --output FILE [--config FILE] [--replace]\n";

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
    Symlink(&'static str, PathBuf),
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

fn write_atomic(path: &Path, mode: u32, data: &[u8], replace: bool) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| invalid("Missing parent"))?;
    protected_directory(parent)?;
    let tmp = parent.join(format!(".sandcrab-{}", sandcrab_core::new_uuid()?));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
        .open(&tmp)?;
    let written = (|| {
        file.write_all(data)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        renameat_with(
            CWD,
            &tmp,
            CWD,
            path,
            if replace {
                RenameFlags::empty()
            } else {
                RenameFlags::NOREPLACE
            },
        )?;
        fs::File::open(parent)?.sync_all()
    })();
    if written.is_err() {
        let _ = fs::remove_file(tmp);
    }
    written
}

fn write_symlink(path: &Path, target: &Path, replace: bool) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| invalid("Missing parent"))?;
    protected_directory(parent)?;
    let tmp = parent.join(format!(".sandcrab-{}", sandcrab_core::new_uuid()?));
    symlink(target, &tmp)?;
    let linked = (|| {
        renameat_with(
            CWD,
            &tmp,
            CWD,
            path,
            if replace {
                RenameFlags::empty()
            } else {
                RenameFlags::NOREPLACE
            },
        )?;
        fs::File::open(parent)?.sync_all()
    })();
    if linked.is_err() {
        let _ = fs::remove_file(tmp);
    }
    linked
}

impl Action {
    fn perform(&self, write: bool, explain: bool, upgrade: bool) -> io::Result<()> {
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
                    let same = info.is_file()
                        && info.uid() == 0
                        && info.nlink() == 1
                        && info.mode() & 0o7777 == *mode
                        && info.len() == text.len() as u64
                        && fs::read(path)? == text.as_bytes();
                    if !same {
                        if !upgrade {
                            return Err(invalid(format!(
                                "Existing {name} differs; no files were replaced. Manage this installation explicitly."
                            )));
                        }
                        if !info.is_file() || info.uid() != 0 || info.nlink() != 1 {
                            return Err(invalid(format!(
                                "Refusing to replace irregular or linked {name}"
                            )));
                        }
                        show(format!("update {name} ({mode:04o}):\n{text}"));
                        if write {
                            write_atomic(path, *mode, text.as_bytes(), true)?;
                        }
                    }
                } else {
                    show(format!("create {name} ({mode:04o}):\n{text}"));
                    if write {
                        write_atomic(path, *mode, text.as_bytes(), false)?;
                    }
                }
            }
            Self::Symlink(name, target) => {
                let path = Path::new(name);
                protected_directory(path.parent().ok_or_else(|| invalid("Missing parent"))?)?;
                match metadata(path)? {
                    None => {
                        show(format!("link {name} -> {}", target.display()));
                        if write {
                            write_symlink(path, target, false)?;
                        }
                    }
                    Some(info) if info.file_type().is_symlink() && info.uid() == 0 => {
                        if fs::read_link(path)? == *target {
                            return Ok(());
                        }
                        if !upgrade {
                            return Err(invalid(format!(
                                "Existing {name} points elsewhere; pass --upgrade or manage it explicitly."
                            )));
                        }
                        show(format!("update link {name} -> {}", target.display()));
                        if write {
                            write_symlink(path, target, true)?;
                        }
                    }
                    Some(_) => {
                        return Err(invalid(format!(
                            "Existing {name} is not a root-owned symlink; no files were replaced."
                        )));
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
                        write_atomic(path, 0o600, auth::Token::random()?.text().as_bytes(), false)?;
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
                    execution_account(USER, 0, 0)?;
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

pub fn install(dry_run: bool, container: bool, upgrade: bool) -> io::Result<()> {
    let exe = std::env::current_exe()?.canonicalize()?;
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
        if protected_directory(Path::new("/usr/local/bin")).is_ok() {
            steps.push(Symlink(BIN_LINK, exe.clone()));
        }
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
                SYSTEMD_SLICE,
                0o644,
                include_str!("../install/sandcrab.slice").into(),
            ),
            Text(SYSTEMD_SERVICE, 0o644, unit),
            Command("/usr/bin/systemctl", vec!["daemon-reload"]),
        ]);
        if upgrade {
            steps.extend([
                Command("/usr/bin/systemctl", vec!["enable", "sandcrab.service"]),
                Command("/usr/bin/systemctl", vec!["restart", "sandcrab.service"]),
            ]);
        } else {
            steps.push(Command(
                "/usr/bin/systemctl",
                vec!["enable", "--now", "sandcrab.service"],
            ));
        }
        steps.push(WaitForService);
    }
    for step in &steps {
        step.perform(false, !container, upgrade)?;
    }
    if !dry_run {
        for step in &steps {
            step.perform(true, false, upgrade)?;
        }
    }
    Ok(())
}

fn regular_root_file(path: &Path) -> io::Result<bool> {
    let Some(info) = metadata(path)? else {
        return Ok(false);
    };
    checked_parent(path)?;
    if !info.is_file() || info.uid() != 0 || info.nlink() != 1 {
        return Err(invalid(format!(
            "Refusing to remove irregular or linked {}",
            path.display()
        )));
    }
    Ok(true)
}

pub fn uninstall(dry_run: bool) -> io::Result<()> {
    if !dry_run && rustix::process::geteuid().as_raw() != 0 {
        return Err(invalid("Run uninstall as root or use --dry-run"));
    }
    let current = std::env::current_exe().and_then(|p| p.canonicalize()).ok();
    let has_service = regular_root_file(Path::new(SYSTEMD_SERVICE))?;
    let has_slice = regular_root_file(Path::new(SYSTEMD_SLICE))?;
    let has_apparmor = regular_root_file(Path::new(APPARMOR))?;

    if has_service {
        println!("/usr/bin/systemctl stop sandcrab.service");
        println!("/usr/bin/systemctl disable sandcrab.service");
        println!("remove {SYSTEMD_SERVICE}");
        if !dry_run {
            command("/usr/bin/systemctl", &["stop", "sandcrab.service"])?;
            let _ = Command::new("/usr/bin/systemctl")
                .args(["disable", "sandcrab.service"])
                .status();
            fs::remove_file(SYSTEMD_SERVICE)?;
        }
    }
    if has_slice {
        println!("/usr/bin/systemctl stop sandcrab.slice");
        println!("remove {SYSTEMD_SLICE}");
        if !dry_run {
            command("/usr/bin/systemctl", &["stop", "sandcrab.slice"])?;
            fs::remove_file(SYSTEMD_SLICE)?;
        }
    }
    if has_service || has_slice {
        println!("/usr/bin/systemctl daemon-reload");
        if !dry_run {
            fs::File::open("/etc/systemd/system")?.sync_all()?;
            command("/usr/bin/systemctl", &["daemon-reload"])?;
            let _ = Command::new("/usr/bin/systemctl")
                .args(["reset-failed", "sandcrab.service", "sandcrab.slice"])
                .status();
        }
    }
    if has_apparmor {
        let system_container =
            Path::new("/run/systemd/container").exists() || Path::new("/.dockerenv").exists();
        if !system_container && Path::new("/usr/sbin/apparmor_parser").is_file() {
            println!("/usr/sbin/apparmor_parser -R {APPARMOR}");
            if !dry_run {
                let _ = Command::new("/usr/sbin/apparmor_parser")
                    .args(["-R", APPARMOR])
                    .status();
            }
        }
        println!("remove {APPARMOR}");
        if !dry_run {
            fs::remove_file(APPARMOR)?;
            fs::File::open("/etc/apparmor.d")?.sync_all()?;
        }
    }
    if protected_directory(Path::new("/usr/local/bin")).is_ok()
        && let Some(info) = metadata(Path::new(BIN_LINK))?
        && info.file_type().is_symlink()
        && info.uid() == 0
    {
        let target = fs::read_link(BIN_LINK)?;
        if target == Path::new(DEFAULT_RELEASE_EXE) || current.as_deref() == Some(target.as_path())
        {
            println!("remove link {BIN_LINK}");
            if !dry_run {
                fs::remove_file(BIN_LINK)?;
                fs::File::open("/usr/local/bin")?.sync_all()?;
            }
        }
    }
    println!("preserve /etc/sandcrab, /var/lib/sandcrab and {USER}");
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct ClientTokenSpec {
    user: String,
    output: PathBuf,
    config: PathBuf,
    replace: bool,
}

fn parse_client_token(args: &[String]) -> io::Result<Option<ClientTokenSpec>> {
    if matches!(args, [flag] if ["--help", "-h"].contains(&flag.as_str())) {
        return Ok(None);
    }
    let (mut user, mut output, mut config, mut replace) = (None, None, None, false);
    let mut iter = args.iter();
    while let Some(key) = iter.next() {
        match key.as_str() {
            "--replace" if !replace => replace = true,
            "--user" if user.is_none() => {
                user = Some(
                    iter.next()
                        .ok_or_else(|| invalid("--user requires an account name"))?
                        .clone(),
                );
            }
            "--output" if output.is_none() => {
                output = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| invalid("--output requires a file path"))?,
                ));
            }
            "--config" if config.is_none() => {
                config = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| invalid("--config requires a file path"))?,
                ));
            }
            _ => return Err(invalid(CLIENT_TOKEN_HELP)),
        }
    }
    let Some(user) = user else {
        return Err(invalid(CLIENT_TOKEN_HELP));
    };
    let Some(output) = output else {
        return Err(invalid(CLIENT_TOKEN_HELP));
    };
    if !unit_name(&user) {
        return Err(invalid("Invalid --user account name"));
    }
    Ok(Some(ClientTokenSpec {
        user,
        output,
        config: config.unwrap_or_else(|| PathBuf::from(CONFIG)),
        replace,
    }))
}

fn id_query(flag: &str, user: &str) -> io::Result<String> {
    let out = Command::new("/usr/bin/id").args([flag, user]).output()?;
    if !out.status.success() {
        return Err(invalid(format!("Unknown account: {user}")));
    }
    String::from_utf8(out.stdout).map_err(|_| invalid("Invalid account output"))
}

fn path_overlaps(candidate: &Path, root: &Path) -> bool {
    if candidate.starts_with(root) || root.starts_with(candidate) {
        return true;
    }
    if let Ok(resolved) = root.canonicalize() {
        return candidate.starts_with(&resolved) || resolved.starts_with(candidate);
    }
    false
}

pub fn client_token(args: &[String]) -> io::Result<()> {
    let Some(spec) = parse_client_token(args)? else {
        print!("{CLIENT_TOKEN_HELP}");
        return Ok(());
    };
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(invalid("Run client-token as root"));
    }
    let uid: u32 = id_query("-u", &spec.user)?
        .trim()
        .parse()
        .map_err(|_| invalid("Invalid numeric UID"))?;
    let gid: u32 = id_query("-g", &spec.user)?
        .trim()
        .parse()
        .map_err(|_| invalid("Invalid numeric GID"))?;
    if uid == 0 {
        return Err(invalid(
            "client-token provisions non-root client copies; root already owns the service token",
        ));
    }
    let groups: Vec<u32> = id_query("-G", &spec.user)?
        .split_whitespace()
        .map(|v| v.parse::<u32>().map_err(|_| invalid("Invalid group list")))
        .collect::<io::Result<_>>()?;

    protected_directory(
        spec.config
            .parent()
            .ok_or_else(|| invalid("Configuration needs a parent directory"))?,
    )?;
    let bytes = protected_file(&spec.config, 65536)?;
    let cfg = crate::config::Config::parse(
        std::str::from_utf8(&bytes).map_err(|_| invalid("Configuration is not UTF-8"))?,
    )?;
    let tcp = cfg
        .tcp
        .as_ref()
        .ok_or_else(|| invalid("Configuration has no [tcp] listener"))?;
    let secret = auth::read_token(&tcp.token_file, 0)?;

    for profile in cfg.profiles.values() {
        let (exec_uid, exec_gid) =
            execution_account(&profile.exec_user, uid, gid).map_err(|_| {
                invalid(
                    "Client account must be distinct from sandbox execution accounts and groups",
                )
            })?;
        if spec.user == profile.exec_user || uid == exec_uid || groups.contains(&exec_gid) {
            return Err(invalid(
                "Client account must be distinct from sandbox execution accounts and groups",
            ));
        }
    }

    let output = std::path::absolute(&spec.output)?;
    if !normal(&output) {
        return Err(invalid(
            "Token output path must be a normalized path without traversal",
        ));
    }
    let parent = output
        .parent()
        .ok_or_else(|| invalid("Token output needs a parent directory"))?;
    for directory in parent.ancestors() {
        let info = fs::symlink_metadata(directory)?;
        if !info.is_dir() || ![0, uid].contains(&info.uid()) || info.mode() & 0o022 != 0 {
            return Err(invalid(
                "Token output ancestors must be nonsymlink directories owned by root or the client and not writable by other accounts",
            ));
        }
    }
    let file_name = output
        .file_name()
        .ok_or_else(|| invalid("Token output needs a file name"))?;
    let resolved_output = parent.canonicalize()?.join(file_name);
    if output == tcp.token_file || resolved_output == tcp.token_file {
        return Err(invalid(
            "Refusing to overwrite the server token_file with a client copy",
        ));
    }
    if path_overlaps(&resolved_output, &cfg.service.runtime_root)
        || cfg
            .storage
            .as_ref()
            .is_some_and(|s| path_overlaps(&resolved_output, &s.root))
        || cfg.profiles.values().any(|p| {
            path_overlaps(&resolved_output, &p.tools)
                || p.read_only
                    .iter()
                    .any(|mount| path_overlaps(&resolved_output, mount))
        })
    {
        return Err(invalid(
            "Token output path must be outside runtime, volume and sandbox-mounted paths",
        ));
    }
    if let Some(existing) = metadata(&output)? {
        if !spec.replace {
            return Err(invalid(
                "Token output already exists; pass --replace to rotate the client copy",
            ));
        }
        if !existing.is_file() || existing.nlink() != 1 {
            return Err(invalid(
                "Existing token output must be a singly linked regular file",
            ));
        }
    }

    let tmp = parent.join(format!(".sandcrab-token-{}", sandcrab_core::new_uuid()?));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
        .open(&tmp)?;
    let written = (|| {
        writeln!(file, "{}", secret.text())?;
        fchown(&file, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.sync_all()?;
        renameat_with(
            CWD,
            &tmp,
            CWD,
            &output,
            if spec.replace {
                RenameFlags::empty()
            } else {
                RenameFlags::NOREPLACE
            },
        )?;
        fs::File::open(parent)?.sync_all()?;
        auth::read_token(&output, uid).map(|_| ())
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written?;
    println!(
        "{}",
        serde_json::json!({
            "tokenFile": output,
            "user": spec.user,
            "uid": uid,
            "gid": gid,
            "mode": "0600"
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vec_args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn client_token_options_accept_arbitrary_order_and_reject_invalid_users() {
        let parsed = parse_client_token(&vec_args(&[
            "--output",
            "/home/app/sandcrab.token",
            "--replace",
            "--user",
            "app-worker",
            "--config",
            "/etc/sandcrab-custom/config.toml",
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(
            parsed,
            ClientTokenSpec {
                user: "app-worker".into(),
                output: PathBuf::from("/home/app/sandcrab.token"),
                config: PathBuf::from("/etc/sandcrab-custom/config.toml"),
                replace: true,
            }
        );
        assert!(
            parse_client_token(&vec_args(&["--help"]))
                .unwrap()
                .is_none()
        );
        for bad in [
            &["--user", "../root", "--output", "/tmp/tok"][..],
            &["--user", "-bad", "--output", "/tmp/tok"][..],
            &["--user", "app"][..],
            &["--output", "/tmp/tok"][..],
            &["--user", "a", "--user", "b", "--output", "/tmp/tok"][..],
        ] {
            assert!(
                parse_client_token(&vec_args(bad)).is_err(),
                "accepted {bad:?}"
            );
        }
    }
}
