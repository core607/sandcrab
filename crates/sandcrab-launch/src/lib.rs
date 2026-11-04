#![forbid(unsafe_code)]
//! Fail-closed sandbox launch. Supervisors verify the pinned tools before serving; the
//! unprivileged launcher verifies them again, translates a fixed policy into bubblewrap
//! arguments and replaces itself with bubblewrap carrying the compiled seccomp filter.
//! No failure falls back to an unsandboxed command.
mod seccomp;
pub use seccomp::Seccomp;
use std::{
    collections::HashSet,
    fmt, fs,
    io::{self, Read},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Component, Path, PathBuf},
    process::Command,
};

use rustix::fs::{Mode, OFlags, open, openat};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

include!(concat!(env!("OUT_DIR"), "/bwrap.rs"));

/// A refused launch or verification; the message names the failed requirement.
#[derive(Debug, PartialEq, Eq)]
pub struct Error(pub String);
impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self(format!("Sandbox launch unavailable: {error}"))
    }
}
fn refuse(message: &str) -> Error {
    Error(message.into())
}

/// The file and every ancestor are root-owned and unwritable by other accounts, none is a
/// symbolic link, and the file is an executable regular file.
pub fn trusted_executable(path: &Path) -> Result<(), Error> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(refuse("Sandbox tool paths must be absolute"));
    }
    for current in path.ancestors() {
        let info = fs::symlink_metadata(current)?;
        let expected = if current == path {
            info.file_type().is_file()
        } else {
            info.file_type().is_dir()
        };
        if !expected || info.uid() != 0 || info.mode() & 0o022 != 0 {
            return Err(Error(format!(
                "Sandbox tools and their parents must be root-owned and not writable by other accounts: {}",
                current.display()
            )));
        }
    }
    if fs::metadata(path)?.permissions().mode() & 0o111 == 0 {
        return Err(refuse("Sandbox tool is not executable"));
    }
    Ok(())
}

/// The directory bound into sandboxes contains exactly `programs`, each trusted.
pub fn verify_programs(directory: &Path, programs: &[&str]) -> Result<(), Error> {
    let names = fs::read_dir(directory)?
        .map(|entry| entry.map(|e| e.file_name()))
        .collect::<io::Result<HashSet<_>>>()?;
    let expected = programs
        .iter()
        .map(|name| name.into())
        .collect::<HashSet<_>>();
    if fs::symlink_metadata(directory)?.file_type().is_symlink() || names != expected {
        return Err(refuse(
            "Sandbox program directory must contain only the expected executables",
        ));
    }
    for name in programs {
        trusted_executable(&directory.join(name))?;
    }
    Ok(())
}

/// Verify the pinned helper beside the resolved executable, without running unverified code.
/// Both service startup and each unprivileged launch check its ownership and exact digest.
pub fn verify_bundled_bwrap(executable: &Path) -> Result<PathBuf, Error> {
    let bwrap = executable.with_file_name("bwrap");
    trusted_executable(&bwrap)?;
    let file = fs::File::from(
        open(
            &bwrap,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    let mut bytes = Vec::new();
    file.take(BWRAP_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != BWRAP_BYTES || Sha256::digest(&bytes)[..] != BWRAP_SHA256 {
        return Err(refuse(
            "Bundled bubblewrap checksum mismatch; install the complete matching release",
        ));
    }
    Ok(bwrap)
}

/// Python's `posixpath.normpath`, so a grant is accepted only in its normalized spelling.
fn normalized(path: &str) -> String {
    let leading = if path.starts_with("//") && !path.starts_with("///") {
        2
    } else {
        usize::from(path.starts_with('/'))
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." if leading == 0 && (parts.is_empty() || parts.last() == Some(&"..")) => {
                parts.push(part)
            }
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    let text = "/".repeat(leading) + &parts.join("/");
    if text.is_empty() { ".".into() } else { text }
}
/// Component-wise containment in either direction.
fn overlapping(a: &str, b: &str) -> bool {
    Path::new(a).starts_with(b) || Path::new(b).starts_with(a)
}
fn grants(value: &Value) -> Result<Vec<String>, Error> {
    let paths = value
        .as_array()
        .ok_or_else(|| refuse("Sandbox grants must be distinct path lists"))?;
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for path in paths {
        let Some(path) = path.as_str() else {
            return Err(refuse("Sandbox grants must be normalized absolute paths"));
        };
        if !path.starts_with('/') || path == "/" || path.contains('\0') || normalized(path) != path
        {
            return Err(refuse("Sandbox grants must be normalized absolute paths"));
        }
        if !seen.insert(path) {
            return Err(refuse("Sandbox grants must be distinct path lists"));
        }
        result.push(path.to_owned());
    }
    Ok(result)
}
fn keys(value: &Value) -> Option<HashSet<&str>> {
    value
        .as_object()
        .map(|object| object.keys().map(String::as_str).collect())
}

/// Only an acknowledged, already private proxy network can be retained by a workload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamespaceMode {
    Workload,
    ProxyNetwork,
    /// Fixed daemon-owned file operations need host UID mappings for chown.
    FileHelper,
}

/// Translate the worker policy into bubblewrap arguments carrying the filter descriptor and
/// the literal command. Unknown fields, weaker settings, network exceptions and overlapping
/// grants are refused instead of ignored.
pub fn sandbox_arguments(
    bwrap: &Path,
    seccomp: &Seccomp,
    policy: &Value,
    command: &[String],
    namespaces: NamespaceMode,
) -> Result<Vec<String>, Error> {
    if keys(policy)
        != Some(HashSet::from([
            "filesystem",
            "network",
            "enableWeakerNestedSandbox",
        ]))
        || policy["enableWeakerNestedSandbox"] != false
        || policy["network"]
            != json!({"allowedDomains": [], "deniedDomains": [], "allowAllUnixSockets": false})
    {
        return Err(refuse("Unsupported sandbox policy"));
    }
    let files = &policy["filesystem"];
    if keys(files)
        != Some(HashSet::from([
            "denyRead",
            "allowRead",
            "denyWrite",
            "allowWrite",
        ]))
        || files["denyRead"] != json!(["/", "/sys"])
        || files["denyWrite"] != json!([])
    {
        return Err(refuse("Unsupported sandbox filesystem policy"));
    }
    let read = grants(&files["allowRead"])?;
    let write = grants(&files["allowWrite"])?;
    if read.iter().any(|a| write.iter().any(|b| overlapping(a, b))) {
        return Err(refuse("Sandbox read and write grants must be disjoint"));
    }
    let mut args: Vec<String> = vec![
        bwrap.to_string_lossy().into(),
        "--new-session".into(),
        "--die-with-parent".into(),
        "--cap-drop".into(),
        "ALL".into(),
    ];
    let flags: &[&str] = match namespaces {
        // --unshare-all only tries user and cgroup namespaces. Require both.
        NamespaceMode::Workload | NamespaceMode::ProxyNetwork => &[
            "--unshare-all",
            "--unshare-user",
            "--unshare-cgroup",
            "--disable-userns",
        ],
        NamespaceMode::FileHelper => &[
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-uts",
            "--unshare-cgroup",
            "--unshare-net",
        ],
    };
    args.extend(flags.iter().map(|flag| (*flag).to_owned()));
    if namespaces == NamespaceMode::ProxyNetwork {
        args.push("--share-net".into());
    }
    args.extend(["--hostname".into(), "sandcrab".into()]);
    for path in &read {
        if path == "/dev" || path == "/proc" {
            continue;
        }
        let link = ["/bin", "/lib", "/lib64"].contains(&path.as_str())
            && fs::symlink_metadata(path).is_ok_and(|info| info.file_type().is_symlink());
        if link {
            // Preserve the usr-merged layout without exposing a resolved target outside a grant.
            let resolved = fs::canonicalize(path)?;
            if !read
                .iter()
                .any(|grant| grant != path && resolved.starts_with(grant))
            {
                return Err(refuse(
                    "Sandbox system link resolves outside readable paths",
                ));
            }
            let target = fs::read_link(path)?;
            args.extend([
                "--symlink".into(),
                target.to_string_lossy().into(),
                path.clone(),
            ]);
        } else {
            args.extend(["--ro-bind".into(), path.clone(), path.clone()]);
        }
    }
    for path in &write {
        args.extend(["--bind".into(), path.clone(), path.clone()]);
    }
    // Empty-root scaffolding must not be writable; individual write mounts remain writable.
    args.extend(["--dev", "/dev", "--proc", "/proc", "--remount-ro", "/"].map(String::from));
    args.extend([
        "--seccomp".into(),
        seccomp.descriptor().to_string(),
        "--".into(),
    ]);
    args.extend(command.iter().cloned());
    Ok(args)
}

/// Make `root/bootstrap` the working directory without following a link at either step,
/// so startup never inspects a command-mutated directory.
pub fn enter_bootstrap(root: &Path) -> Result<(), Error> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let root = open(root, flags, Mode::empty()).map_err(io::Error::from)?;
    let bootstrap = openat(&root, "bootstrap", flags, Mode::empty()).map_err(io::Error::from)?;
    rustix::process::fchdir(&bootstrap).map_err(io::Error::from)?;
    Ok(())
}

/// Replace this process with bubblewrap; returns only if the replacement failed.
pub fn exec(arguments: &[String], environment: &[(String, String)], seccomp: &Seccomp) -> Error {
    if let Err(error) = seccomp.prepare_exec() {
        return error;
    }
    let error = Command::new(&arguments[0])
        .args(&arguments[1..])
        .env_clear()
        .envs(environment.iter().map(|(k, v)| (k, v)))
        .exec();
    Error::from(error)
}

#[cfg(test)]
mod tests;
