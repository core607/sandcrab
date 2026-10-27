#![forbid(unsafe_code)]
//! Fail-closed sandbox launch. Supervisors verify the pinned tools before serving; the
//! unprivileged launcher verifies them again, translates a fixed policy into bubblewrap
//! arguments and replaces itself with bubblewrap, whose first command installs the pinned
//! seccomp filter. No failure falls back to an unsandboxed command.
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fmt, fs,
    io::{self, Read},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use rustix::fs::{Mode, OFlags, open, openat};
use serde_json::{Value, json};

/// SRT 0.0.75's static x64 helper supplies the filter and its protected PID namespace.
/// A different helper requires the live equivalence probe, not just a version change.
pub const SECCOMP_SHA256: &str = "64fa7514fa7199584b836159885e59b9ce3684fb8fef7e13de49965b23f54f6b";
pub const MIN_BWRAP_VERSION: (u64, u64, u64) = (0, 6, 1);
/// Tool locations below the prepared tools root.
pub const BWRAP: &str = "extracted/usr/bin/bwrap";
pub const SECCOMP: &str =
    "node_modules/@anthropic-ai/sandbox-runtime/vendor/seccomp/x64/apply-seccomp";

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

/// Verify bubblewrap and the pinned seccomp helper below `tools`; used at supervisor
/// startup and again before each launch.
pub fn verify_tools(tools: &Path) -> Result<(PathBuf, PathBuf), Error> {
    verify_pinned_tools(tools, SECCOMP_SHA256)
}
fn verify_pinned_tools(tools: &Path, pin: &str) -> Result<(PathBuf, PathBuf), Error> {
    let bwrap = tools.join(BWRAP);
    let seccomp = tools.join(SECCOMP);
    for path in [&bwrap, &seccomp] {
        trusted_executable(path)?;
    }
    if format!("{:x}", Sha256::digest(fs::read(&seccomp)?)) != pin {
        return Err(refuse(
            "Sandbox apply-seccomp checksum mismatch; prepare the pinned SRT 0.0.75 tools",
        ));
    }
    let version = version_output(&bwrap)?;
    if parse_version(version.trim()).is_none_or(|v| v < MIN_BWRAP_VERSION) {
        return Err(refuse("Sandbox requires bubblewrap 0.6.1 or newer"));
    }
    Ok((bwrap, seccomp))
}
/// `bubblewrap X.Y.Z` with decimal components and nothing else.
fn parse_version(text: &str) -> Option<(u64, u64, u64)> {
    let mut parts = text.strip_prefix("bubblewrap ")?.split('.');
    let mut number = || {
        parts
            .next()
            .filter(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))?
            .parse()
            .ok()
    };
    let version = (number()?, number()?, number()?);
    parts.next().is_none().then_some(version)
}
/// Run `bwrap --version` with a fixed environment, no input and a five-second bound.
fn version_output(bwrap: &Path) -> Result<String, Error> {
    let mut child = Command::new(bwrap)
        .arg("--version")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| refuse("No version output"))?;
    let reader = thread::spawn(move || {
        let mut text = String::new();
        let _ = (&mut stdout).take(4096).read_to_string(&mut text);
        text
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(refuse("Sandbox bubblewrap version check timed out"));
        }
        thread::sleep(Duration::from_millis(5));
    };
    let text = reader.join().unwrap_or_default();
    if !status.success() {
        return Err(refuse("Sandbox bubblewrap version check failed"));
    }
    Ok(text)
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

/// Translate the worker policy into bubblewrap arguments ending with the seccomp helper and
/// the literal command. Unknown fields, weaker settings, network exceptions and overlapping
/// grants are refused instead of ignored.
pub fn sandbox_arguments(
    bwrap: &Path,
    seccomp: &Path,
    policy: &Value,
    command: &[String],
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
        "--unshare-user".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--unshare-net".into(),
    ];
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
    args.extend(
        [
            "--dev",
            "/dev",
            "--unshare-pid",
            "--proc",
            "/proc",
            "--remount-ro",
            "/",
            "--",
        ]
        .map(String::from),
    );
    args.push(seccomp.to_string_lossy().into());
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
pub fn exec(arguments: &[String], environment: &[(String, String)]) -> Error {
    let error = Command::new(&arguments[0])
        .args(&arguments[1..])
        .env_clear()
        .envs(environment.iter().map(|(k, v)| (k, v)))
        .exec();
    Error::from(error)
}

#[cfg(test)]
mod tests;
