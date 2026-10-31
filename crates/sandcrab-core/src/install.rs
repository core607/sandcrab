//! Shared installation checks: execution accounts, an exclusive runtime root and a bounded slice.
use crate::{
    fs::{normal, protected_directory},
    unit::{checked, verify_resource_pool},
};
use rustix::fs::{FlockOperation, OFlags, flock};
use std::{
    fs::{File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
fn invalid() -> io::Error {
    io::Error::other("Invalid daemon installation")
}
/// A user, unit or slice name that cannot be read as an option or a path.
pub fn unit_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 240
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
fn id(args: &[&str]) -> io::Result<String> {
    let mut command = vec!["id".to_string()];
    command.extend(args.iter().map(|v| v.to_string()));
    let output = checked(&command, Duration::from_secs(15))?;
    String::from_utf8(output.stdout).map_err(|_| invalid())
}
/// The UID and GID of an execution account that is neither root nor the application and
/// is not a member of the application's group.
pub fn execution_account(user: &str, app_uid: u32, app_gid: u32) -> io::Result<(u32, u32)> {
    if !unit_name(user) {
        return Err(invalid());
    }
    let number =
        |kind| -> io::Result<u32> { id(&[kind, user])?.trim().parse().map_err(|_| invalid()) };
    let (uid, gid) = (number("-u")?, number("-g")?);
    if uid == 0
        || uid == app_uid
        || id(&["-G", user])?
            .split_whitespace()
            .any(|v| v.parse::<u32>().ok() == Some(app_gid))
    {
        return Err(invalid());
    }
    Ok((uid, gid))
}
/// The exclusive lock that keeps a second daemon off one runtime root.
pub fn runtime_lock(root: &Path) -> io::Result<File> {
    protected_directory(root)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
        .open(root.join(".supervisor.lock"))?;
    let info = file.metadata()?;
    if !info.is_file() || info.uid() != 0 || info.mode() & 0o077 != 0 {
        return Err(invalid());
    }
    flock(&file, FlockOperation::NonBlockingLockExclusive)?;
    Ok(file)
}
/// The cgroup of `slice`, which must contain this process and bound memory, tasks and CPU.
pub fn resource_pool(slice: &str) -> io::Result<PathBuf> {
    let group = checked(
        &[
            "systemctl".into(),
            "show".into(),
            slice.into(),
            "--property=ControlGroup".into(),
            "--value".into(),
        ],
        Duration::from_secs(15),
    )?;
    let group = std::str::from_utf8(&group.stdout)
        .map_err(|_| invalid())?
        .trim();
    if !group.starts_with('/')
        || !normal(Path::new(group))
        || group.rsplit('/').next() != Some(slice)
    {
        return Err(invalid());
    }
    let pool = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
    verify_resource_pool(&pool)?;
    Ok(pool)
}
