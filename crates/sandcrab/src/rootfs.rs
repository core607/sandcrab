//! A template root is writable beneath protected mount anchors. Its root must
//! prevent a workload from replacing the path later bound by a root file helper.
use crate::config::{Profile, invalid};
use rustix::fs::{Gid, Uid, chown};
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

fn directory(root: &Path, name: &str, uid: u32, gid: u32, mode: u32) -> io::Result<()> {
    let path = root.join(name);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if !metadata.is_dir() => {
            return Err(invalid(format!("Rootfs /{name} must be a directory")));
        }
        Ok(_) => (),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            DirBuilder::new().mode(mode).create(&path)?;
        }
        Err(error) => return Err(error),
    }
    chown(&path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

fn file(root: &Path, name: &str) -> io::Result<()> {
    let path = root.join(name);
    // Chown can copy up file contents. Fixed empty anchors keep this daemon-side
    // preparation bounded and avoid changing the ownership of guest hard links.
    match fs::symlink_metadata(&path) {
        Ok(metadata) if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() != 0 => {
            return Err(invalid(format!(
                "Rootfs /{name} must be an empty regular file with one link"
            )));
        }
        Ok(_) => (),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(&path)?;
        }
        Err(error) => return Err(error),
    }
    chown(&path, Some(Uid::ROOT), Some(Gid::ROOT))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o644))
}

/// Call once on the parent's overlay before any workload can access it. All
/// ownership changes copy up into that session; the template lower stays intact.
pub fn prepare(root: &Path, profile: &Profile) -> io::Result<()> {
    if !fs::symlink_metadata(root)?.is_dir() {
        return Err(invalid("Rootfs must be a directory"));
    }
    chown(root, Some(Uid::ROOT), Some(Gid::ROOT))?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o755))?;
    for name in ["tmp", "dev", "proc"] {
        directory(root, name, 0, 0, 0o755)?;
    }
    directory(root, "workspace", profile.uid, profile.gid, 0o750)?;
    file(root, "sandcrab-driver")?;
    if profile.host_calls {
        directory(root, "sandcrab", 0, 0, 0o755)?;
        directory(root, "sandcrab-calls", 0, 0, 0o755)?;
        file(root, "sandcrab/sandcrab")?;
    }
    Ok(())
}

/// Keep the common isolation and seccomp arguments. The template supplies the
/// filesystem; only the empty-root read-only remount is replaced.
pub fn mount(arguments: &mut Vec<String>, root: &Path) -> io::Result<()> {
    sandcrab_core::fs::protected_directory(root)?;
    let boundary = arguments
        .iter()
        .position(|arg| arg == "--remount-ro")
        .ok_or_else(|| invalid("Missing rootfs remount boundary"))?;
    if arguments.get(boundary + 1).map(String::as_str) != Some("/") {
        return Err(invalid("Invalid rootfs remount boundary"));
    }
    arguments.drain(boundary..boundary + 2);
    let devices = arguments
        .iter()
        .position(|arg| arg == "--dev")
        .ok_or_else(|| invalid("Missing rootfs device boundary"))?;
    arguments.splice(
        devices..devices,
        ["--bind".into(), root.to_string_lossy().into(), "/".into()],
    );
    Ok(())
}
