//! Path checks for root-owned state that other accounts must not replace.
use rustix::fs::OFlags;
use std::{
    fs::{self, OpenOptions},
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path},
};
fn invalid() -> io::Error {
    io::Error::other("Protected path unavailable")
}
/// An absolute path of plain components drawn from a conservative character set.
pub fn normal(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        && path
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"/_.-".contains(b))
        && path.to_str().is_some_and(|text| {
            text.split('/')
                .skip(1)
                .all(|part| !part.is_empty() && part != "." && part != "..")
        })
}
/// The directory and every ancestor are root-owned directories that other accounts cannot write.
pub fn protected_directory(path: &Path) -> io::Result<()> {
    if !normal(path) {
        return Err(invalid());
    }
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(invalid());
        }
    }
    Ok(())
}
/// Read at most `limit` bytes of a private root-owned regular file without following a link.
pub fn protected_file(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    let info = file.metadata()?;
    if !info.is_file() || info.uid() != 0 || info.mode() & 0o077 != 0 || info.len() > limit as u64 {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(invalid());
    }
    Ok(bytes)
}
/// Whether `path` is a mount target of the current mount namespace.
pub fn mounted(path: &Path) -> io::Result<bool> {
    let target = path.to_str().ok_or_else(invalid)?;
    Ok(fs::read_to_string("/proc/self/mountinfo")?
        .lines()
        .any(|line| line.split_whitespace().nth(4) == Some(target)))
}
