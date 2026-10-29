//! Fixed trusted file helper. Untrusted archive paths never select host paths;
//! publication uses an open parent directory and one atomic rename.
use crate::config::invalid;
use rustix::fs::{
    AtFlags, Gid, Mode, OFlags, RenameFlags, Uid, chownat, fchmod, fchown, linkat, mkdirat, openat,
    readlinkat, renameat_with, statat, symlinkat,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Raw,
    Tar,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Job {
    pub action: String,
    pub workspace: PathBuf,
    pub stage: PathBuf,
    pub path: String,
    pub format: Format,
    pub bytes: u64,
    pub sha256: String,
    pub replace: bool,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub byte_limit: u64,
    pub entry_limit: usize,
}

/// Names remain case-sensitive and are not Unicode-normalized. A tar root marker
/// is allowed only for a download; publication always addresses a child entry.
pub fn valid_path(path: &str, root: bool) -> bool {
    (root && path == ".")
        || (!path.is_empty()
            && path.len() <= 4096
            && !path.chars().any(|c| c.is_control() || c == '\\')
            && path.split('/').count() <= 64
            && path
                .split('/')
                .all(|p| !matches!(p, "" | "." | "..") && p.len() <= 255))
}
pub fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn directory(path: &Path) -> io::Result<File> {
    Ok(File::from(rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?))
}
fn child_dir(parent: &File, name: &str) -> io::Result<File> {
    sandcrab_core::transfer::dir(parent, name)
}
fn parent(root: &File, path: &str, create: bool) -> io::Result<(File, String)> {
    if !valid_path(path, false) {
        return Err(invalid("INVALID_PATH"));
    }
    let mut dir = root.try_clone()?;
    let mut parts = path.split('/').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            return Ok((dir, part.into()));
        }
        if create {
            match mkdirat(&dir, part, Mode::from_raw_mode(0o700)) {
                Err(rustix::io::Errno::EXIST) => (),
                result => result?,
            }
        }
        dir = child_dir(&dir, part)?;
    }
    Err(invalid("INVALID_PATH"))
}
fn regular(parent: &File, name: &str) -> io::Result<File> {
    let file = File::from(openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    if !file.metadata()?.is_file() {
        return Err(invalid("NOT_REGULAR_FILE"));
    }
    Ok(file)
}
fn new_file(parent: &File, name: &str) -> io::Result<File> {
    Ok(File::from(openat(
        parent,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?))
}
fn copy_hash(
    input: &mut impl Read,
    output: &mut impl Write,
    limit: u64,
) -> io::Result<(u64, String)> {
    let mut bytes = 0u64;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 32768];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .ok_or_else(|| invalid("FILE_LIMIT"))?;
        if bytes > limit {
            return Err(invalid("FILE_LIMIT"));
        }
        output.write_all(&buffer[..count])?;
        hash.update(&buffer[..count]);
    }
    Ok((bytes, format!("{:x}", hash.finalize())))
}
fn ownership(file: &File, job: &Job, mode: u32) -> io::Result<()> {
    fchown(
        file,
        Some(Uid::from_raw(job.uid)),
        Some(Gid::from_raw(job.gid)),
    )?;
    fchmod(file, Mode::from_raw_mode(mode & 0o777))?;
    file.sync_all()
}

fn unpack(job: &Job) -> io::Result<()> {
    let stage = directory(&job.stage)?;
    mkdirat(&stage, "tree", Mode::from_raw_mode(0o700))?;
    let tree = child_dir(&stage, "tree")?;
    let mut archive = tar::Archive::new(regular(&stage, "content")?);
    let mut seen = BTreeSet::new();
    let mut directories = BTreeMap::new();
    let mut total = 0u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        if let Some(extensions) = entry.pax_extensions()? {
            for extension in extensions {
                let extension = extension?;
                if extension.key_bytes().starts_with(b"GNU.sparse.")
                    || extension.key_bytes() == b"SCHILY.realsize"
                    || (extension.key_bytes() == b"SCHILY.filetype"
                        && extension.value_bytes() == b"sparse")
                {
                    return Err(invalid("UNSUPPORTED_ARCHIVE_ENTRY"));
                }
            }
        }
        let name = String::from_utf8(entry.path_bytes().into_owned())
            .map_err(|_| invalid("INVALID_PATH"))?;
        let name = name.trim_end_matches('/').trim_start_matches("./");
        let kind = entry.header().entry_type();
        if name.is_empty() || name == "." {
            if kind.is_dir() {
                continue;
            }
            return Err(invalid("INVALID_PATH"));
        }
        if !valid_path(name, false) || !seen.insert(name.to_owned()) {
            return Err(invalid("INVALID_PATH"));
        }
        if seen.len() > job.entry_limit {
            return Err(invalid("FILE_ENTRY_LIMIT"));
        }
        let (dir, leaf) = parent(&tree, name, true)?;
        // Every implicit parent is also charged to the entry budget.
        let mut prefix = String::new();
        let parts: Vec<_> = name.split('/').collect();
        for part in &parts[..parts.len() - 1] {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            directories.entry(prefix.clone()).or_insert(0o755);
        }
        if kind.is_dir() {
            directories.insert(name.to_owned(), entry.header().mode()? & 0o777);
            match mkdirat(&dir, &leaf, Mode::from_raw_mode(0o700)) {
                Err(rustix::io::Errno::EXIST) => {
                    child_dir(&dir, &leaf)?;
                }
                result => result?,
            }
        } else if kind.is_file() {
            let size = entry.size();
            total = total
                .checked_add(size)
                .ok_or_else(|| invalid("FILE_LIMIT"))?;
            if total > job.byte_limit {
                return Err(invalid("FILE_LIMIT"));
            }
            let mode = entry.header().mode()?;
            let mut file = new_file(&dir, &leaf)?;
            let (bytes, _) = copy_hash(&mut entry, &mut file, size)?;
            if bytes != size {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            ownership(&file, job, mode)?;
        } else if kind.is_symlink() {
            let target = entry
                .link_name_bytes()
                .ok_or_else(|| invalid("INVALID_LINK"))?;
            let target = std::str::from_utf8(&target).map_err(|_| invalid("INVALID_LINK"))?;
            if target.is_empty() || target.len() > 4096 || target.contains('\0') {
                return Err(invalid("INVALID_LINK"));
            }
            symlinkat(target, &dir, &leaf)?;
            chownat(
                &dir,
                &leaf,
                Some(Uid::from_raw(job.uid)),
                Some(Gid::from_raw(job.gid)),
                AtFlags::SYMLINK_NOFOLLOW,
            )?;
        } else if kind.is_hard_link() {
            let target = entry
                .link_name_bytes()
                .ok_or_else(|| invalid("INVALID_LINK"))?;
            let target = std::str::from_utf8(&target)
                .map_err(|_| invalid("INVALID_LINK"))?
                .trim_start_matches("./");
            let (source, name) = parent(&tree, target, false)?;
            regular(&source, &name)?;
            linkat(&source, &name, &dir, &leaf, AtFlags::empty())?;
        } else {
            return Err(invalid("UNSUPPORTED_ARCHIVE_ENTRY"));
        }
        if directories.len()
            + seen
                .iter()
                .filter(|s| !directories.contains_key(*s))
                .count()
            > job.entry_limit
        {
            return Err(invalid("FILE_ENTRY_LIMIT"));
        }
    }
    for (path, mode) in directories.iter().rev() {
        let (dir, name) = parent(&tree, path, false)?;
        ownership(&child_dir(&dir, &name)?, job, *mode)?;
    }
    ownership(&tree, job, job.mode)?;
    Ok(())
}

fn receive(job: &Job) -> io::Result<()> {
    let stage = directory(&job.stage)?;
    let mut content = new_file(&stage, "content")?;
    let (bytes, sha) = copy_hash(&mut io::stdin().lock(), &mut content, job.bytes)?;
    if bytes != job.bytes || sha != job.sha256 {
        return Err(invalid("CONTENT_MISMATCH"));
    }
    content.sync_all()?;
    if job.format == Format::Tar {
        unpack(job)?;
    } else {
        ownership(&content, job, job.mode)?;
    }
    stage.sync_all()
}

fn publish(job: &Job) -> io::Result<()> {
    let workspace = directory(&job.workspace)?;
    let stage = directory(&job.stage)?;
    let (dir, name) = parent(&workspace, &job.path, false)?;
    let source = if job.format == Format::Raw {
        "content"
    } else {
        "tree"
    };
    if job.format == Format::Raw && job.replace {
        match statat(&dir, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(info)
                if rustix::fs::FileType::from_raw_mode(info.st_mode)
                    != rustix::fs::FileType::RegularFile =>
            {
                return Err(invalid("NOT_REGULAR_FILE"));
            }
            Err(rustix::io::Errno::NOENT) | Ok(_) => (),
            Err(error) => return Err(error.into()),
        }
    }
    let flags = if job.replace {
        RenameFlags::empty()
    } else {
        RenameFlags::NOREPLACE
    };
    if job.format == Format::Tar && job.replace {
        match statat(&dir, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(info) => {
                if rustix::fs::FileType::from_raw_mode(info.st_mode)
                    != rustix::fs::FileType::Directory
                {
                    return Err(invalid("NOT_DIRECTORY"));
                }
                renameat_with(&stage, source, &dir, &name, RenameFlags::EXCHANGE)?;
            }
            Err(rustix::io::Errno::NOENT) => {
                renameat_with(&stage, source, &dir, &name, RenameFlags::NOREPLACE)?
            }
            Err(error) => return Err(error.into()),
        }
    } else {
        renameat_with(&stage, source, &dir, &name, flags)?;
    }
    dir.sync_all()?;
    stage.sync_all()?;
    Ok(())
}

struct Bounded<W> {
    writer: W,
    bytes: u64,
    limit: u64,
    hash: Sha256,
}
impl<W: Write> Write for Bounded<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.limit - self.bytes {
            return Err(invalid("FILE_LIMIT"));
        }
        let n = self.writer.write(bytes)?;
        self.bytes += n as u64;
        self.hash.update(&bytes[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}
fn stable(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    (
        before.dev(),
        before.ino(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) == (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    )
}
fn pack(
    dir: &File,
    prefix: &str,
    tar: &mut tar::Builder<Bounded<File>>,
    names_seen: &mut BTreeMap<(u64, u64), String>,
    count: &mut usize,
    job: &Job,
    depth: usize,
) -> io::Result<()> {
    if depth > 64 {
        return Err(invalid("FILE_ENTRY_LIMIT"));
    }
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(dir)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| invalid("INVALID_PATH"))?;
        if matches!(name, "." | "..") {
            continue;
        }
        *count += 1;
        if *count > job.entry_limit {
            return Err(invalid("FILE_ENTRY_LIMIT"));
        }
        names.push(name.to_owned());
    }
    names.sort();
    for name in names {
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if !valid_path(&path, false) {
            return Err(invalid("INVALID_PATH"));
        }
        let info = statat(dir, &name, AtFlags::SYMLINK_NOFOLLOW)?;
        let mut header = tar::Header::new_gnu();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(info.st_mtime.max(0) as u64);
        header.set_mode(info.st_mode & 0o777);
        match rustix::fs::FileType::from_raw_mode(info.st_mode) {
            rustix::fs::FileType::Directory => {
                let child = child_dir(dir, &name)?;
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                header.set_cksum();
                tar.append_data(&mut header, &path, io::empty())?;
                pack(&child, &path, tar, names_seen, count, job, depth + 1)?;
            }
            rustix::fs::FileType::RegularFile => {
                let mut file = regular(dir, &name)?;
                let before = file.metadata()?;
                if before.len() > job.byte_limit {
                    return Err(invalid("FILE_LIMIT"));
                }
                let key = (before.dev(), before.ino());
                if let Some(previous) = names_seen.get(&key) {
                    header.set_entry_type(tar::EntryType::Link);
                    header.set_size(0);
                    header.set_cksum();
                    tar.append_link(&mut header, &path, previous)?;
                    continue;
                }
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(before.len());
                header.set_cksum();
                tar.append_data(&mut header, &path, &mut file)?;
                if !stable(&before, &file.metadata()?) {
                    return Err(invalid("FILE_CHANGED"));
                }
                names_seen.insert(key, path);
            }
            rustix::fs::FileType::Symlink => {
                let target = readlinkat(dir, &name, Vec::new())?;
                let target = target.to_str().map_err(|_| invalid("INVALID_LINK"))?;
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_size(0);
                header.set_cksum();
                tar.append_link(&mut header, &path, target)?;
            }
            _ => return Err(invalid("UNSUPPORTED_FILE_TYPE")),
        }
    }
    Ok(())
}
fn snapshot(job: &Job) -> io::Result<serde_json::Value> {
    let workspace = directory(&job.workspace)?;
    let stage = directory(&job.stage)?;
    let content = new_file(&stage, "content")?;
    let mut output = Bounded {
        writer: content,
        bytes: 0,
        limit: job.byte_limit,
        hash: Sha256::new(),
    };
    if job.format == Format::Raw {
        let (dir, name) = parent(&workspace, &job.path, false)?;
        let mut file = regular(&dir, &name)?;
        let before = file.metadata()?;
        copy_hash(&mut file, &mut output, job.byte_limit)?;
        if !stable(&before, &file.metadata()?) {
            return Err(invalid("FILE_CHANGED"));
        }
    } else {
        let root = if job.path == "." {
            workspace
        } else {
            let (dir, name) = parent(&workspace, &job.path, false)?;
            child_dir(&dir, &name)?
        };
        let mut tar = tar::Builder::new(output);
        pack(&root, "", &mut tar, &mut BTreeMap::new(), &mut 0, job, 0)?;
        tar.finish()?;
        output = tar.into_inner()?;
    }
    output.writer.sync_all()?;
    stage.sync_all()?;
    Ok(serde_json::json!({"bytes":output.bytes,"sha256":format!("{:x}",output.hash.finalize())}))
}

pub fn execute(path: &Path) -> io::Result<serde_json::Value> {
    if rustix::process::geteuid() != Uid::ROOT {
        return Err(invalid("File helper requires root"));
    }
    let raw = sandcrab_core::fs::protected_file(path, 16384)?;
    let job: Job = serde_json::from_slice(&raw)?;
    if !sandcrab_core::fs::normal(&job.workspace)
        || !sandcrab_core::fs::normal(&job.stage)
        || job.workspace.parent() != job.stage.parent()
        || !job
            .stage
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|s| s.strip_prefix(".transfer-"))
            .is_some_and(sandcrab_core::uuid)
        || job.workspace == job.stage
        || job.stage.starts_with(&job.workspace)
        || job.uid == 0
        || job.bytes > job.byte_limit
        || job.byte_limit > 1_073_741_824
        || job.mode > 0o777
        || !(1..=10000).contains(&job.entry_limit)
        || !valid_path(
            &job.path,
            job.action == "snapshot" && job.format == Format::Tar,
        )
    {
        return Err(invalid("Invalid file helper authority"));
    }
    sandcrab_core::fs::protected_directory(&job.stage)?;
    if job.stage.metadata()?.permissions().mode() & 0o077 != 0 {
        return Err(invalid("Unprotected file stage"));
    }
    crate::storage::no_mounts_below(&job.stage, true)?;
    if ["publish", "snapshot"].contains(&job.action.as_str()) {
        crate::storage::no_mounts_below(&job.workspace, true)?;
    }
    let owner: crate::file_records::Stage = serde_json::from_slice(
        &sandcrab_core::fs::protected_file(&job.stage.join("owner.json"), 16384)?,
    )?;
    if job.stage.file_name().unwrap().to_string_lossy() != format!(".transfer-{}", owner.id)
        || owner.uid != job.uid
        || owner.gid != job.gid
    {
        return Err(invalid("File stage ownership changed"));
    }
    if job.action == "snapshot" {
        return snapshot(&job);
    }
    match job.action.as_str() {
        "receive" => receive(&job),
        "publish" => publish(&job),
        "cleanup" => {
            for entry in fs::read_dir(&job.stage)? {
                let entry = entry?;
                if entry.file_name() == "owner.json" {
                    continue;
                }
                if entry.file_type()?.is_dir() {
                    fs::remove_dir_all(entry.path())?;
                } else {
                    fs::remove_file(entry.path())?;
                }
            }
            Ok(())
        }
        _ => Err(invalid("Invalid file helper action")),
    }?;
    Ok(serde_json::json!({"ok":true}))
}
pub fn error_code(error: &io::Error) -> &'static str {
    match error.to_string().as_str() {
        "INVALID_PATH" => "INVALID_PATH",
        "INVALID_LINK" => "INVALID_LINK",
        "NOT_DIRECTORY" => "NOT_DIRECTORY",
        "NOT_REGULAR_FILE" => "NOT_REGULAR_FILE",
        "FILE_LIMIT" => "FILE_LIMIT",
        "FILE_ENTRY_LIMIT" => "FILE_ENTRY_LIMIT",
        "CONTENT_MISMATCH" => "CONTENT_MISMATCH",
        "FILE_CHANGED" => "FILE_CHANGED",
        "UNSUPPORTED_ARCHIVE_ENTRY" => "UNSUPPORTED_ARCHIVE_ENTRY",
        "UNSUPPORTED_FILE_TYPE" => "UNSUPPORTED_FILE_TYPE",
        _ => match error.kind() {
            io::ErrorKind::NotFound => "FILE_NOT_FOUND",
            io::ErrorKind::AlreadyExists => "PATH_EXISTS",
            io::ErrorKind::NotADirectory => "NOT_DIRECTORY",
            _ if error.raw_os_error() == Some(40) => "INVALID_LINK",
            _ if matches!(error.raw_os_error(), Some(28 | 122)) => "FILE_CAPACITY",
            _ => "FILE_FAILED",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths_preserve_case_and_unicode_but_not_escape_components() {
        for p in ["README.md", "Readme.md", "项目/main.py", "a/b"] {
            assert!(valid_path(p, false));
        }
        for p in [
            "",
            ".",
            "..",
            "../a",
            "a/../b",
            "/etc/passwd",
            "a//b",
            "a\\b",
            "a\0b",
        ] {
            assert!(!valid_path(p, false));
        }
        assert!(valid_path(".", true));
        assert!(!valid_path(&"a/".repeat(65), false));
    }
}
