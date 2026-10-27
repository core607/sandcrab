//! Bounded snapshots and compare-and-replace transfers under a retained lease mount.
use base64::{Engine, engine::general_purpose::STANDARD};
use rustix::fs::{
    AtFlags, Gid, Mode, OFlags, Uid, fchmod, fchown, mkdirat, openat, renameat, statvfs, unlinkat,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};
use unicode_normalization::UnicodeNormalization;

pub const CHUNK_BYTES: usize = 65536;
const TEXT_BYTES: usize = 4 * 1024 * 1024;
const BINARY_BYTES: u64 = 128 * 1024 * 1024;
const FILE_BYTES: u64 = 1024 * 1024 * 1024;
#[derive(Debug)]
pub struct Error {
    pub reason: &'static str,
    pub capacity: bool,
    pub fatal: bool,
}
type Result<T> = std::result::Result<T, Error>;
fn rejected(reason: &'static str) -> Error {
    Error {
        reason,
        capacity: false,
        fatal: false,
    }
}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self {
            reason: "CAPTURE_UNAVAILABLE",
            capacity: matches!(error.raw_os_error(), Some(28 | 122)),
            fatal: false,
        }
    }
}
impl From<rustix::io::Errno> for Error {
    fn from(error: rustix::io::Errno) -> Self {
        io::Error::from(error).into()
    }
}
/// The directory a lease's transfers address, as components below the lease mount, and
/// the path component no request may name.
#[derive(Clone, Copy, Debug)]
pub struct Tree {
    pub directories: &'static [&'static str],
    pub reserved: &'static str,
}
impl Tree {
    /// Open the tree one component at a time, never following a link.
    pub fn open(&self, root: &Path) -> io::Result<File> {
        let mut parent = root_file(root)?;
        for name in self.directories {
            parent = dir(&parent, name)?;
        }
        Ok(parent)
    }
}
pub fn selected(tree: Tree, writes: &Value, deletes: &Value) -> Result<(Vec<String>, Vec<String>)> {
    let writes = writes
        .as_array()
        .ok_or_else(|| rejected("INVALID_ARGUMENTS"))?;
    let deletes = deletes
        .as_array()
        .ok_or_else(|| rejected("INVALID_ARGUMENTS"))?;
    if !(1..=64).contains(&(writes.len() + deletes.len())) {
        return Err(rejected("SELECTION_LIMIT"));
    }
    let mut seen = HashSet::new();
    let mut all = Vec::new();
    for path in writes.iter().chain(deletes) {
        let path = path.as_str().ok_or_else(|| rejected("INVALID_PATH"))?;
        if path.is_empty()
            || path.len() > 4096
            || path.contains('\\')
            || path.chars().any(|c| c < ' ' || c == '\u{7f}')
            || path.split('/').any(|p| matches!(p, "" | "." | ".."))
        {
            return Err(rejected("INVALID_PATH"));
        }
        let normalized = path.nfc().collect::<String>();
        let key = normalized
            .to_uppercase()
            .to_lowercase()
            .nfc()
            .collect::<String>();
        if key.split('/').any(|p| p == tree.reserved) || !seen.insert(key) {
            return Err(rejected("PATH_COLLISION"));
        }
        all.push(path.to_string());
    }
    let deleted = all.split_off(writes.len());
    Ok((all, deleted))
}
fn one(tree: Tree, path: &Value) -> Result<String> {
    let (mut paths, _) = selected(tree, &json!([path]), &json!([]))?;
    Ok(paths.remove(0))
}
pub fn dir(parent: &File, name: &str) -> io::Result<File> {
    Ok(File::from(openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?))
}
fn root_file(root: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::DIRECTORY | OFlags::NOFOLLOW).bits() as i32)
        .open(root)
}
fn regular(parent: &File, name: &str) -> io::Result<File> {
    Ok(File::from(openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?))
}
fn source(repository: &File, path: &str, binary: bool) -> Result<(File, File, String)> {
    let mut parent = repository.try_clone()?;
    let mut parts = path.split('/').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            return regular(&parent, part)
                .map(|file| (parent, file, part.into()))
                .map_err(|e| source_error(e, binary));
        }
        parent = dir(&parent, part).map_err(|e| source_error(e, binary))?;
    }
    Err(rejected("INVALID_PATH"))
}
fn source_error(error: io::Error, binary: bool) -> Error {
    if error.kind() == io::ErrorKind::NotFound {
        rejected("NOT_FOUND")
    } else if binary && matches!(error.raw_os_error(), Some(20 | 40)) {
        rejected("NOT_REGULAR_FILE")
    } else {
        error.into()
    }
}
fn identity(info: &Metadata) -> (u64, u64, u64, i64, i64, i64, i64, u64, u32) {
    (
        info.dev(),
        info.ino(),
        info.len(),
        info.mtime(),
        info.mtime_nsec(),
        info.ctime(),
        info.ctime_nsec(),
        info.nlink(),
        info.mode(),
    )
}
fn unchanged(before: &Metadata, file: &File, parent: &File, name: &str) -> Result<()> {
    let after = file.metadata()?;
    let current = regular(parent, name)?.metadata()?;
    if identity(before) != identity(&after) || identity(&after) != identity(&current) {
        Err(rejected("FILE_CHANGED"))
    } else {
        Ok(())
    }
}
fn cancelled(flag: &AtomicBool) -> Result<()> {
    if flag.load(Ordering::SeqCst) {
        Err(rejected("CAPTURE_UNAVAILABLE"))
    } else {
        Ok(())
    }
}
#[cfg(test)]
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
struct Stage {
    path: PathBuf,
    file: Option<File>,
}
impl Stage {
    fn new(root: &Path, prefix: &str) -> Result<Self> {
        let path = root.join(format!("{prefix}-{}", crate::new_uuid()?));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(OFlags::NOFOLLOW.bits() as i32)
            .open(&path)?;
        Ok(Self {
            path,
            file: Some(file),
        })
    }
    fn file(&self) -> Result<&File> {
        self.file
            .as_ref()
            .ok_or_else(|| rejected("CAPTURE_UNAVAILABLE"))
    }
    fn close(&mut self) -> io::Result<()> {
        self.file.take();
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
enum Content {
    Memory(Vec<u8>),
    Disk(Stage),
}
struct Entry {
    path: String,
    bytes: u64,
    digest: String,
    content: Content,
}
pub struct Snapshot {
    pub id: String,
    entries: Vec<Entry>,
    deletes: Vec<String>,
    absent: Vec<String>,
}
impl Snapshot {
    pub fn capture(
        root: &Path,
        tree: Tree,
        operation: &str,
        data: &Value,
        flag: &AtomicBool,
    ) -> Result<Self> {
        Self::capture_bounded(root, tree, operation, data, flag, BINARY_BYTES)
    }
    pub fn capture_binary(
        root: &Path,
        tree: Tree,
        path: &Value,
        maximum: u64,
        flag: &AtomicBool,
    ) -> Result<Self> {
        if maximum > BINARY_BYTES {
            return Err(rejected("INVALID_ARGUMENTS"));
        }
        Self::capture_bounded(
            root,
            tree,
            "CAPTURE_BINARY",
            &json!({"path":path}),
            flag,
            maximum,
        )
    }
    fn capture_bounded(
        root: &Path,
        tree: Tree,
        operation: &str,
        data: &Value,
        flag: &AtomicBool,
        binary_maximum: u64,
    ) -> Result<Self> {
        let (paths, deletes) = if operation == "CAPTURE_BEGIN" {
            selected(tree, &data["writes"], &data["deletes"])?
        } else {
            (vec![one(tree, &data["path"])?], vec![])
        };
        let repository = tree.open(root)?;
        let mut captured = Self {
            id: crate::new_uuid()?,
            entries: Vec::new(),
            deletes,
            absent: Vec::new(),
        };
        let binary = operation == "CAPTURE_BINARY";
        let mut remaining = TEXT_BYTES;
        for path in paths {
            cancelled(flag)?;
            let (parent, mut file, name) = match source(&repository, &path, binary) {
                Err(error) if operation == "CAPTURE_OPTIONAL" && error.reason == "NOT_FOUND" => {
                    captured.absent.push(path);
                    continue;
                }
                other => other?,
            };
            let before = file.metadata()?;
            if !before.is_file() || before.nlink() != 1 {
                return Err(rejected("NOT_REGULAR_FILE"));
            }
            let maximum = if binary {
                binary_maximum
            } else {
                remaining as u64
            };
            let limit_reason = if binary { "BINARY_LIMIT" } else { "TEXT_LIMIT" };
            if before.len() > maximum {
                return Err(rejected(limit_reason));
            }
            let mut bytes = Vec::new();
            let mut stage = if binary {
                Some(Stage::new(root, "outgoing")?)
            } else {
                None
            };
            let mut digest = Sha256::new();
            let mut size = 0u64;
            loop {
                cancelled(flag)?;
                let mut buffer = [0; CHUNK_BYTES];
                let count = file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                size += count as u64;
                if size > maximum {
                    return Err(rejected(limit_reason));
                }
                digest.update(&buffer[..count]);
                if let Some(stage) = &mut stage {
                    stage.file.as_mut().unwrap().write_all(&buffer[..count])?;
                } else {
                    bytes.extend_from_slice(&buffer[..count]);
                }
            }
            unchanged(&before, &file, &parent, &name)?;
            if size != before.len() {
                return Err(rejected("FILE_CHANGED"));
            }
            if !binary && std::str::from_utf8(&bytes).is_err() {
                return Err(rejected("NOT_UTF8"));
            }
            let content = match stage {
                Some(stage) => Content::Disk(stage),
                None => {
                    remaining -= bytes.len();
                    Content::Memory(bytes)
                }
            };
            captured.entries.push(Entry {
                path,
                bytes: size,
                digest: format!("{:x}", digest.finalize()),
                content,
            });
        }
        Ok(captured)
    }
    pub fn transfer_binary(&mut self, destination: &Path) -> Result<(File, String, u64, String)> {
        if self.entries.len() != 1 {
            return Err(rejected("CAPTURE_UNAVAILABLE"));
        }
        let entry = &mut self.entries[0];
        let Content::Disk(stage) = &mut entry.content else {
            return Err(rejected("CAPTURE_UNAVAILABLE"));
        };
        if stage.file.is_none() || fs::symlink_metadata(destination).is_ok() {
            return Err(rejected("CAPTURE_UNAVAILABLE"));
        }
        fs::rename(&stage.path, destination)?;
        Ok((
            stage.file.take().unwrap(),
            entry.path.clone(),
            entry.bytes,
            entry.digest.clone(),
        ))
    }
    pub fn manifest(&self) -> Value {
        json!({"captureId": self.id, "writes": self.entries.iter().map(|v| json!({"path":v.path,"bytes":v.bytes,"sha256":v.digest})).collect::<Vec<_>>(), "deletes":self.deletes,"absent":self.absent})
    }
    pub fn close(&mut self) -> io::Result<()> {
        for entry in &mut self.entries {
            if let Content::Disk(stage) = &mut entry.content {
                stage.close()?;
            }
        }
        Ok(())
    }
    /// The byte length of [`Snapshot::write_tar`] with this manifest.
    pub fn tar_length(&self, manifest: &[u8]) -> u64 {
        let entry = |bytes: u64| 512 + bytes.div_ceil(512) * 512;
        entry(manifest.len() as u64)
            + self.entries.iter().map(|e| entry(e.bytes)).sum::<u64>()
            + 1024
    }
    /// One ustar archive: `manifest.json`, then each captured file as `files/<index>` in
    /// manifest order. Paths, sizes and digests are in the manifest; entry names never carry
    /// a repository path.
    pub fn write_tar(&self, manifest: &[u8], out: &mut impl Write) -> io::Result<()> {
        out.write_all(&tar_header("manifest.json", manifest.len() as u64))?;
        out.write_all(manifest)?;
        tar_pad(out, manifest.len() as u64)?;
        for (index, entry) in self.entries.iter().enumerate() {
            out.write_all(&tar_header(&format!("files/{index}"), entry.bytes))?;
            match &entry.content {
                Content::Memory(bytes) => out.write_all(bytes)?,
                Content::Disk(stage) => {
                    let file = stage
                        .file()
                        .map_err(|_| io::Error::other("Captured file unavailable"))?;
                    let mut offset = 0;
                    let mut buffer = vec![0; CHUNK_BYTES];
                    while offset < entry.bytes {
                        let count = (entry.bytes - offset).min(CHUNK_BYTES as u64) as usize;
                        let read = file.read_at(&mut buffer[..count], offset)?;
                        if read == 0 {
                            return Err(io::Error::other("Captured file shrank"));
                        }
                        out.write_all(&buffer[..read])?;
                        offset += read as u64;
                    }
                }
            }
            tar_pad(out, entry.bytes)?;
        }
        out.write_all(&[0; 1024])
    }
}
fn tar_pad(out: &mut impl Write, bytes: u64) -> io::Result<()> {
    out.write_all(&[0; 512][..(bytes.div_ceil(512) * 512 - bytes) as usize])
}
/// A ustar header for a regular file of `size` bytes, owned by nobody and dated at the epoch.
fn tar_header(name: &str, size: u64) -> [u8; 512] {
    let mut header = [0u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..107].copy_from_slice(b"0000644");
    header[108..115].copy_from_slice(b"0000000");
    header[116..123].copy_from_slice(b"0000000");
    header[124..135].copy_from_slice(format!("{size:011o}").as_bytes());
    header[136..147].copy_from_slice(b"00000000000");
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[148..156].copy_from_slice(b"        ");
    let sum: u32 = header.iter().map(|b| u32::from(*b)).sum();
    header[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    header
}
fn read_at(file: &File, offset: u64, count: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0; count];
    let mut done = 0;
    while done < count {
        let size = file.read_at(&mut bytes[done..], offset + done as u64)?;
        if size == 0 {
            return Err(rejected("CAPTURE_UNAVAILABLE"));
        }
        done += size;
    }
    Ok(bytes)
}
fn capacity(root: &Path, bytes: u64) -> Result<()> {
    let available = statvfs(root)?;
    if available
        .f_bavail
        .saturating_mul(available.f_frsize)
        .saturating_sub(bytes)
        < 1024 * 1024
    {
        Err(Error {
            reason: "CAPTURE_UNAVAILABLE",
            capacity: true,
            fatal: false,
        })
    } else {
        Ok(())
    }
}
fn digest(value: &Value, optional: bool) -> Result<Option<String>> {
    if optional && value.is_null() {
        return Ok(None);
    }
    value
        .as_str()
        .filter(|s| crate::hex(s, 64))
        .map(|s| Some(s.to_owned()))
        .ok_or_else(|| rejected("CAPTURE_UNAVAILABLE"))
}
pub struct Incoming {
    pub id: String,
    root: PathBuf,
    tree: Tree,
    path: String,
    size: u64,
    digest: String,
    expected: Option<String>,
    delete: bool,
    allow_identical: bool,
    pub received: u64,
    hasher: Sha256,
    stage: Stage,
    result: Option<Value>,
}
impl Incoming {
    pub fn begin(root: &Path, tree: Tree, data: &Value) -> Result<Self> {
        let path = one(tree, &data["path"])?;
        let digest = digest(&data["sha256"], false)?.unwrap();
        let expected = digest_value(&data["expectedSha256"])?;
        let size = data["bytes"]
            .as_u64()
            .filter(|v| *v <= FILE_BYTES)
            .ok_or_else(|| rejected("CAPTURE_UNAVAILABLE"))?;
        let delete = data["delete"]
            .as_bool()
            .ok_or_else(|| rejected("CAPTURE_UNAVAILABLE"))?;
        let allow_identical = data["allowIdentical"]
            .as_bool()
            .ok_or_else(|| rejected("CAPTURE_UNAVAILABLE"))?;
        if delete && size != 0 {
            return Err(rejected("CAPTURE_UNAVAILABLE"));
        }
        if !delete {
            capacity(root, size)?;
        }
        let stage = Stage::new(root, "incoming")?;
        let id = stage
            .path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .strip_prefix("incoming-")
            .unwrap()
            .to_owned();
        Ok(Self {
            id,
            root: root.into(),
            tree,
            path,
            size,
            digest,
            expected,
            delete,
            allow_identical,
            received: 0,
            hasher: Sha256::new(),
            stage,
            result: None,
        })
    }
    pub fn move_plan(root: &Path, tree: Tree, data: &Value) -> Result<Self> {
        if !data["bytes"]
            .as_u64()
            .is_some_and(|v| (1..=64 * 1024 * 1024).contains(&v))
        {
            return Err(rejected("CAPTURE_UNAVAILABLE"));
        }
        Self::begin(
            root,
            tree,
            &json!({"path":"__move_plan__","bytes":data["bytes"],"sha256":data["sha256"],"expectedSha256":null,"delete":false,"allowIdentical":false}),
        )
    }
    pub fn plan_bytes(&self, flag: &AtomicBool) -> Result<Vec<u8>> {
        self.verify(flag)?;
        read_at(self.stage.file()?, 0, self.size as usize)
    }
    pub fn plan_digest(&self) -> &str {
        &self.digest
    }
    pub fn append(&mut self, data: &Value) -> Result<()> {
        let encoded = data["data"]
            .as_str()
            .filter(|v| v.len() <= 87384)
            .ok_or_else(|| rejected("CAPTURE_UNAVAILABLE"))?;
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|_| rejected("CAPTURE_UNAVAILABLE"))?;
        if self.result.is_some()
            || self.stage.file.is_none()
            || data["offset"].as_u64() != Some(self.received)
            || bytes.is_empty()
            || bytes.len() > CHUNK_BYTES
            || self.received + bytes.len() as u64 > self.size
        {
            return Err(rejected("CAPTURE_UNAVAILABLE"));
        }
        let written: Result<()> = (|| {
            capacity(&self.root, bytes.len() as u64)?;
            self.stage.file.as_mut().unwrap().write_all(&bytes)?;
            Ok(())
        })();
        if written.is_err() {
            self.stage.close()?;
        }
        written?;
        self.hasher.update(&bytes);
        self.received += bytes.len() as u64;
        Ok(())
    }
    fn verify(&self, flag: &AtomicBool) -> Result<()> {
        if self.received != self.size
            || format!("{:x}", self.hasher.clone().finalize()) != self.digest
            || self.stage.file()?.metadata()?.len() != self.size
        {
            return Err(rejected("CAPTURE_UNAVAILABLE"));
        }
        let mut digest = Sha256::new();
        let mut offset = 0;
        while offset < self.size {
            cancelled(flag)?;
            let bytes = read_at(
                self.stage.file()?,
                offset,
                (self.size - offset).min(CHUNK_BYTES as u64) as usize,
            )?;
            offset += bytes.len() as u64;
            digest.update(bytes);
        }
        if format!("{:x}", digest.finalize()) != self.digest {
            return Err(rejected("CAPTURE_UNAVAILABLE"));
        }
        Ok(())
    }
    pub fn install(&mut self, uid: u32, gid: u32, flag: &AtomicBool) -> Result<Value> {
        if let Some(result) = &self.result {
            return Ok(result.clone());
        }
        self.verify(flag)?;
        cancelled(flag)?;
        let root = root_file(&self.root)?;
        let mut parent = self.tree.open(&self.root)?;
        let parts: Vec<_> = self.path.split('/').collect();
        for part in &parts[..parts.len() - 1] {
            parent = match dir(&parent, part) {
                Ok(child) => child,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    if self.expected.is_some() {
                        return Err(rejected("CAPTURE_UNAVAILABLE"));
                    }
                    if self.delete {
                        return self.finished(false);
                    }
                    mkdirat(&parent, *part, Mode::from_bits_truncate(0o700))?;
                    let child = dir(&parent, part)?;
                    fchown(&child, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))?;
                    child
                }
                Err(error) => return Err(error.into()),
            };
        }
        let name = parts.last().unwrap();
        let (current, mode) = current(&parent, name, flag)?;
        let target = if self.delete {
            None
        } else {
            Some(self.digest.clone())
        };
        if self.allow_identical && current == target {
            return self.finished(false);
        }
        if current != self.expected {
            return Err(rejected("CAPTURE_UNAVAILABLE"));
        }
        if !self.delete && current == target {
            return self.finished(false);
        }
        cancelled(flag)?;
        if self.delete {
            if current.is_some() {
                unlinkat(&parent, *name, AtFlags::empty())?;
            }
        } else {
            let file = self.stage.file()?;
            fchown(file, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))?;
            fchmod(file, Mode::from_bits_truncate(mode))?;
            renameat(&root, self.stage.path.file_name().unwrap(), &parent, *name)?;
        }
        self.finished(if self.delete {
            current.is_some()
        } else {
            current != target
        })
    }
    fn finished(&mut self, changed: bool) -> Result<Value> {
        let result = json!({"path":self.path,"sha256":if self.delete { None } else { Some(&self.digest) },"changed":changed});
        self.stage.close()?;
        self.result = Some(result.clone());
        Ok(result)
    }
    pub fn close(&mut self) -> io::Result<()> {
        self.stage.close()
    }
}
fn digest_value(value: &Value) -> Result<Option<String>> {
    digest(value, true)
}
pub fn current(parent: &File, name: &str, flag: &AtomicBool) -> Result<(Option<String>, u32)> {
    let mut file = match regular(parent, name) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok((None, 0o600)),
        other => other?,
    };
    let info = file.metadata()?;
    if !info.is_file() || info.nlink() != 1 || info.len() > FILE_BYTES {
        return Err(rejected("CAPTURE_UNAVAILABLE"));
    }
    let mut digest = Sha256::new();
    let mut total = 0u64;
    loop {
        cancelled(flag)?;
        let mut block = [0; CHUNK_BYTES];
        let count = file.read(&mut block)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > FILE_BYTES {
            return Err(rejected("CAPTURE_UNAVAILABLE"));
        }
        digest.update(&block[..count]);
    }
    Ok((
        Some(format!("{:x}", digest.finalize())),
        0o600 | (info.mode() & 0o111),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    /// The files of a snapshot's archive, read back by their declared sizes.
    fn archived(snapshot: &Snapshot) -> Vec<Vec<u8>> {
        let mut archive = Vec::new();
        snapshot.write_tar(b"{}", &mut archive).unwrap();
        let mut offset = 1024;
        let mut files = Vec::new();
        while archive[offset] != 0 {
            let size = usize::from_str_radix(
                std::str::from_utf8(&archive[offset + 124..offset + 135]).unwrap(),
                8,
            )
            .unwrap();
            files.push(archive[offset + 512..offset + 512 + size].to_vec());
            offset += 512 + size.div_ceil(512) * 512;
        }
        files
    }
    #[test]
    fn a_snapshot_streams_as_one_ustar_archive_of_its_declared_length() {
        let snapshot = Snapshot {
            id: "capture".into(),
            entries: vec![
                Entry {
                    path: "notes/a.md".into(),
                    bytes: 3,
                    digest: String::new(),
                    content: Content::Memory(b"abc".to_vec()),
                },
                Entry {
                    path: "notes/empty.md".into(),
                    bytes: 0,
                    digest: String::new(),
                    content: Content::Memory(vec![]),
                },
            ],
            deletes: vec![],
            absent: vec![],
        };
        let manifest = br#"{"ok":true}"#;
        let mut archive = Vec::new();
        snapshot.write_tar(manifest, &mut archive).unwrap();
        assert_eq!(archive.len() as u64, snapshot.tar_length(manifest));
        assert_eq!(archive.len(), 512 * 7);
        let header = |offset: usize| &archive[offset..offset + 512];
        for (offset, name, size) in [
            (0, "manifest.json", 11),
            (1024, "files/0", 3),
            (2048, "files/1", 0),
        ] {
            let block = header(offset);
            assert_eq!(&block[..name.len()], name.as_bytes());
            assert_eq!(&block[124..135], format!("{size:011o}").as_bytes());
            assert_eq!(&block[257..263], b"ustar\0");
            let recorded =
                u32::from_str_radix(std::str::from_utf8(&block[148..154]).unwrap(), 8).unwrap();
            let mut copy = block.to_vec();
            copy[148..156].copy_from_slice(b"        ");
            assert_eq!(recorded, copy.iter().map(|b| u32::from(*b)).sum::<u32>());
        }
        assert_eq!(&archive[512..523], manifest);
        assert_eq!(&archive[1536..1539], b"abc");
        assert!(archive[2560..].iter().all(|b| *b == 0));
    }
    const TREE: Tree = Tree {
        directories: &["work", "repository"],
        reserved: ".git",
    };
    use std::os::unix::fs::{PermissionsExt, symlink};
    struct Fixture {
        root: PathBuf,
        repository: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .join(format!("poketto-transfer-{}", crate::new_uuid().unwrap()));
            let repository = root.join("work/repository");
            fs::create_dir_all(&repository).unwrap();
            Self { root, repository }
        }
        fn incoming(
            &self,
            path: &str,
            bytes: &[u8],
            expected: Option<&str>,
            delete: bool,
            identical: bool,
        ) -> Incoming {
            let mut incoming = Incoming::begin(&self.root, TREE, &json!({"path":path,"bytes":bytes.len(),"sha256":hash(bytes),"expectedSha256":expected,"delete":delete,"allowIdentical":identical})).unwrap();
            for (index, part) in bytes.chunks(CHUNK_BYTES).enumerate() {
                incoming
                    .append(&json!({"offset":index*CHUNK_BYTES,"data":STANDARD.encode(part)}))
                    .unwrap();
            }
            incoming
        }
        fn install(&self, incoming: &mut Incoming) -> Result<Value> {
            let info = fs::metadata(&self.root).unwrap();
            incoming.install(info.uid(), info.gid(), &AtomicBool::new(false))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }
    #[test]
    fn selection_rejects_escapes_unicode_collisions_and_reserved_git() {
        for path in [
            "/etc/passwd",
            "../secret",
            "a/../b",
            "a//b",
            "a\\b",
            "a\0b",
            "a\nb",
            ".git/config",
            "x/.GIT/config",
        ] {
            assert!(
                selected(TREE, &json!([path]), &json!([])).is_err(),
                "{path:?}"
            );
        }
        for (writes, deletes, reason) in [
            (json!([]), json!([]), "SELECTION_LIMIT"),
            (json!(["straße"]), json!(["strasse"]), "PATH_COLLISION"),
            (json!(["é"]), json!(["e\u{301}"]), "PATH_COLLISION"),
            (json!([1]), json!([]), "INVALID_PATH"),
            (json!(false), json!([]), "INVALID_ARGUMENTS"),
        ] {
            assert_eq!(
                selected(TREE, &writes, &deletes).unwrap_err().reason,
                reason
            );
        }
        assert!(selected(TREE, &json!(["private/猫.md"]), &json!(["removed.md"])).is_ok());
    }
    #[test]
    fn text_capture_preserves_bytes_explicit_deletions_and_optional_absence() {
        let fixture = Fixture::new();
        let flag = AtomicBool::new(false);
        let bytes = "\u{feff}---\r\ntitle: 猫\r\n---\r\n正文\n".as_bytes();
        fs::write(fixture.repository.join("note.md"), bytes).unwrap();
        let snapshot = Snapshot::capture(
            &fixture.root,
            TREE,
            "CAPTURE_BEGIN",
            &json!({"writes":["note.md"],"deletes":["deleted.md"]}),
            &flag,
        )
        .unwrap();
        let manifest = snapshot.manifest();
        assert_eq!(manifest["writes"][0]["sha256"], hash(bytes));
        assert_eq!(manifest["deletes"], json!(["deleted.md"]));
        assert_eq!(archived(&snapshot), vec![bytes.to_vec()]);
        let absent = Snapshot::capture(
            &fixture.root,
            TREE,
            "CAPTURE_OPTIONAL",
            &json!({"path":"absent/child"}),
            &flag,
        )
        .unwrap();
        assert_eq!(absent.manifest()["absent"], json!(["absent/child"]));
        fs::write(fixture.repository.join("invalid"), [255]).unwrap();
        assert_eq!(
            Snapshot::capture(
                &fixture.root,
                TREE,
                "CAPTURE_OPTIONAL",
                &json!({"path":"invalid"}),
                &flag
            )
            .err()
            .unwrap()
            .reason,
            "NOT_UTF8"
        );
        fs::write(fixture.repository.join("limit"), vec![b'x'; TEXT_BYTES]).unwrap();
        assert!(
            Snapshot::capture(
                &fixture.root,
                TREE,
                "CAPTURE_BEGIN",
                &json!({"writes":["limit"],"deletes":[]}),
                &flag
            )
            .is_ok()
        );
        assert_eq!(
            Snapshot::capture(
                &fixture.root,
                TREE,
                "CAPTURE_BEGIN",
                &json!({"writes":["limit","note.md"],"deletes":[]}),
                &flag
            )
            .err()
            .unwrap()
            .reason,
            "TEXT_LIMIT"
        );
    }
    #[test]
    fn binary_snapshot_is_private_immutable_and_released() {
        let fixture = Fixture::new();
        let bytes: Vec<u8> = (0..256_000).map(|v| (v % 256) as u8).collect();
        fs::write(fixture.repository.join("data"), &bytes).unwrap();
        let mut snapshot = Snapshot::capture(
            &fixture.root,
            TREE,
            "CAPTURE_BINARY",
            &json!({"path":"data"}),
            &AtomicBool::new(false),
        )
        .unwrap();
        let stage = fixture.root.join(format!(
            "outgoing-{}",
            match &snapshot.entries[0].content {
                Content::Disk(v) => v
                    .path
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .strip_prefix("outgoing-")
                    .unwrap(),
                _ => panic!(),
            }
        ));
        assert_eq!(fs::metadata(&stage).unwrap().mode() & 0o777, 0o600);
        fs::write(fixture.repository.join("data"), b"changed").unwrap();
        // The archive comes from the staged copy, not from the changed source.
        assert_eq!(archived(&snapshot), vec![bytes.to_vec()]);
        snapshot.close().unwrap();
        assert!(!stage.exists());
    }
    #[test]
    fn capture_and_install_never_follow_links_or_special_files() {
        let fixture = Fixture::new();
        let outside = fixture.root.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("secret"), b"secret").unwrap();
        symlink(&outside, fixture.repository.join("linked")).unwrap();
        symlink(outside.join("secret"), fixture.repository.join("symbolic")).unwrap();
        fs::hard_link(outside.join("secret"), fixture.repository.join("hard")).unwrap();
        let fifo = fixture.repository.join("fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        for path in ["linked/secret", "symbolic", "hard", "fifo"] {
            assert!(
                Snapshot::capture(
                    &fixture.root,
                    TREE,
                    "CAPTURE_BINARY",
                    &json!({"path":path}),
                    &AtomicBool::new(false)
                )
                .is_err()
            );
            let mut incoming =
                fixture.incoming(path, b"replace", Some(&hash(b"secret")), false, false);
            assert!(fixture.install(&mut incoming).is_err());
        }
        assert_eq!(fs::read(outside.join("secret")).unwrap(), b"secret");
        let original = fixture.root.join("original");
        fs::rename(&fixture.repository, &original).unwrap();
        symlink(&outside, &fixture.repository).unwrap();
        assert!(
            Snapshot::capture(
                &fixture.root,
                TREE,
                "CAPTURE_OPTIONAL",
                &json!({"path":"missing"}),
                &AtomicBool::new(false)
            )
            .is_err()
        );
    }
    #[test]
    fn installation_rechecks_content_preserves_exec_mode_and_retries_identical() {
        let fixture = Fixture::new();
        let path = fixture.repository.join("script");
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let mut incoming = fixture.incoming("script", b"new", Some(&hash(b"old")), false, false);
        assert_eq!(fixture.install(&mut incoming).unwrap()["changed"], true);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o711);
        assert_eq!(fixture.install(&mut incoming).unwrap()["changed"], true);
        let inode = fs::metadata(&path).unwrap().ino();
        let mut retry = fixture.incoming("script", b"new", None, false, true);
        assert_eq!(fixture.install(&mut retry).unwrap()["changed"], false);
        assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
        let mut conflict =
            fixture.incoming("script", b"replace", Some(&hash(b"old")), false, false);
        assert!(fixture.install(&mut conflict).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"new");
        let mut delete = fixture.incoming("script", b"", Some(&hash(b"new")), true, false);
        assert_eq!(fixture.install(&mut delete).unwrap()["changed"], true);
        let mut retry = fixture.incoming("script", b"", Some(&hash(b"new")), true, true);
        assert_eq!(fixture.install(&mut retry).unwrap()["changed"], false);
        let mut empty = fixture.incoming("new/folder/empty", b"", None, false, false);
        assert!(fixture.install(&mut empty).is_ok());
        assert_eq!(
            fs::read(fixture.repository.join("new/folder/empty")).unwrap(),
            b""
        );
    }
    #[test]
    fn corrupt_or_incomplete_staging_cannot_install_and_abort_removes_it() {
        let fixture = Fixture::new();
        let mut partial=Incoming::begin(&fixture.root, TREE, &json!({"path":"note","bytes":4,"sha256":hash(b"data"),"expectedSha256":null,"delete":false,"allowIdentical":false})).unwrap();
        partial
            .append(&json!({"offset":0,"data":STANDARD.encode(b"da")}))
            .unwrap();
        assert!(
            partial
                .append(&json!({"offset":0,"data":STANDARD.encode(b"da")}))
                .is_err()
        );
        assert!(fixture.install(&mut partial).is_err());
        partial
            .append(&json!({"offset":2,"data":STANDARD.encode(b"XX")}))
            .unwrap();
        assert!(fixture.install(&mut partial).is_err());
        let mut corrupt = fixture.incoming("note", b"original", None, false, false);
        corrupt
            .stage
            .file()
            .unwrap()
            .write_at(b"changed!", 0)
            .unwrap();
        assert!(fixture.install(&mut corrupt).is_err());
        let path = corrupt.stage.path.clone();
        corrupt.close().unwrap();
        assert!(!path.exists());
        assert!(!fixture.repository.join("note").exists());
    }
}
