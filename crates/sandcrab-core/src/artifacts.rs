//! Lease-scoped immutable disk artifacts and bounded command-output previews.
use base64::{Engine, engine::general_purpose::STANDARD};
use rustix::fs::OFlags;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, DirBuilder, File, Metadata, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};
const MAX_TOTAL: u64 = 256 * 1024 * 1024;
const MAX_FILE: u64 = 128 * 1024 * 1024;
const MAX_COUNT: usize = 16;
type Result<T> = std::result::Result<T, &'static str>;
type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;
#[derive(PartialEq, Eq)]
struct Version(u64, u64, u64, i64, i64, i64, i64);
fn version(info: &Metadata) -> Version {
    Version(
        info.dev(),
        info.ino(),
        info.len(),
        info.mtime(),
        info.mtime_nsec(),
        info.ctime(),
        info.ctime_nsec(),
    )
}
struct Description {
    name: String,
    media_type: String,
    bytes: u64,
    digest: String,
    truncated: bool,
}
struct Entry {
    path: PathBuf,
    file: File,
    name: String,
    media_type: String,
    bytes: u64,
    digest: String,
    deadline: Instant,
    version: Version,
    truncated: bool,
}
pub struct Store {
    root: PathBuf,
    tree: crate::transfer::Tree,
    directory: PathBuf,
    entries: HashMap<String, Entry>,
    clock: Clock,
    maximum: u64,
    count: usize,
    closed: bool,
}
fn unavailable<T>(_: T) -> &'static str {
    "ARTIFACT_UNAVAILABLE"
}
impl Store {
    pub fn new(root: &Path, tree: crate::transfer::Tree) -> Result<Self> {
        Self::configured(root, tree, Arc::new(Instant::now), MAX_TOTAL, MAX_COUNT)
    }
    fn configured(
        root: &Path,
        tree: crate::transfer::Tree,
        clock: Clock,
        maximum: u64,
        count: usize,
    ) -> Result<Self> {
        if maximum == 0 || maximum > MAX_TOTAL || count == 0 || count > MAX_COUNT {
            return Err("ARTIFACT_CAPACITY");
        }
        let directory = root.join("artifacts");
        DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(unavailable)?;
        Ok(Self {
            root: root.into(),
            tree,
            directory,
            entries: HashMap::new(),
            clock,
            maximum,
            count,
            closed: false,
        })
    }
    fn admit(&mut self, media_type: &Value, size: u64) -> Result<u64> {
        if self.closed {
            return Err("ARTIFACT_UNAVAILABLE");
        }
        let media = media_type
            .as_str()
            .filter(|v| v.len() <= 128)
            .ok_or("INVALID_ARTIFACT")?;
        let Some((kind, subtype)) = media.split_once('/') else {
            return Err("INVALID_ARTIFACT");
        };
        if [kind, subtype].iter().any(|v| {
            v.is_empty()
                || !v
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".+-".contains(&b))
        }) {
            return Err("INVALID_ARTIFACT");
        }
        self.reap().map_err(unavailable)?;
        let remaining = self.maximum - self.entries.values().map(|v| v.bytes).sum::<u64>();
        if self.entries.len() >= self.count || size > remaining || size > MAX_FILE {
            return Err("ARTIFACT_CAPACITY");
        }
        Ok(remaining.min(MAX_FILE))
    }
    fn keep(&mut self, identifier: String, file: File, description: Description) -> Result<Value> {
        let Description {
            name,
            media_type,
            bytes,
            digest,
            truncated,
        } = description;
        let path = self.directory.join(&identifier);
        let result = (|| {
            let info = file.metadata().map_err(unavailable)?;
            if !info.is_file() || info.nlink() != 1 || info.len() != bytes {
                return Err("ARTIFACT_UNAVAILABLE");
            }
            let entry = Entry {
                path: path.clone(),
                file,
                name,
                media_type,
                bytes,
                digest,
                deadline: (self.clock)() + Duration::from_secs(300),
                version: version(&info),
                truncated,
            };
            let metadata = self.metadata(&identifier, &entry);
            self.entries.insert(identifier, entry);
            Ok(metadata)
        })();
        if result.is_err() {
            let _ = fs::remove_file(path);
        }
        result
    }
    pub fn capture(
        &mut self,
        path: &Value,
        media_type: &Value,
        cancelled: &AtomicBool,
    ) -> Result<Value> {
        let maximum = self.admit(media_type, 0)?;
        let mut snapshot = crate::transfer::Snapshot::capture_binary(
            &self.root, self.tree, path, maximum, cancelled,
        )
        .map_err(unavailable)?;
        let identifier = snapshot.id.clone();
        let destination = self.directory.join(&identifier);
        if self.entries.contains_key(&identifier) || fs::symlink_metadata(&destination).is_ok() {
            return Err("ARTIFACT_UNAVAILABLE");
        }
        let (file, path, bytes, digest) = snapshot
            .transfer_binary(&destination)
            .map_err(unavailable)?;
        self.keep(
            identifier,
            file,
            Description {
                name: path.rsplit('/').next().unwrap().into(),
                media_type: media_type.as_str().unwrap().into(),
                bytes,
                digest,
                truncated: false,
            },
        )
    }
    pub fn put(&mut self, name: &str, content: &[u8], truncated: bool) -> Result<Value> {
        if !["stdout.txt", "stderr.txt"].contains(&name) {
            return Err("INVALID_ARTIFACT");
        }
        self.admit(&json!("text/plain"), content.len() as u64)?;
        let identifier = crate::new_uuid().map_err(unavailable)?;
        let path = self.directory.join(&identifier);
        if self.entries.contains_key(&identifier) {
            return Err("ARTIFACT_UNAVAILABLE");
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(OFlags::NOFOLLOW.bits() as i32)
            .open(&path)
            .map_err(unavailable)?;
        if let Err(error) = file.write_all(content) {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(unavailable(error));
        }
        self.keep(
            identifier,
            file,
            Description {
                name: name.into(),
                media_type: "text/plain".into(),
                bytes: content.len() as u64,
                digest: format!("{:x}", Sha256::digest(content)),
                truncated,
            },
        )
    }
    fn metadata(&self, id: &str, entry: &Entry) -> Value {
        let remaining = entry.deadline.saturating_duration_since((self.clock)());
        json!({"artifactId":id,"name":entry.name,"mediaType":entry.media_type,"bytes":entry.bytes,"sha256":entry.digest,"truncated":entry.truncated,"expiresInSeconds":remaining.as_secs()+u64::from(remaining.subsec_nanos()>0)})
    }
    pub fn read(&mut self, id: &str, offset: &Value, limit: &Value) -> Result<Value> {
        self.reap().map_err(unavailable)?;
        let entry = self
            .entries
            .get(id)
            .filter(|_| !self.closed)
            .ok_or("ARTIFACT_UNAVAILABLE")?;
        let offset = offset
            .as_u64()
            .filter(|v| *v <= entry.bytes)
            .ok_or("INVALID_ARTIFACT_RANGE")?;
        let limit = limit
            .as_u64()
            .filter(|v| (1..=65536).contains(v))
            .ok_or("INVALID_ARTIFACT_RANGE")?;
        let info = entry.file.metadata().map_err(unavailable)?;
        if !info.is_file() || info.nlink() != 1 || version(&info) != entry.version {
            return Err("ARTIFACT_UNAVAILABLE");
        }
        let mut bytes = vec![0; limit.min(entry.bytes - offset) as usize];
        let mut read = 0;
        while read < bytes.len() {
            let count = entry
                .file
                .read_at(&mut bytes[read..], offset + read as u64)
                .map_err(unavailable)?;
            if count == 0 {
                return Err("ARTIFACT_UNAVAILABLE");
            }
            read += count;
        }
        if entry.deadline <= (self.clock)() {
            self.remove(id).map_err(unavailable)?;
            return Err("ARTIFACT_UNAVAILABLE");
        }
        let mut response = self.metadata(id, entry);
        response["offset"] = offset.into();
        response["data"] = STANDARD.encode(bytes).into();
        Ok(response)
    }
    pub fn remove(&mut self, id: &str) -> io::Result<()> {
        if let Some(entry) = self.entries.remove(id) {
            drop(entry.file);
            match fs::remove_file(entry.path) {
                Ok(()) => (),
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    pub fn reap(&mut self) -> io::Result<()> {
        let now = (self.clock)();
        let expired: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, v)| v.deadline <= now)
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            self.remove(&id)?;
        }
        Ok(())
    }
    pub fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        let mut error = None;
        for id in self.entries.keys().cloned().collect::<Vec<_>>() {
            if let Err(e) = self.remove(&id) {
                error = Some(e);
            }
        }
        error.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::symlink,
        sync::atomic::{AtomicU64, Ordering},
    };
    struct Fixture {
        root: PathBuf,
        now: Arc<AtomicU64>,
        store: Store,
    }
    impl Fixture {
        fn new(maximum: u64, count: usize) -> Self {
            let root = std::env::temp_dir()
                .join(format!("poketto-artifact-{}", crate::new_uuid().unwrap()));
            fs::create_dir_all(root.join("work/repository")).unwrap();
            let now = Arc::new(AtomicU64::new(0));
            let ticks = now.clone();
            let base = Instant::now();
            let store = Store::configured(
                &root,
                crate::transfer::Tree {
                    directories: &["work", "repository"],
                    reserved: ".git",
                },
                Arc::new(move || base + Duration::from_secs(ticks.load(Ordering::SeqCst))),
                maximum,
                count,
            )
            .unwrap();
            Self { root, now, store }
        }
        fn bytes(&mut self, item: &Value) -> Vec<u8> {
            let reply = self
                .store
                .read(
                    item["artifactId"].as_str().unwrap(),
                    &json!(0),
                    &json!(65536),
                )
                .unwrap();
            STANDARD.decode(reply["data"].as_str().unwrap()).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.store.close().unwrap();
            fs::remove_dir_all(&self.root).unwrap();
        }
    }
    #[test]
    fn captured_bytes_are_private_immutable_and_scoped_to_their_store() {
        let mut fixture = Fixture::new(32, 3);
        let source = fixture.root.join("work/repository/note.txt");
        fs::write(&source, b"original").unwrap();
        let item = fixture
            .store
            .capture(
                &json!("note.txt"),
                &json!("text/plain"),
                &AtomicBool::new(false),
            )
            .unwrap();
        fs::write(source, b"changed").unwrap();
        assert_eq!(fixture.bytes(&item), b"original");
        assert_eq!(
            fs::metadata(
                fixture
                    .store
                    .directory
                    .join(item["artifactId"].as_str().unwrap())
            )
            .unwrap()
            .mode()
                & 0o777,
            0o600
        );
        let mut other = Fixture::new(32, 3);
        let equal = other.store.put("stdout.txt", b"original", false).unwrap();
        assert_ne!(item["artifactId"], equal["artifactId"]);
        assert_eq!(
            other
                .store
                .read(item["artifactId"].as_str().unwrap(), &json!(0), &json!(1))
                .unwrap_err(),
            "ARTIFACT_UNAVAILABLE"
        );
        assert!(!fs::read_dir(&fixture.root).unwrap().any(|v| {
            v.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("outgoing-")
        }));
    }
    #[test]
    fn expiry_frees_capacity_and_retired_handles_cannot_read_new_entries() {
        let mut fixture = Fixture::new(32, 3);
        let old = fixture.store.put("stdout.txt", &[b'a'; 32], true).unwrap();
        assert_eq!(old["expiresInSeconds"], 300);
        assert_eq!(
            fixture.store.put("stderr.txt", b"x", false).unwrap_err(),
            "ARTIFACT_CAPACITY"
        );
        fixture.now.store(300, Ordering::SeqCst);
        assert_eq!(
            fixture
                .store
                .read(old["artifactId"].as_str().unwrap(), &json!(0), &json!(1))
                .unwrap_err(),
            "ARTIFACT_UNAVAILABLE"
        );
        assert_eq!(fs::read_dir(&fixture.store.directory).unwrap().count(), 0);
        let new = fixture.store.put("stdout.txt", &[b'b'; 32], false).unwrap();
        assert_ne!(new["artifactId"], old["artifactId"]);
        assert_eq!(fixture.bytes(&new), [b'b'; 32]);
        fixture
            .store
            .remove(new["artifactId"].as_str().unwrap())
            .unwrap();
        fixture
            .store
            .remove(new["artifactId"].as_str().unwrap())
            .unwrap();
    }
    #[test]
    fn ranges_media_types_links_and_tampering_cannot_expose_bytes() {
        let mut fixture = Fixture::new(65536, 16);
        let root = fixture.root.clone();
        fs::write(root.join("outside"), b"secret").unwrap();
        symlink(root.join("outside"), root.join("work/repository/symbolic")).unwrap();
        fs::hard_link(root.join("outside"), root.join("work/repository/hard")).unwrap();
        for path in ["../outside", "/etc/passwd", "symbolic", "hard", "missing"] {
            assert!(
                fixture
                    .store
                    .capture(
                        &json!(path),
                        &json!("application/octet-stream"),
                        &AtomicBool::new(false)
                    )
                    .is_err()
            );
        }
        for media in [
            "text/plain\nHeader: x",
            "text",
            "text/",
            "text/too/many",
            "Text/plain",
        ] {
            assert_eq!(
                fixture
                    .store
                    .capture(&json!("missing"), &json!(media), &AtomicBool::new(false))
                    .unwrap_err(),
                "INVALID_ARTIFACT"
            );
        }
        let item = fixture.store.put("stdout.txt", b"hello", false).unwrap();
        let id = item["artifactId"].as_str().unwrap();
        for (offset, limit) in [
            (json!(-1), json!(1)),
            (json!(6), json!(1)),
            (json!(true), json!(1)),
            (json!(0), json!(65537)),
            (json!(0), json!(0)),
        ] {
            assert_eq!(
                fixture.store.read(id, &offset, &limit).unwrap_err(),
                "INVALID_ARTIFACT_RANGE"
            );
        }
        assert_eq!(
            fixture.store.read(id, &json!(5), &json!(1)).unwrap()["data"],
            ""
        );
        fs::write(fixture.store.directory.join(id), b"tampered").unwrap();
        assert_eq!(
            fixture.store.read(id, &json!(0), &json!(1)).unwrap_err(),
            "ARTIFACT_UNAVAILABLE"
        );
        assert_eq!(fs::read(root.join("outside")).unwrap(), b"secret");
        fixture.store.close().unwrap();
        assert_eq!(fs::read_dir(&fixture.store.directory).unwrap().count(), 0);
    }
    #[test]
    fn count_and_binary_capture_bounds_are_independent() {
        let mut fixture = Fixture::new(32, 3);
        for _ in 0..3 {
            fixture.store.put("stdout.txt", b"", false).unwrap();
        }
        assert_eq!(
            fixture.store.put("stderr.txt", b"", false).unwrap_err(),
            "ARTIFACT_CAPACITY"
        );
        fixture.now.store(300, Ordering::SeqCst);
        fs::write(fixture.root.join("work/repository/large"), [b'x'; 33]).unwrap();
        assert_eq!(
            fixture
                .store
                .capture(
                    &json!("large"),
                    &json!("text/plain"),
                    &AtomicBool::new(false)
                )
                .unwrap_err(),
            "ARTIFACT_UNAVAILABLE"
        );
        assert_eq!(fs::read_dir(&fixture.store.directory).unwrap().count(), 0);
        fixture.store.close().unwrap();
        assert_eq!(
            fixture
                .store
                .put("stdout.txt", b"closed", false)
                .unwrap_err(),
            "ARTIFACT_UNAVAILABLE"
        );
    }
}
