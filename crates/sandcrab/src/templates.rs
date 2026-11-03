//! Published templates survive restart. Incoming trees are disposable only after
//! the runtime has contained its old helpers; ambiguous cleanup fences new imports.
use crate::{
    config::{Profile, invalid},
    file_io::digest,
    file_records::{Result, Stage},
    template_io::Tree,
};
use sandcrab_core::fs::{protected_directory, protected_file};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder, File},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

pub const ENTRY_LIMIT: usize = 100_000;

struct State {
    trees: BTreeMap<String, Tree>,
    active: Option<String>,
    fenced: bool,
    pins: BTreeMap<String, usize>,
}
pub struct Store {
    root: PathBuf,
    owner: Value,
    max_count: usize,
    pool_bytes: u64,
    state: Mutex<State>,
}

pub struct Finished {
    /// Helpers are contained and incoming staging has been removed or published.
    pub cleanup_complete: bool,
    pub catalog_available: bool,
}

/// Before setup, drop releases the pin. Once a mount may exist, only confirmed
/// workspace cleanup releases it; losing an owner preserves the pin until restart.
pub struct Lease {
    store: Arc<Store>,
    id: String,
    started: AtomicBool,
    released: AtomicBool,
}
impl Lease {
    pub fn lower(&self) -> PathBuf {
        self.store.root.join("objects").join(&self.id).join("lower")
    }
    pub fn start(&self) {
        self.started.store(true, Ordering::SeqCst);
    }
    pub fn release(&self) {
        if !self.released.swap(true, Ordering::SeqCst) {
            let mut state = self.store.state.lock().unwrap();
            if let Some(count) = state.pins.get_mut(&self.id) {
                *count -= 1;
                if *count == 0 {
                    state.pins.remove(&self.id);
                }
            }
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if !self.started.load(Ordering::SeqCst) {
            self.release();
        }
    }
}

fn directory(path: &Path) -> io::Result<()> {
    match DirBuilder::new().mode(0o700).create(path) {
        Err(error) if error.kind() != io::ErrorKind::AlreadyExists => return Err(error),
        _ => (),
    }
    protected_directory(path)
}

fn checked_tree(path: &Path) -> io::Result<Tree> {
    protected_directory(path)?;
    crate::storage::no_mounts_below(path, false)?;
    let tree: Tree = serde_json::from_slice(&protected_file(&path.join("record.json"), 4096)?)?;
    if !digest(&tree.id)
        || tree.uid == 0
        || tree.bytes > 1_073_741_824
        || tree.allocated_bytes > 1 << 50
        || tree.entries > ENTRY_LIMIT
    {
        return Err(invalid("Invalid template record"));
    }
    protected_directory(&path.join("lower"))?;
    let data = fs::symlink_metadata(path.join("lower/data"))?;
    if !data.is_dir() || data.uid() != tree.uid || data.gid() != tree.gid {
        return Err(invalid("Invalid template tree"));
    }
    Ok(tree)
}

impl Store {
    pub fn open(
        runtime: &Path,
        owner: Value,
        max_count: usize,
        pool_bytes: u64,
    ) -> io::Result<Arc<Self>> {
        let root = runtime.join("templates");
        directory(&root)?;
        if root.metadata()?.mode() & 0o077 != 0 {
            return Err(invalid("Template store must have mode 0700"));
        }
        let marker = root.join("owner.json");
        match protected_file(&marker, 4096) {
            Ok(bytes) if sandcrab_core::parse(&bytes).ok() == Some(owner.clone()) => (),
            Ok(_) => return Err(invalid("Templates belong to another runtime namespace")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if fs::read_dir(&root)?.next().is_some() {
                    return Err(invalid("Refusing to adopt unowned templates"));
                }
                crate::storage::write(&marker, &owner)?;
            }
            Err(error) => return Err(error),
        }
        directory(&root.join("objects"))?;
        directory(&root.join("incoming"))?;
        let mut trees = BTreeMap::new();
        for entry in fs::read_dir(root.join("objects"))? {
            let entry = entry?;
            let id = entry
                .file_name()
                .into_string()
                .map_err(|_| invalid("Invalid template name"))?;
            if !digest(&id) {
                return Err(invalid("Invalid template name"));
            }
            let tree = checked_tree(&entry.path())?;
            if tree.id != id {
                return Err(invalid("Template record identity changed"));
            }
            trees.insert(id, tree);
            if trees.len() > max_count {
                return Err(invalid("Stored templates exceed max_templates"));
            }
        }
        if trees.values().map(|tree| tree.allocated_bytes).sum::<u64>() > pool_bytes {
            return Err(invalid("Stored templates exceed template_pool_bytes"));
        }
        Ok(Arc::new(Self {
            root,
            owner,
            max_count,
            pool_bytes,
            state: Mutex::new(State {
                trees,
                active: None,
                fenced: false,
                pins: BTreeMap::new(),
            }),
        }))
    }

    fn verify(&self) -> io::Result<()> {
        protected_directory(&self.root)?;
        if self.root.metadata()?.mode() & 0o077 != 0 {
            return Err(invalid("Template store must have mode 0700"));
        }
        if sandcrab_core::parse(&protected_file(&self.root.join("owner.json"), 4096)?)
            .ok()
            .as_ref()
            != Some(&self.owner)
        {
            return Err(invalid("Template namespace changed"));
        }
        for name in ["objects", "incoming"] {
            protected_directory(&self.root.join(name))?;
        }
        Ok(())
    }

    /// The caller first kills and waits for every old-epoch helper and workload.
    pub fn recover(&self) -> io::Result<()> {
        self.verify()?;
        let mut entries = Vec::new();
        for entry in fs::read_dir(self.root.join("incoming"))? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| invalid("Invalid template staging name"))?;
            let import = name
                .strip_prefix(".transfer-")
                .is_some_and(sandcrab_core::uuid);
            let trash = name.strip_prefix(".deleted-").is_some_and(digest);
            if !import && !trash {
                return Err(invalid("Unexpected template staging entry"));
            }
            protected_directory(&entry.path())?;
            crate::storage::no_mounts_below(&entry.path(), false)?;
            entries.push(entry.path());
        }
        for path in entries {
            fs::remove_dir_all(path)?;
        }
        File::open(self.root.join("incoming"))?.sync_all()
    }

    fn info(&self, state: &State) -> Value {
        json!({"available":!state.fenced,"count":state.trees.len(),"maxTemplates":self.max_count,
            "logicalBytes":state.trees.values().map(|tree|tree.bytes).sum::<u64>(),
            "allocatedBytes":state.trees.values().map(|tree|tree.allocated_bytes).sum::<u64>(),
            "poolBytes":self.pool_bytes,"entryLimit":ENTRY_LIMIT,"importBusy":state.active.is_some()})
    }

    pub fn list(&self, after: &str) -> Value {
        let state = self.state.lock().unwrap();
        let page = state
            .trees
            .values()
            .filter(|tree| tree.id.as_str() > after)
            .take(65)
            .collect::<Vec<_>>();
        json!({"templates":page.iter().take(64).collect::<Vec<_>>(),"pool":self.info(&state),
            "nextAfter":(page.len()>64).then(||&page[63].id)})
    }

    pub fn get(&self, id: &str) -> Result<Tree> {
        self.state
            .lock()
            .unwrap()
            .trees
            .get(id)
            .cloned()
            .ok_or((404, "TEMPLATE_NOT_FOUND"))
    }

    pub fn acquire(self: &Arc<Self>, id: &str, profile: &Profile) -> Result<Lease> {
        let mut state = self.state.lock().unwrap();
        if state.fenced {
            return Err((503, "TEMPLATE_STATE_UNCERTAIN"));
        }
        let tree = state.trees.get(id).ok_or((404, "TEMPLATE_NOT_FOUND"))?;
        if (tree.uid, tree.gid) != (profile.uid, profile.gid) {
            return Err((409, "TEMPLATE_IDENTITY_MISMATCH"));
        }
        self.verify()
            .map_err(|_| (503, "TEMPLATE_STATE_UNCERTAIN"))?;
        if checked_tree(&self.root.join("objects").join(id))
            .ok()
            .as_ref()
            != Some(tree)
        {
            return Err((503, "TEMPLATE_STATE_UNCERTAIN"));
        }
        *state.pins.entry(id.into()).or_default() += 1;
        Ok(Lease {
            store: self.clone(),
            id: id.into(),
            started: AtomicBool::new(false),
            released: AtomicBool::new(false),
        })
    }

    pub fn begin(&self, profile_name: &str, profile: &Profile) -> Result<Stage> {
        let mut state = self.state.lock().unwrap();
        if state.fenced {
            return Err((503, "TEMPLATE_STATE_UNCERTAIN"));
        }
        if state.active.is_some() {
            return Err((409, "TEMPLATE_IMPORT_BUSY"));
        }
        self.verify()
            .map_err(|_| (503, "TEMPLATE_STATE_UNCERTAIN"))?;
        let id = sandcrab_core::new_uuid().map_err(|_| (503, "TEMPLATE_UNAVAILABLE"))?;
        let stage = Stage {
            id: id.clone(),
            session_id: id.clone(),
            volume_id: None,
            rootfs: false,
            profile: profile_name.into(),
            uid: profile.uid,
            gid: profile.gid,
        };
        state.active = Some(id);
        let prepared = (|| -> io::Result<()> {
            let path = self.stage(&stage);
            DirBuilder::new().mode(0o700).create(&path)?;
            crate::storage::write(&path.join("owner.json"), &stage)
        })();
        if prepared.is_err() {
            state.fenced = true;
            return Err((503, "TEMPLATE_STATE_UNCERTAIN"));
        }
        Ok(stage)
    }

    pub fn stage(&self, stage: &Stage) -> PathBuf {
        self.root
            .join("incoming")
            .join(format!(".transfer-{}", stage.id))
    }

    pub fn publish(&self, stage: &Stage, tree: Tree) -> Result<Tree> {
        let mut state = self.state.lock().unwrap();
        if state.fenced || state.active.as_ref() != Some(&stage.id) {
            return Err((503, "TEMPLATE_STATE_UNCERTAIN"));
        }
        if !digest(&tree.id)
            || tree.uid != stage.uid
            || tree.gid != stage.gid
            || tree.entries > ENTRY_LIMIT
            || tree.bytes > 1_073_741_824
            || tree.allocated_bytes > 1 << 50
        {
            return Err((503, "TEMPLATE_HELPER_FAILED"));
        }
        if let Some(existing) = state.trees.get(&tree.id) {
            if (existing.uid, existing.gid, existing.bytes, existing.entries)
                != (tree.uid, tree.gid, tree.bytes, tree.entries)
            {
                state.fenced = true;
                return Err((503, "TEMPLATE_STATE_UNCERTAIN"));
            }
            return Ok(existing.clone());
        }
        if state.trees.len() >= self.max_count
            || state.trees.values().map(|t| t.allocated_bytes).sum::<u64>() + tree.allocated_bytes
                > self.pool_bytes
        {
            return Err((507, "TEMPLATE_CAPACITY"));
        }
        let committed = (|| -> io::Result<()> {
            self.verify()?;
            let path = self.stage(stage);
            protected_directory(&path)?;
            crate::storage::no_mounts_below(&path, false)?;
            DirBuilder::new().mode(0o711).create(path.join("lower"))?;
            fs::rename(path.join("tree"), path.join("lower/data"))?;
            crate::storage::write(&path.join("record.json"), &tree)?;
            fs::remove_file(path.join("owner.json"))?;
            File::open(path.join("lower"))?.sync_all()?;
            File::open(&path)?.sync_all()?;
            rustix::fs::renameat_with(
                rustix::fs::CWD,
                &path,
                rustix::fs::CWD,
                self.root.join("objects").join(&tree.id),
                rustix::fs::RenameFlags::NOREPLACE,
            )?;
            File::open(self.root.join("objects"))?.sync_all()?;
            File::open(self.root.join("incoming"))?.sync_all()
        })();
        if committed.is_err() {
            state.fenced = true;
            return Err((503, "TEMPLATE_PUBLICATION_UNKNOWN"));
        }
        state.trees.insert(tree.id.clone(), tree.clone());
        Ok(tree)
    }

    pub fn finish(&self, stage: &Stage, contained: bool) -> Finished {
        let mut state = self.state.lock().unwrap();
        if !contained || state.active.as_ref() != Some(&stage.id) {
            state.fenced = true;
            return Finished {
                cleanup_complete: false,
                catalog_available: false,
            };
        }
        let clean = (|| -> io::Result<()> {
            self.verify()?;
            let path = self.stage(stage);
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                result => {
                    result?;
                }
            }
            protected_directory(&path)?;
            crate::storage::no_mounts_below(&path, false)?;
            fs::remove_dir_all(path)?;
            File::open(self.root.join("incoming"))?.sync_all()
        })();
        if clean.is_err() {
            state.fenced = true;
            return Finished {
                cleanup_complete: false,
                catalog_available: false,
            };
        }
        state.active = None;
        Finished {
            cleanup_complete: true,
            catalog_available: !state.fenced,
        }
    }

    pub fn delete(&self, id: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.fenced {
            return Err((503, "TEMPLATE_STATE_UNCERTAIN"));
        }
        if !state.trees.contains_key(id) {
            return Err((404, "TEMPLATE_NOT_FOUND"));
        }
        if state.pins.get(id).copied().unwrap_or(0) > 0 {
            return Err((409, "TEMPLATE_BUSY"));
        }
        let deleted = (|| -> io::Result<()> {
            self.verify()?;
            let path = self.root.join("objects").join(id);
            checked_tree(&path)?;
            let trash = self.root.join("incoming").join(format!(".deleted-{id}"));
            rustix::fs::renameat_with(
                rustix::fs::CWD,
                &path,
                rustix::fs::CWD,
                &trash,
                rustix::fs::RenameFlags::NOREPLACE,
            )?;
            File::open(self.root.join("objects"))?.sync_all()?;
            File::open(self.root.join("incoming"))?.sync_all()?;
            fs::remove_dir_all(trash)?;
            File::open(self.root.join("incoming"))?.sync_all()
        })();
        if deleted.is_err() {
            state.fenced = true;
            return Err((503, "TEMPLATE_STATE_UNCERTAIN"));
        }
        state.trees.remove(id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::{Gid, Uid, chown};
    use std::sync::atomic::AtomicBool;

    fn staged(store: &Store, profile: &Profile, content: &[u8]) -> (Stage, Tree) {
        let stage = store.begin("python", profile).unwrap();
        let path = store.stage(&stage).join("tree");
        fs::create_dir(&path).unwrap();
        chown(
            &path,
            Some(Uid::from_raw(profile.uid)),
            Some(Gid::from_raw(profile.gid)),
        )
        .unwrap();
        fs::write(path.join("artifact"), content).unwrap();
        chown(
            path.join("artifact"),
            Some(Uid::from_raw(profile.uid)),
            Some(Gid::from_raw(profile.gid)),
        )
        .unwrap();
        let job = crate::file_io::Job {
            action: "template-receive".into(),
            workspace: path.clone(),
            stage: store.stage(&stage),
            path: "data".into(),
            format: crate::file_io::Format::Tar,
            bytes: 0,
            sha256: String::new(),
            replace: false,
            mode: 0o755,
            uid: profile.uid,
            gid: profile.gid,
            byte_limit: 1024,
            entry_limit: 8,
            multipart: None,
            selection: None,
        };
        let tree = crate::template_io::identify(&path, &job).unwrap();
        (stage, tree)
    }

    #[test]
    fn publication_deduplicates_and_recovery_preserves_committed_templates() {
        let runtime = Path::new("/source").join(format!(
            "template-store-{}",
            sandcrab_core::new_uuid().unwrap()
        ));
        fs::create_dir(&runtime).unwrap();
        let owner = json!({"test":sandcrab_core::new_uuid().unwrap()});
        let store = Store::open(&runtime, owner.clone(), 1, 65536).unwrap();
        let mut config =
            crate::config::Config::parse(include_str!("../config.example.toml")).unwrap();
        let profile = config.profiles.get_mut("python").unwrap();
        profile.uid = 65534;
        profile.gid = 65534;
        let (stage, tree) = staged(&store, profile, b"retained");
        assert_eq!(store.publish(&stage, tree.clone()).unwrap(), tree);
        assert!(store.finish(&stage, true).cleanup_complete);
        let (stage, duplicate) = staged(&store, profile, b"retained");
        assert_eq!(duplicate, tree);
        assert_eq!(store.publish(&stage, duplicate).unwrap(), tree);
        assert!(store.finish(&stage, true).cleanup_complete);
        assert_eq!(store.list("")["pool"]["count"], 1);
        let (stage, another) = staged(&store, profile, b"another");
        assert_eq!(
            store.publish(&stage, another).unwrap_err(),
            (507, "TEMPLATE_CAPACITY")
        );
        assert!(!store.finish(&stage, false).cleanup_complete);
        assert!(store.stage(&stage).exists());
        assert!(store.begin("python", profile).is_err());
        drop(store);
        assert!(Store::open(&runtime, json!({"foreign":true}), 1, 65536).is_err());
        let store = Store::open(&runtime, owner, 1, 65536).unwrap();
        fs::write(runtime.join("templates/incoming/unknown"), b"preserve").unwrap();
        assert!(store.recover().is_err());
        assert!(store.stage(&stage).exists());
        fs::remove_file(runtime.join("templates/incoming/unknown")).unwrap();
        store.recover().unwrap();
        assert!(!store.stage(&stage).exists());
        assert_eq!(store.get(&tree.id).unwrap(), tree);
        assert_eq!(
            fs::read(
                runtime
                    .join("templates/objects")
                    .join(&tree.id)
                    .join("lower/data/artifact")
            )
            .unwrap(),
            b"retained"
        );
        assert!(matches!(
            crate::usage::measure(
                &runtime,
                crate::usage::Usage {
                    bytes: 1024 * 1024,
                    inodes: 100
                },
                &AtomicBool::new(false)
            ),
            crate::usage::Observation::Complete(_)
        ));
        store.delete(&tree.id).unwrap();
        assert_eq!(
            store.get(&tree.id).unwrap_err(),
            (404, "TEMPLATE_NOT_FOUND")
        );
        let (stage, candidate) = staged(&store, profile, b"fault");
        fs::create_dir(store.stage(&stage).join("lower")).unwrap();
        assert_eq!(
            store.publish(&stage, candidate).unwrap_err(),
            (503, "TEMPLATE_PUBLICATION_UNKNOWN")
        );
        let finished = store.finish(&stage, true);
        assert!(finished.cleanup_complete);
        assert!(!finished.catalog_available);
        assert!(!store.stage(&stage).exists());
        let limited = Store::open(&runtime, store.owner.clone(), 4, 1).unwrap();
        let (stage, tiny) = staged(&limited, profile, b"a");
        assert_eq!(tiny.bytes, 1);
        assert!(tiny.allocated_bytes > tiny.bytes);
        assert_eq!(
            limited.publish(&stage, tiny).unwrap_err(),
            (507, "TEMPLATE_CAPACITY")
        );
        assert!(limited.finish(&stage, true).cleanup_complete);
        assert_eq!(runtime.parent(), Some(Path::new("/source")));
        fs::remove_dir_all(runtime).unwrap();
    }
}
