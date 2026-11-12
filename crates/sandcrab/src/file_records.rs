//! Upload identities and stage ownership outlive transport connections. A crash
//! during publication is retained as unknown and is never replayed automatically.
use crate::{
    config::{Config, invalid, name},
    file_io::{Format, digest, valid_path},
    storage,
};
use sandcrab_core::{
    fs::{protected_directory, protected_file},
    uuid,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder, File},
    io,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, SystemTime},
};

pub type Result<T> = std::result::Result<T, (u16, &'static str)>;
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Upload {
    pub id: String,
    pub server_id: String,
    pub session_id: String,
    pub path: String,
    pub format: Format,
    pub bytes: u64,
    pub sha256: String,
    #[serde(default)]
    pub replace: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub parents: bool,
    pub mode: Option<u32>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub keep_result: bool,
}
impl Upload {
    pub fn valid(&self) -> bool {
        uuid(&self.id)
            && uuid(&self.server_id)
            && uuid(&self.session_id)
            && valid_path(&self.path, false)
            && digest(&self.sha256)
            && self.bytes <= 1_073_741_824
            && self.mode.is_none_or(|m| m <= 0o777)
    }
    pub fn digest(&self) -> String {
        let mut value = serde_json::to_value(self).unwrap();
        value.as_object_mut().unwrap().remove("serverId");
        format!("{:x}", Sha256::digest(serde_json::to_vec(&value).unwrap()))
    }
    pub fn mode(&self) -> u32 {
        self.mode.unwrap_or(if self.format == Format::Tar {
            0o755
        } else {
            0o644
        })
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Record {
    #[serde(skip)]
    pub completed_at: Option<SystemTime>,
    pub request: Upload,
    pub plan_digest: String,
    pub state: String,
    pub code: Option<String>,
    pub publication_started: bool,
    pub publication_confirmed: bool,
    pub volume_id: Option<String>,
    pub profile: String,
}
impl Record {
    pub fn value(&self) -> Value {
        json!({"id":self.request.id,"serverId":self.request.server_id,"sessionId":self.request.session_id,
            "path":self.request.path,"format":self.request.format,"bytes":self.request.bytes,"sha256":self.request.sha256,
            "planDigest":self.plan_digest,"state":self.state,"code":self.code,"volumeId":self.volume_id,"profile":self.profile,"keepResult":self.request.keep_result,
            "publication":if self.publication_confirmed {"committed"} else if self.publication_started {"unknown"} else {"none"}})
    }
    pub fn terminal(&self) -> bool {
        ["succeeded", "failed", "unknown"].contains(&self.state.as_str())
    }
    fn valid(&self) -> bool {
        self.request.valid()
            && self.plan_digest == self.request.digest()
            && name(&self.profile)
            && self.volume_id.as_ref().is_none_or(|v| uuid(v))
            && [
                "waiting",
                "receiving",
                "publishing",
                "published",
                "succeeded",
                "failed",
                "unknown",
                "closing",
            ]
            .contains(&self.state.as_str())
            && (!self.publication_confirmed || self.publication_started)
            && (self.state != "succeeded" || self.publication_confirmed)
            && self.code.as_ref().is_none_or(|c| {
                c.len() <= 64 && c.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
            })
    }
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Stage {
    pub id: String,
    pub session_id: String,
    pub volume_id: Option<String>,
    pub rootfs: bool,
    pub profile: String,
    pub uid: u32,
    pub gid: u32,
}
impl Stage {
    fn valid(&self) -> bool {
        uuid(&self.id)
            && uuid(&self.session_id)
            && self.volume_id.as_ref().is_none_or(|v| uuid(v))
            && (!self.rootfs || self.volume_id.is_none())
            && name(&self.profile)
            && self.uid != 0
    }
    pub fn workspace(&self, config: &Config) -> io::Result<PathBuf> {
        let root = self.base(config)?.join("data");
        Ok(if self.rootfs {
            root.join("workspace")
        } else {
            root
        })
    }
    fn base(&self, config: &Config) -> io::Result<PathBuf> {
        match &self.volume_id {
            Some(id) => Ok(config
                .storage
                .as_ref()
                .ok_or_else(|| invalid("File stage requires its volume store"))?
                .root
                .join("data/volumes")
                .join(id)),
            None => Ok(config
                .service
                .runtime_root
                .join("workspaces")
                .join(&self.session_id)),
        }
    }
    pub fn path(&self, config: &Config) -> io::Result<PathBuf> {
        Ok(self.base(config)?.join(format!(".transfer-{}", self.id)))
    }
}
struct State {
    records: BTreeMap<String, Record>,
    stages: BTreeMap<String, Stage>,
    fenced: bool,
}
pub struct Store {
    root: PathBuf,
    state: Mutex<State>,
    limit: usize,
}
fn directory(path: &Path) -> io::Result<()> {
    match DirBuilder::new().mode(0o700).create(path) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
        result => result?,
    }
    protected_directory(path)
}
fn read<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<T> {
    let bytes = protected_file(path, 16384)?;
    let value = sandcrab_core::parse(&bytes).map_err(|_| invalid("Invalid file metadata"))?;
    Ok(serde_json::from_value(value)?)
}
fn files(path: &Path, limit: usize) -> io::Result<Vec<(String, PathBuf)>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let filename = entry.file_name().to_string_lossy().into_owned();
        if filename.strip_prefix(".write-").is_some_and(uuid) {
            protected_file(&entry.path(), 16384)?;
            fs::remove_file(entry.path())?;
            continue;
        }
        let id = filename
            .strip_suffix(".json")
            .filter(|s| uuid(s))
            .ok_or_else(|| invalid("Unexpected file metadata"))?;
        if entries.len() >= limit {
            return Err(invalid("File record capacity exceeded"));
        }
        entries.push((id.into(), entry.path()));
    }
    Ok(entries)
}
impl Store {
    pub fn open(config: &Config) -> io::Result<Self> {
        let root = config.storage.as_ref().map_or_else(
            || config.service.runtime_root.join("uploads"),
            |s| s.root.join("state/uploads"),
        );
        directory(&root)?;
        let owner = json!({"version":3,"runtimeRoot":config.service.runtime_root,
            "cgroupRoot":config.service.cgroup_root});
        let owner_path = root.join("owner.json");
        match read::<Value>(&owner_path) {
            Ok(old) if old != owner => return Err(invalid("File cleanup namespace changed")),
            Ok(_) => (),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if fs::read_dir(&root)?.next().is_some() {
                    return Err(invalid("Refusing unowned file state"));
                }
                storage::write(&owner_path, &owner)?;
            }
            Err(e) => return Err(e),
        }
        for name in ["records", "stages"] {
            directory(&root.join(name))?;
        }
        let mut records = BTreeMap::new();
        for (id, path) in files(&root.join("records"), config.service.max_file_records)? {
            let mut record: Record = read(&path)?;
            if !record.valid() || record.request.id != id {
                return Err(invalid("Invalid upload record"));
            }
            if record.terminal() {
                record.completed_at = Some(fs::metadata(&path)?.modified()?);
            }
            records.insert(id, record);
        }
        let mut stages = BTreeMap::new();
        for (id, path) in files(&root.join("stages"), 16)? {
            let stage: Stage = read(&path)?;
            if !stage.valid() || stage.id != id {
                return Err(invalid("Invalid file stage"));
            }
            stages.insert(id, stage);
        }
        Ok(Self {
            root,
            state: Mutex::new(State {
                records,
                stages,
                fenced: false,
            }),
            limit: config.service.max_file_records,
        })
    }
    pub fn available(&self) -> bool {
        !self.state.lock().unwrap().fenced
    }
    fn view(state: &State, record: &Record) -> Record {
        let mut record = record.clone();
        if state.fenced && !record.terminal() {
            record.state = if record.publication_confirmed {
                "closing"
            } else {
                "unknown"
            }
            .into();
            record.code = Some("FILE_STATE_UNCERTAIN".into());
        }
        record
    }
    fn record_path(&self, id: &str) -> PathBuf {
        self.root.join("records").join(format!("{id}.json"))
    }
    fn save(&self, state: &mut State, mut record: Record) -> Result<Record> {
        if record.terminal() && record.completed_at.is_none() {
            record.completed_at = Some(SystemTime::now());
        }
        if storage::write(&self.record_path(&record.request.id), &record).is_err() {
            state.fenced = true;
            return Err((503, "FILE_STATE_UNCERTAIN"));
        }
        state
            .records
            .insert(record.request.id.clone(), record.clone());
        Ok(record)
    }
    pub fn existing(&self, request: &Upload) -> Result<Option<Record>> {
        let state = self.state.lock().unwrap();
        match state.records.get(&request.id) {
            Some(record) if record.plan_digest != request.digest() => Err((409, "ID_CONFLICT")),
            value => Ok(value.map(|r| Self::view(&state, r))),
        }
    }
    pub fn create(
        &self,
        request: Upload,
        profile: String,
        volume_id: Option<String>,
    ) -> Result<Record> {
        let mut state = self.state.lock().unwrap();
        if state.fenced {
            return Err((503, "FILE_STATE_UNCERTAIN"));
        }
        if let Some(record) = state.records.get(&request.id) {
            return if record.plan_digest == request.digest() {
                Ok(record.clone())
            } else {
                Err((409, "ID_CONFLICT"))
            };
        }
        if state.records.len() >= self.limit {
            return Err((429, "FILE_RECORD_CAPACITY"));
        }
        let record = Record {
            completed_at: None,
            plan_digest: request.digest(),
            request,
            state: "waiting".into(),
            code: None,
            publication_started: false,
            publication_confirmed: false,
            profile,
            volume_id,
        };
        self.save(&mut state, record)
    }
    pub fn get(&self, id: &str) -> Result<Record> {
        let state = self.state.lock().unwrap();
        state
            .records
            .get(id)
            .map(|r| Self::view(&state, r))
            .ok_or((404, "UPLOAD_NOT_FOUND"))
    }
    pub fn list(&self, after: &str) -> Value {
        let state = self.state.lock().unwrap();
        let mut rows = state.records.range((
            std::ops::Bound::Excluded(after.to_owned()),
            std::ops::Bound::Unbounded,
        ));
        let page: Vec<_> = rows
            .by_ref()
            .take(10)
            .map(|(_, r)| Self::view(&state, r).value())
            .collect();
        let next = rows
            .next()
            .and_then(|_| page.last().map(|r| r["id"].clone()));
        json!({"uploads":page,"nextAfter":next})
    }
    pub fn transition(
        &self,
        id: &str,
        expected: &[&str],
        next: &str,
        code: Option<&str>,
    ) -> Result<Record> {
        let mut state = self.state.lock().unwrap();
        if state.fenced {
            return Err((503, "FILE_STATE_UNCERTAIN"));
        }
        let mut record = state
            .records
            .get(id)
            .cloned()
            .ok_or((404, "UPLOAD_NOT_FOUND"))?;
        if !expected.contains(&record.state.as_str()) {
            return Err((409, "UPLOAD_STATE"));
        }
        record.state = next.into();
        record.code = code.map(str::to_owned);
        if next == "publishing" {
            record.publication_started = true;
        }
        if matches!(next, "published" | "succeeded") {
            record.publication_confirmed = true;
        }
        if next == "failed" {
            record.publication_started = false;
            record.publication_confirmed = false;
        }
        self.save(&mut state, record)
    }
    pub fn forget(&self, id: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        self.forget_locked(&mut state, id)
    }
    fn forget_locked(&self, state: &mut State, id: &str) -> Result<()> {
        if state.fenced {
            return Err((503, "FILE_STATE_UNCERTAIN"));
        }
        let record = state.records.get(id).ok_or((404, "UPLOAD_NOT_FOUND"))?;
        if (!record.terminal() && record.state != "waiting") || state.stages.contains_key(id) {
            return Err((409, "UPLOAD_ACTIVE"));
        }
        if fs::remove_file(self.record_path(id))
            .and_then(|_| File::open(self.root.join("records"))?.sync_all())
            .is_err()
        {
            state.fenced = true;
            return Err((503, "FILE_STATE_UNCERTAIN"));
        }
        state.records.remove(id);
        Ok(())
    }
    pub fn expire_results(&self, ttl: Duration) {
        let mut state = self.state.lock().unwrap();
        if state.fenced {
            return;
        }
        let now = SystemTime::now();
        // Bounded durable work per maintenance pass; active staging always keeps its identity.
        let expired: Vec<_> = state
            .records
            .iter()
            .filter(|(id, record)| {
                record.terminal()
                    && !record.request.keep_result
                    && !state.stages.contains_key(*id)
                    && record
                        .completed_at
                        .is_some_and(|at| now.duration_since(at).is_ok_and(|age| age >= ttl))
            })
            .take(16)
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            if self.forget_locked(&mut state, &id).is_err() {
                break;
            }
        }
    }
    pub fn begin_stage(&self, stage: &Stage, config: &Config) -> io::Result<PathBuf> {
        let mut state = self.state.lock().unwrap();
        if state.fenced || state.stages.contains_key(&stage.id) {
            return Err(invalid("File stage unavailable"));
        }
        let metadata = self.root.join("stages").join(format!("{}.json", stage.id));
        if storage::write(&metadata, stage).is_err() {
            state.fenced = true;
            return Err(invalid("File stage intent uncertain"));
        }
        state.stages.insert(stage.id.clone(), stage.clone());
        let path = stage.path(config)?;
        DirBuilder::new().mode(0o700).create(&path)?;
        storage::write(&path.join("owner.json"), stage)?;
        Ok(path)
    }
    pub fn validate_stage(&self, stage: &Stage, config: &Config) -> io::Result<Option<PathBuf>> {
        let path = stage.path(config)?;
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
            Ok(_) => (),
        }
        protected_directory(&path)?;
        match read::<Stage>(&path.join("owner.json")) {
            Ok(owner) if owner == *stage => Ok(Some(path)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                for entry in fs::read_dir(&path)? {
                    let entry = entry?;
                    if !entry
                        .file_name()
                        .to_str()
                        .and_then(|s| s.strip_prefix(".write-"))
                        .is_some_and(uuid)
                    {
                        return Err(invalid("Unowned file stage is preserved"));
                    }
                    protected_file(&entry.path(), 16384)?;
                    fs::remove_file(entry.path())?;
                }
                fs::remove_dir(&path)?;
                Ok(None)
            }
            _ => Err(invalid("File stage ownership changed")),
        }
    }
    pub fn finish_stage(&self, id: &str) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        let path = self.root.join("stages").join(format!("{id}.json"));
        if let Err(e) =
            fs::remove_file(path).and_then(|_| File::open(self.root.join("stages"))?.sync_all())
        {
            state.fenced = true;
            return Err(e);
        }
        state.stages.remove(id);
        Ok(())
    }
    pub fn pending_stages(&self) -> Vec<Stage> {
        self.state
            .lock()
            .unwrap()
            .stages
            .values()
            .cloned()
            .collect()
    }
    pub fn has_stage(&self, id: &str) -> bool {
        self.state.lock().unwrap().stages.contains_key(id)
    }
    pub fn recovered(&self) -> io::Result<()> {
        let records: Vec<_> = self
            .state
            .lock()
            .unwrap()
            .records
            .values()
            .cloned()
            .collect();
        for record in records {
            if record.terminal() {
                continue;
            }
            let (next, code) = if record.publication_confirmed {
                ("succeeded", None)
            } else if record.publication_started {
                ("unknown", Some("PUBLICATION_UNKNOWN"))
            } else {
                ("failed", Some("INTERRUPTED"))
            };
            self.transition(&record.request.id, &[&record.state], next, code)
                .map_err(|_| invalid("Upload recovery could not commit"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod retention_tests {
    use super::*;

    #[test]
    fn garbage_collection_preserves_stage_pins_and_fenced_state() {
        let root = std::env::temp_dir().join(format!(
            "sandcrab-retention-{}",
            sandcrab_core::new_uuid().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("records")).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                fs::remove_dir_all(&self.0).unwrap();
            }
        }
        let _cleanup = Cleanup(root.clone());
        let mut state = State {
            records: BTreeMap::new(),
            stages: BTreeMap::new(),
            fenced: true,
        };
        let mut ids = Vec::new();
        for (index, (status, kept, staged)) in [
            ("succeeded", false, false),
            ("unknown", false, true),
            ("failed", true, false),
            ("waiting", false, false),
        ]
        .into_iter()
        .enumerate()
        {
            let id = format!("00000000-0000-4000-8000-{index:012}");
            let request: Upload = serde_json::from_value(json!({"id":id,"serverId":id,
                "sessionId":id,"path":"file","format":"raw","bytes":1,"sha256":"0".repeat(64),
                "keepResult":kept}))
            .unwrap();
            let record = Record {
                plan_digest: request.digest(),
                request,
                state: status.into(),
                code: None,
                publication_started: status == "unknown",
                publication_confirmed: status == "succeeded",
                volume_id: None,
                profile: "python".into(),
                completed_at: Some(SystemTime::UNIX_EPOCH),
            };
            fs::write(
                root.join("records").join(format!("{id}.json")),
                serde_json::to_vec(&record).unwrap(),
            )
            .unwrap();
            if staged {
                state.stages.insert(
                    id.clone(),
                    Stage {
                        id: id.clone(),
                        session_id: id.clone(),
                        volume_id: None,
                        rootfs: false,
                        profile: "python".into(),
                        uid: 1000,
                        gid: 1000,
                    },
                );
            }
            state.records.insert(id.clone(), record);
            ids.push(id);
        }
        let store = Store {
            root,
            state: Mutex::new(state),
            limit: 8,
        };
        store.expire_results(Duration::from_secs(1));
        assert_eq!(store.state.lock().unwrap().records.len(), 4);
        store.state.lock().unwrap().fenced = false;
        store.expire_results(Duration::from_secs(1));
        assert!(matches!(store.get(&ids[0]), Err((404, "UPLOAD_NOT_FOUND"))));
        assert!(!store.record_path(&ids[0]).exists());
        for id in &ids[1..] {
            assert!(store.get(id).is_ok());
            assert!(store.record_path(id).is_file());
        }
    }
}
