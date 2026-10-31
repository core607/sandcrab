//! Durable volume metadata is outside the bounded XFS data filesystem. Data exhaustion
//! must not prevent recording deletion or recovery. Published data is never startup garbage.
use crate::config::{Profile, Storage, invalid, name};
use rustix::fs::{Gid, OFlags, Uid, chown};
use sandcrab_core::install;
use sandcrab_core::{
    fs::{normal, protected_directory, protected_file},
    unit::checked,
    uuid,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

pub type Result<T> = std::result::Result<T, Fault>;
pub struct Fault {
    pub status: u16,
    pub code: &'static str,
}
pub fn fault(status: u16, code: &'static str) -> Fault {
    Fault { status, code }
}
impl From<io::Error> for Fault {
    fn from(_: io::Error) -> Self {
        fault(503, "STORAGE_UNAVAILABLE")
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Plan {
    pub id: String,
    pub profile: String,
    pub clone_from: Option<String>,
    pub byte_limit: Option<u64>,
    pub inode_limit: Option<u64>,
}
impl Plan {
    fn digest(&self) -> String {
        format!("{:x}", Sha256::digest(serde_json::to_vec(self).unwrap()))
    }
    fn valid(&self) -> bool {
        uuid(&self.id)
            && name(&self.profile)
            && self
                .clone_from
                .as_ref()
                .is_none_or(|id| uuid(id) && id != &self.id)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Record {
    pub plan: Plan,
    pub plan_digest: String,
    pub state: String,
    pub action: String,
    pub code: Option<String>,
    pub bytes: u64,
    pub inodes: u64,
    pub uid: u32,
    pub gid: u32,
    pub project: Option<u64>,
    pub operation: String,
}
impl Record {
    fn valid(&self) -> bool {
        self.plan.valid()
            && self.plan_digest == self.plan.digest()
            && uuid(&self.operation)
            && (1_048_576..=1 << 50).contains(&self.bytes)
            && self.bytes.is_multiple_of(1024)
            && (32..=1_000_000).contains(&self.inodes)
            && self.uid != 0
            && ["create", "delete"].contains(&self.action.as_str())
            && self.plan.byte_limit.is_none_or(|n| n == self.bytes)
            && self.plan.inode_limit.is_none_or(|n| n == self.inodes)
            && self.code.as_ref().is_none_or(|code| {
                code.len() <= 64 && code.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
            })
            && self.project.is_none_or(|p| (1..=4096).contains(&p))
            && [
                "creating", "ready", "deleting", "deleted", "failed", "closing",
            ]
            .contains(&self.state.as_str())
            && (self.state != "ready" || self.project.is_some())
    }
    fn occupies_volume(&self) -> bool {
        !["deleted", "failed"].contains(&self.state.as_str())
    }
    fn value(&self, binding: Option<&Binding>) -> Value {
        json!({"id":self.plan.id,"profile":self.plan.profile,"state":self.state,"code":self.code,
            "byteLimit":self.bytes,"inodeLimit":self.inodes,"cloneFrom":self.plan.clone_from,
            "planDigest":self.plan_digest,"busy":binding.is_some(),
            "attachedTo":binding.and_then(|b| if let Binding::Session(id) = b { Some(id) } else { None })})
    }
}

#[derive(Clone, PartialEq, Eq)]
enum Binding {
    Session(String),
    Clone(String),
}
struct State {
    records: BTreeMap<String, Record>,
    bindings: BTreeMap<String, Binding>,
    active: Option<String>,
    working: bool,
    fenced: bool,
}
impl State {
    fn value(&self, record: &Record) -> Value {
        let mut value = record.value(self.bindings.get(&record.plan.id));
        if self.fenced && self.active.as_ref() == Some(&record.plan.id) {
            value["state"] = "closing".into();
            value["code"] = "STORAGE_UNCERTAIN".into();
        }
        value
    }
}
pub struct Store {
    pub config: Storage,
    state: Mutex<State>,
    _lock: File,
}

fn call(args: &[String]) -> io::Result<std::process::Output> {
    checked(args, Duration::from_secs(15))
}
fn sync(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}
fn directory(path: &Path, mode: u32) -> io::Result<()> {
    match DirBuilder::new().mode(mode).create(path) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
        _ => (),
    }
    protected_directory(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}
pub(crate) fn write(path: &Path, value: &impl Serialize) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("Metadata needs a parent"))?;
    let temporary = parent.join(format!(".write-{}", sandcrab_core::new_uuid()?));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec(value)?)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    sync(parent)
}

pub fn verify_pool(config: &Storage) -> io::Result<()> {
    protected_directory(&config.root)?;
    let data = config.root.join("data");
    protected_directory(&data)?;
    for path in data.ancestors() {
        if fs::metadata(path)?.mode() & 0o001 == 0 {
            return Err(invalid(
                "Volume mount ancestors must be searchable by execution accounts",
            ));
        }
    }
    let output = call(&[
        "findmnt".into(),
        "-J".into(),
        "-T".into(),
        data.to_string_lossy().into(),
        "-o".into(),
        "TARGET,FSTYPE,OPTIONS".into(),
    ])?;
    let value =
        sandcrab_core::parse(&output.stdout).map_err(|_| invalid("Invalid mount description"))?;
    let mount = &value["filesystems"][0];
    let options = mount["options"]
        .as_str()
        .unwrap_or("")
        .split(',')
        .collect::<Vec<_>>();
    if mount["target"] != data.to_string_lossy().as_ref()
        || mount["fstype"] != "xfs"
        || !(options.contains(&"prjquota") || options.contains(&"pquota"))
        || options.contains(&"pqnoenforce")
        || !options.contains(&"nosuid")
        || !options.contains(&"nodev")
    {
        return Err(invalid(
            "storage.root/data needs a dedicated XFS mount with enforced project quotas, nosuid and nodev",
        ));
    }
    let stat = rustix::fs::statvfs(&data)?;
    if stat
        .f_blocks
        .checked_mul(stat.f_frsize)
        .is_none_or(|bytes| bytes > config.pool_bytes)
        || fs::metadata(&config.root)?.dev() == fs::metadata(&data)?.dev()
    {
        return Err(invalid(
            "Volume data must be bounded and separate from its control metadata filesystem",
        ));
    }
    let features = call(&[
        "/usr/sbin/xfs_spaceman".into(),
        "-c".into(),
        "info".into(),
        data.to_string_lossy().into(),
    ])?;
    if !String::from_utf8_lossy(&features.stdout).contains("reflink=1") {
        return Err(invalid("The volume filesystem must support reflinks"));
    }
    Ok(())
}

impl Store {
    pub fn open(config: Storage, owner: Value) -> io::Result<Arc<Self>> {
        verify_pool(&config)?;
        let state_dir = config.root.join("state");
        directory(&state_dir, 0o700)?;
        if fs::metadata(&state_dir)?.dev() == fs::metadata(config.root.join("data"))?.dev() {
            return Err(invalid("Volume metadata cannot be on the data filesystem"));
        }
        let lock = install::runtime_lock(&state_dir)?;
        let owner_path = state_dir.join("owner.json");
        match protected_file(&owner_path, 4096) {
            Ok(bytes) if sandcrab_core::parse(&bytes).ok() == Some(owner.clone()) => (),
            Ok(_) => {
                return Err(invalid(
                    "Volume store belongs to another runtime namespace; preserve it and restore the matching configuration",
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if fs::read_dir(config.root.join("data"))?.next().is_some() {
                    return Err(invalid(
                        "Refusing to initialize a nonempty unowned volume store",
                    ));
                }
                for entry in fs::read_dir(&state_dir)? {
                    if entry?.file_name() != ".supervisor.lock" {
                        return Err(invalid(
                            "Refusing to initialize a nonempty unowned volume store",
                        ));
                    }
                }
                write(&owner_path, &owner)?;
            }
            Err(e) => return Err(e),
        }
        directory(&config.root.join("data/volumes"), 0o711)?;
        directory(&state_dir.join("records"), 0o700)?;
        let mut records = BTreeMap::new();
        for entry in fs::read_dir(state_dir.join("records"))? {
            let entry = entry?;
            let filename = entry.file_name().to_string_lossy().into_owned();
            if filename.strip_prefix(".write-").is_some_and(uuid) {
                continue;
            }
            let id = filename
                .strip_suffix(".json")
                .filter(|id| uuid(id))
                .ok_or_else(|| invalid("Unexpected volume record"))?;
            let raw = protected_file(&entry.path(), 65536)?;
            let value = sandcrab_core::parse(&raw).map_err(|_| invalid("Invalid volume record"))?;
            let record: Record = serde_json::from_value(value)?;
            if !record.valid() || record.plan.id != id || records.len() >= config.max_records {
                return Err(invalid(
                    "Volume record identity, limits or count are invalid",
                ));
            }
            records.insert(id.to_owned(), record);
        }
        Ok(Arc::new(Self {
            config,
            state: Mutex::new(State {
                records,
                bindings: BTreeMap::new(),
                active: None,
                working: false,
                fenced: false,
            }),
            _lock: lock,
        }))
    }
    fn metadata(&self, id: &str) -> PathBuf {
        self.config
            .root
            .join("state/records")
            .join(format!("{id}.json"))
    }
    pub fn directory(&self, id: &str) -> PathBuf {
        self.config.root.join("data/volumes").join(id)
    }
    pub fn data(&self, id: &str) -> PathBuf {
        self.directory(id).join("data")
    }
    fn publish(&self, state: &mut State, record: Record) -> Result<()> {
        if write(&self.metadata(&record.plan.id), &record).is_err() {
            state.fenced = true;
            return Err(fault(503, "STORAGE_UNCERTAIN"));
        }
        state.records.insert(record.plan.id.clone(), record);
        Ok(())
    }
    fn usable(state: &State) -> Result<()> {
        if state.fenced {
            Err(fault(503, "STORAGE_UNCERTAIN"))
        } else {
            Ok(())
        }
    }
    pub fn get(&self, id: &str) -> Result<Value> {
        let state = self.state.lock().unwrap();
        let record = state
            .records
            .get(id)
            .ok_or_else(|| fault(404, "VOLUME_NOT_FOUND"))?;
        Ok(state.value(record))
    }
    pub fn list(&self, after: &str) -> Value {
        let state = self.state.lock().unwrap();
        let mut rows = state.records.range((
            std::ops::Bound::Excluded(after.to_string()),
            std::ops::Bound::Unbounded,
        ));
        let page: Vec<_> = rows
            .by_ref()
            .take(100)
            .map(|(_, r)| state.value(r))
            .collect();
        let next = rows
            .next()
            .and_then(|_| page.last().map(|v| v["id"].clone()));
        json!({"volumes":page,"nextAfter":next})
    }
    pub fn begin_create(
        &self,
        plan: Plan,
        profile: Option<&Profile>,
        current_epoch: bool,
        stopped: &AtomicBool,
    ) -> Result<(Value, bool)> {
        if !plan.valid() {
            return Err(fault(400, "INVALID_REQUEST"));
        }
        let mut state = self.state.lock().unwrap();
        if stopped.load(Ordering::SeqCst) {
            return Err(fault(503, "STOPPING"));
        }
        Self::usable(&state)?;
        if let Some(record) = state.records.get(&plan.id) {
            return if record.plan == plan {
                Ok((record.value(state.bindings.get(&plan.id)), false))
            } else {
                Err(fault(409, "ID_CONFLICT"))
            };
        }
        if !current_epoch {
            return Err(fault(409, "SERVER_CHANGED"));
        }
        let profile = profile
            .filter(|p| p.uid != 0)
            .ok_or_else(|| fault(400, "PROFILE_NOT_FOUND"))?;
        if state.active.is_some() {
            return Err(fault(429, "STORAGE_CAPACITY"));
        }
        if state.records.len() >= self.config.max_records {
            return Err(fault(429, "VOLUME_RECORD_CAPACITY"));
        }
        if state
            .records
            .values()
            .filter(|r| r.occupies_volume())
            .count()
            >= self.config.max_volumes
        {
            return Err(fault(429, "VOLUME_CAPACITY"));
        }
        let bytes = plan.byte_limit.unwrap_or(self.config.max_volume_bytes);
        let inodes = plan.inode_limit.unwrap_or(self.config.max_volume_inodes);
        if !(1_048_576..=self.config.max_volume_bytes).contains(&bytes)
            || !bytes.is_multiple_of(1024)
            || !(32..=self.config.max_volume_inodes).contains(&inodes)
        {
            return Err(fault(400, "VOLUME_LIMIT"));
        }
        match fs::symlink_metadata(self.directory(&plan.id)) {
            Ok(_) => return Err(fault(503, "STORAGE_INCONSISTENT")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        if let Some(source) = &plan.clone_from {
            let record = state
                .records
                .get(source)
                .ok_or_else(|| fault(404, "VOLUME_NOT_FOUND"))?;
            if record.state != "ready" {
                return Err(fault(409, "VOLUME_NOT_READY"));
            }
            if record.uid != profile.uid || record.gid != profile.gid {
                return Err(fault(409, "VOLUME_PROFILE_MISMATCH"));
            }
            if state.bindings.contains_key(source) {
                return Err(fault(409, "VOLUME_IN_USE"));
            }
        }
        let record = Record {
            plan_digest: plan.digest(),
            plan,
            state: "creating".into(),
            action: "create".into(),
            code: None,
            bytes,
            inodes,
            uid: profile.uid,
            gid: profile.gid,
            project: None,
            operation: sandcrab_core::new_uuid()?,
        };
        self.publish(&mut state, record.clone())?;
        if let Some(source) = &record.plan.clone_from {
            state
                .bindings
                .insert(source.clone(), Binding::Clone(record.plan.id.clone()));
        }
        state.active = Some(record.plan.id.clone());
        state.working = true;
        Ok((record.value(None), true))
    }
    pub fn begin_delete(&self, id: &str, stopped: &AtomicBool) -> Result<(Value, bool)> {
        let mut state = self.state.lock().unwrap();
        Self::usable(&state)?;
        if stopped.load(Ordering::SeqCst) {
            return Err(fault(503, "STOPPING"));
        }
        let mut record = state
            .records
            .get(id)
            .cloned()
            .ok_or_else(|| fault(404, "VOLUME_NOT_FOUND"))?;
        if ["deleted", "deleting"].contains(&record.state.as_str()) {
            return Ok((record.value(None), false));
        }
        if record.state != "ready" {
            return Err(fault(409, "VOLUME_NOT_READY"));
        }
        if state.bindings.contains_key(id) {
            return Err(fault(409, "VOLUME_IN_USE"));
        }
        if state.active.is_some() {
            return Err(fault(429, "STORAGE_CAPACITY"));
        }
        record.state = "deleting".into();
        record.action = "delete".into();
        self.publish(&mut state, record.clone())?;
        state.active = Some(id.into());
        state.working = true;
        Ok((record.value(None), true))
    }
    pub fn forget(&self, id: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        Self::usable(&state)?;
        let record = state
            .records
            .get(id)
            .ok_or_else(|| fault(404, "VOLUME_NOT_FOUND"))?;
        if !["deleted", "failed"].contains(&record.state.as_str()) {
            return Err(fault(409, "VOLUME_ACTIVE"));
        }
        match fs::symlink_metadata(self.directory(id)) {
            Ok(_) => return Err(fault(503, "STORAGE_INCONSISTENT")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        if fs::remove_file(self.metadata(id))
            .and_then(|()| sync(&self.config.root.join("state/records")))
            .is_err()
        {
            state.fenced = true;
            return Err(fault(503, "STORAGE_UNCERTAIN"));
        }
        state.records.remove(id);
        Ok(())
    }
    pub fn record(&self, id: &str) -> Record {
        self.state.lock().unwrap().records[id].clone()
    }
    pub fn finish(&self, id: &str, status: &str, code: Option<&str>, contained: bool) {
        let mut state = self.state.lock().unwrap();
        let mut record = state.records[id].clone();
        record.state = if contained {
            status.into()
        } else {
            "closing".into()
        };
        record.code = code.map(str::to_owned);
        let published = self.publish(&mut state, record.clone()).is_ok();
        state.working = false;
        if contained && published {
            if let Some(source) = &record.plan.clone_from
                && state.bindings.get(source) == Some(&Binding::Clone(id.into()))
            {
                state.bindings.remove(source);
            }
            state.active = None;
        } else {
            state.fenced = true;
        }
    }
    pub fn finished(&self) -> bool {
        !self.state.lock().unwrap().working
    }
    pub fn available(&self) -> bool {
        !self.state.lock().unwrap().fenced
    }
    pub fn quiescent(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.active.is_none() && !state.fenced
    }

    pub fn bind(
        self: &Arc<Self>,
        id: &str,
        session: &str,
        profile: &Profile,
    ) -> Result<Attachment> {
        let mut state = self.state.lock().unwrap();
        Self::usable(&state)?;
        let record = state
            .records
            .get(id)
            .ok_or_else(|| fault(404, "VOLUME_NOT_FOUND"))?;
        if record.state != "ready" {
            return Err(fault(409, "VOLUME_NOT_READY"));
        }
        if record.uid != profile.uid || record.gid != profile.gid {
            return Err(fault(409, "VOLUME_PROFILE_MISMATCH"));
        }
        if record.bytes > self.config.max_volume_bytes
            || record.inodes > self.config.max_volume_inodes
        {
            return Err(fault(409, "VOLUME_LIMIT"));
        }
        if state.bindings.contains_key(id) {
            return Err(fault(409, "VOLUME_IN_USE"));
        }
        let record = record.clone();
        let binding = Binding::Session(session.into());
        state.bindings.insert(id.into(), binding.clone());
        let attachment = Attachment {
            store: self.clone(),
            id: id.into(),
            binding,
            release_on_drop: true,
        };
        drop(state);
        self.verify_record(&record)?;
        Ok(attachment)
    }
    pub fn verify_record(&self, record: &Record) -> io::Result<()> {
        verify_pool(&self.config)?;
        let path = self.directory(&record.plan.id);
        protected_directory(&path)?;
        self.verify_owner(record)?;
        no_mounts_below(&path, false)?;
        let data_path = self.data(&record.plan.id);
        let data = fs::symlink_metadata(&data_path)?;
        if !data.is_dir()
            || data.uid() != record.uid
            || data.gid() != record.gid
            || data.dev() != fs::metadata(self.config.root.join("data"))?.dev()
        {
            return Err(invalid("Volume data ownership or filesystem changed"));
        }
        for path in [&path, &data_path] {
            let attributes = call(&[
                "/usr/sbin/xfs_io".into(),
                "-r".into(),
                "-c".into(),
                "stat".into(),
                path.to_string_lossy().into(),
            ])?;
            let text = String::from_utf8_lossy(&attributes.stdout);
            let attribute = |key: &str| {
                text.lines()
                    .find_map(|line| line.trim().strip_prefix(key)?.strip_prefix(" = "))
            };
            let project = attribute("fsxattr.projid").and_then(|v| v.parse::<u64>().ok());
            let flags = attribute("fsxattr.xflags")
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.strip_prefix("0x"))
                .and_then(|v| u64::from_str_radix(v, 16).ok());
            if project != record.project || !flags.is_some_and(|v| v & 0x200 != 0) {
                return Err(invalid("Volume quota identity or inheritance changed"));
            }
        }
        for (kind, limit) in [("b", record.bytes / 1024), ("i", record.inodes)] {
            let output = call(&[
                "/usr/sbin/xfs_quota".into(),
                "-x".into(),
                "-c".into(),
                format!(
                    "quota -p -{kind} -N -v {}",
                    record
                        .project
                        .ok_or_else(|| invalid("Missing quota identity"))?
                ),
                self.config.root.join("data").to_string_lossy().into(),
            ])?;
            let text = String::from_utf8_lossy(&output.stdout);
            let rows: Vec<_> = text
                .lines()
                .filter(|line| !line.trim().is_empty())
                .collect();
            let fields: Vec<_> = rows.first().map_or("", |s| *s).split_whitespace().collect();
            if rows.len() != 1
                || fields.get(2).and_then(|s| s.parse::<u64>().ok()) != Some(limit)
                || fields.get(3).and_then(|s| s.parse::<u64>().ok()) != Some(limit)
            {
                return Err(invalid(
                    "Volume quota limits changed or could not be verified",
                ));
            }
        }
        Ok(())
    }
    fn verify_owner(&self, record: &Record) -> io::Result<()> {
        let bytes = protected_file(&self.directory(&record.plan.id).join("owner.json"), 4096)?;
        if sandcrab_core::parse(&bytes).ok()
            != Some(json!({"operation":record.operation,"planDigest":record.plan_digest}))
        {
            return Err(invalid("Volume directory ownership changed"));
        }
        Ok(())
    }
    pub fn prepare(&self, id: &str) -> io::Result<Record> {
        verify_pool(&self.config)?;
        let mut state = self.state.lock().unwrap();
        // Retained records reserve quota identities even after deletion. Forgetting is
        // allowed only after their data is absent, so the bounded slots can then be reused.
        let project = (1..=4096)
            .find(|p| !state.records.values().any(|r| r.project == Some(*p)))
            .ok_or_else(|| invalid("No volume quota identity available"))?;
        let mut record = state.records[id].clone();
        record.project = Some(project);
        self.publish(&mut state, record.clone())
            .map_err(|_| invalid("Volume metadata unavailable"))?;
        drop(state);
        let path = self.directory(id);
        DirBuilder::new().mode(0o750).create(&path)?;
        write(
            &path.join("owner.json"),
            &json!({"operation":record.operation,"planDigest":record.plan_digest}),
        )?;
        call(&[
            "/usr/sbin/xfs_quota".into(),
            "-x".into(),
            "-c".into(),
            format!("project -s -p {} {project}", path.display()),
            self.config.root.join("data").to_string_lossy().into(),
        ])?;
        call(&[
            "/usr/sbin/xfs_quota".into(),
            "-x".into(),
            "-c".into(),
            format!(
                "limit -p bsoft={}k bhard={}k isoft={} ihard={} {project}",
                record.bytes / 1024,
                record.bytes / 1024,
                record.inodes,
                record.inodes
            ),
            self.config.root.join("data").to_string_lossy().into(),
        ])?;
        chown(&path, Some(Uid::ROOT), Some(Gid::from_raw(record.gid)))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o750))?;
        let data = self.data(id);
        DirBuilder::new().mode(0o750).create(&data)?;
        chown(
            &data,
            Some(Uid::from_raw(record.uid)),
            Some(Gid::from_raw(record.gid)),
        )?;
        fs::set_permissions(&data, fs::Permissions::from_mode(0o750))?;
        sync(&data)?;
        sync(&path)?;
        sync(&self.config.root.join("data/volumes"))?;
        rustix::fs::syncfs(File::open(self.config.root.join("data"))?)?;
        self.verify_record(&record)?;
        Ok(record)
    }
    pub fn remove_data(&self, id: &str) -> io::Result<()> {
        let path = self.directory(id);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
            Ok(_) => (),
        }
        protected_directory(&path)?;
        no_mounts_below(&path, false)?;
        match self.verify_owner(&self.record(id)) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // A crash before the ownership marker may leave only an empty directory.
                // Never recursively remove unexpected data without its durable marker.
                for entry in fs::read_dir(&path)? {
                    let entry = entry?;
                    if !entry
                        .file_name()
                        .to_str()
                        .and_then(|s| s.strip_prefix(".write-"))
                        .is_some_and(uuid)
                    {
                        return Err(invalid("Unowned volume data is preserved"));
                    }
                    protected_file(&entry.path(), 4096)?;
                    fs::remove_file(entry.path())?;
                }
                fs::remove_dir(&path)?;
                return sync(&self.config.root.join("data/volumes"));
            }
            Err(e) => return Err(e),
        }
        fs::remove_dir_all(&path)?;
        sync(&self.config.root.join("data/volumes"))
    }
    /// Called only after the runtime has stopped every unit in its bound namespace.
    pub fn recover(&self) -> io::Result<()> {
        let records: Vec<_> = self
            .state
            .lock()
            .unwrap()
            .records
            .values()
            .cloned()
            .collect();
        for mut record in records {
            if ["creating", "deleting", "closing"].contains(&record.state.as_str()) {
                self.remove_data(&record.plan.id)?;
                record.state = if record.action == "delete" {
                    "deleted".into()
                } else {
                    "failed".into()
                };
                record.code = Some("INTERRUPTED".into());
                let mut state = self.state.lock().unwrap();
                self.publish(&mut state, record)
                    .map_err(|_| invalid("Volume recovery could not commit"))?;
            } else if record.state == "ready" {
                self.verify_record(&record)?;
            }
        }
        for entry in fs::read_dir(self.config.root.join("data/volumes"))? {
            let entry = entry?;
            let id = entry.file_name().to_string_lossy().into_owned();
            if !uuid(&id)
                || !self
                    .state
                    .lock()
                    .unwrap()
                    .records
                    .get(&id)
                    .is_some_and(|r| r.state == "ready")
            {
                return Err(invalid(
                    "Unowned volume data is preserved; operator reconciliation required",
                ));
            }
        }
        for parent in [
            self.config.root.join("state"),
            self.config.root.join("state/records"),
        ] {
            for entry in fs::read_dir(&parent)? {
                let entry = entry?;
                if entry
                    .file_name()
                    .to_str()
                    .and_then(|s| s.strip_prefix(".write-"))
                    .is_some_and(uuid)
                {
                    protected_file(&entry.path(), 65536)?;
                    fs::remove_file(entry.path())?;
                }
            }
            sync(&parent)?;
        }
        Ok(())
    }
}

/// Fixed root helper invoked only inside the daemon's bounded copy unit.
pub fn copy_tree(source: &Path, destination: &Path, pool: &Path) -> io::Result<()> {
    if rustix::process::geteuid() != Uid::ROOT || !normal(pool) || source == destination {
        return Err(invalid("Invalid volume copy authority"));
    }
    protected_directory(pool)?;
    for path in [source, destination] {
        let parent = path
            .parent()
            .ok_or_else(|| invalid("Missing volume parent"))?;
        if !normal(path)
            || path.file_name().is_none_or(|n| n != "data")
            || parent.parent() != Some(pool.join("volumes").as_path())
            || !parent
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(uuid)
        {
            return Err(invalid(
                "Copy paths must be managed volume data directories",
            ));
        }
        protected_directory(parent)?;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.dev() != fs::metadata(pool)?.dev() {
            return Err(invalid("Volume copy filesystem changed"));
        }
        no_mounts_below(path, true)?;
    }
    if fs::read_dir(destination)?.next().is_some() {
        return Err(invalid("Clone destination is not empty"));
    }
    let status = std::process::Command::new("/usr/bin/cp")
        .args(["--archive", "--reflink=always", "--"])
        .arg(format!("{}/.", source.display()))
        .arg(destination)
        .status()?;
    if !status.success() {
        return Err(invalid("Volume reflink failed"));
    }
    let fd = rustix::fs::open(
        pool,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    rustix::fs::syncfs(fd)?;
    Ok(())
}

pub fn no_mounts_below(path: &Path, allow_root: bool) -> io::Result<()> {
    let prefix = format!("{}/", path.display());
    for line in fs::read_to_string("/proc/self/mountinfo")?.lines() {
        let target = line.split_whitespace().nth(4).unwrap_or("");
        if target.starts_with(&prefix) || (!allow_root && target == path.to_string_lossy()) {
            return Err(invalid("Unexpected mount within volume data"));
        }
    }
    Ok(())
}

pub struct Attachment {
    store: Arc<Store>,
    id: String,
    binding: Binding,
    release_on_drop: bool,
}
impl Attachment {
    pub fn path(&self) -> PathBuf {
        self.store.data(&self.id)
    }
    /// After launch, dropping a failed owner must not make its volume available elsewhere.
    pub fn launched(&mut self) {
        self.release_on_drop = false;
    }
    pub fn release(mut self) {
        self.release_on_drop = true;
    }
}
impl Drop for Attachment {
    fn drop(&mut self) {
        if self.release_on_drop {
            let mut state = self.store.state.lock().unwrap();
            if state.bindings.get(&self.id) == Some(&self.binding) {
                state.bindings.remove(&self.id);
            }
        }
    }
}
