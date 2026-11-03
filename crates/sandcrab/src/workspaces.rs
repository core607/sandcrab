//! Disposable disk data belongs to a runtime namespace and one parent session.
//! Removal requires caller-confirmed launcher, descendant and file-helper containment.
use crate::{
    config::{Profile, invalid},
    runtime::SetupError,
    usage::{Account, Usage},
};
use rustix::fs::{Gid, Uid, chown};
use sandcrab_core::fs::{protected_directory, protected_file};
use serde_json::Value;
use std::{
    fs::{self, DirBuilder},
    io,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
};

pub struct Store {
    root: PathBuf,
    owner: Value,
}

/// Dropping this value deliberately preserves its data. Failed containment must
/// retain it for namespace-validated recovery, not trigger filesystem cleanup.
pub struct Workspace {
    store: Arc<Store>,
    id: String,
    pub usage: Arc<Account>,
}

impl Store {
    pub fn open(runtime: &Path, owner: Value) -> io::Result<Arc<Self>> {
        let root = runtime.join("workspaces");
        match DirBuilder::new().mode(0o700).create(&root) {
            Err(error) if error.kind() != io::ErrorKind::AlreadyExists => return Err(error),
            _ => (),
        }
        protected_directory(&root)?;
        let marker = root.join("owner.json");
        match protected_file(&marker, 4096) {
            Ok(bytes) if sandcrab_core::parse(&bytes).ok() == Some(owner.clone()) => (),
            Ok(_) => {
                return Err(invalid(
                    "Disk workspaces belong to another runtime namespace",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if fs::read_dir(&root)?.next().is_some() {
                    return Err(invalid(
                        "Refusing to adopt nonempty unowned disk workspaces",
                    ));
                }
                crate::storage::write(&marker, &owner)?;
            }
            Err(error) => return Err(error),
        }
        fs::set_permissions(&root, fs::Permissions::from_mode(0o711))?;
        Ok(Arc::new(Self { root, owner }))
    }

    fn verify(&self) -> io::Result<()> {
        protected_directory(&self.root)?;
        let bytes = protected_file(&self.root.join("owner.json"), 4096)?;
        if sandcrab_core::parse(&bytes).ok().as_ref() != Some(&self.owner) {
            return Err(invalid("Disk workspace ownership changed"));
        }
        Ok(())
    }

    fn directory(&self, id: &str) -> io::Result<PathBuf> {
        if !sandcrab_core::uuid(id) {
            return Err(invalid("Invalid disk workspace identity"));
        }
        Ok(self.root.join(id))
    }

    fn remove(&self, id: &str) -> io::Result<()> {
        self.verify()?;
        let root = self.directory(id)?;
        protected_directory(&root)?;
        crate::storage::no_mounts_below(&root, false)?;
        fs::remove_dir_all(root)
    }

    /// Validate every entry before removing any data; unknown names or mounts
    /// cannot turn partial recovery into silent adoption or deletion.
    pub fn recover(&self) -> io::Result<()> {
        self.verify()?;
        let mut ids = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if entry.file_name() == "owner.json" {
                continue;
            }
            let id = entry
                .file_name()
                .into_string()
                .map_err(|_| invalid("Invalid workspace entry"))?;
            let root = self.directory(&id)?;
            protected_directory(&root)?;
            crate::storage::no_mounts_below(&root, false)?;
            ids.push(id);
        }
        for id in ids {
            self.remove(&id)?;
        }
        Ok(())
    }

    pub fn create(
        self: &Arc<Self>,
        id: &str,
        profile: &Profile,
        cancelled: &AtomicBool,
    ) -> Result<Workspace, SetupError> {
        self.verify()?;
        let root = self.directory(id)?;
        DirBuilder::new().mode(0o700).create(&root)?;
        let result = (|| {
            fs::set_permissions(&root, fs::Permissions::from_mode(0o711))?;
            let data = root.join("data");
            DirBuilder::new().mode(0o750).create(&data)?;
            chown(
                &data,
                Some(Uid::from_raw(profile.uid)),
                Some(Gid::from_raw(profile.gid)),
            )?;
            fs::set_permissions(&data, fs::Permissions::from_mode(0o750))?;
            let usage = Arc::new(Account::new(
                root.clone(),
                Usage {
                    bytes: profile.temporary_bytes,
                    inodes: profile.temporary_inodes,
                },
            ));
            usage.refresh(true, cancelled);
            usage.allow_growth().map_err(invalid)?;
            Ok(Workspace {
                store: self.clone(),
                id: id.into(),
                usage,
            })
        })();
        result.map_err(|error| SetupError {
            error,
            contained: self.remove(id).is_ok(),
        })
    }
}

impl Workspace {
    pub fn path(&self) -> PathBuf {
        self.store.root.join(&self.id).join("data")
    }

    pub fn remove(&self) -> io::Result<()> {
        self.store.remove(&self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::symlink;

    #[test]
    fn ownership_and_whole_inventory_validation_precede_disposable_data_removal() {
        let runtime = Path::new("/source").join(format!(
            "sandcrab-workspaces-test-{}",
            sandcrab_core::new_uuid().unwrap()
        ));
        DirBuilder::new().mode(0o755).create(&runtime).unwrap();
        let root = runtime.join("workspaces");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("unowned"), b"preserve").unwrap();
        let owner = json!({"test":sandcrab_core::new_uuid().unwrap()});
        assert!(Store::open(&runtime, owner.clone()).is_err());
        assert_eq!(fs::read(root.join("unowned")).unwrap(), b"preserve");
        fs::remove_file(root.join("unowned")).unwrap();
        let store = Store::open(&runtime, owner.clone()).unwrap();
        let mut config =
            crate::config::Config::parse(include_str!("../config.example.toml")).unwrap();
        let profile = config.profiles.get_mut("python").unwrap();
        profile.uid = 65534;
        profile.gid = 65534;
        let id = sandcrab_core::new_uuid().unwrap();
        let workspace = store
            .create(&id, profile, &AtomicBool::new(false))
            .unwrap_or_else(|e| panic!("{}", e.error));
        let sentinel = runtime.join("sentinel");
        fs::write(&sentinel, b"outside").unwrap();
        symlink(&sentinel, workspace.path().join("link")).unwrap();
        fs::write(workspace.path().join("work"), b"ephemeral").unwrap();
        drop(workspace);
        assert!(root.join(&id).exists());
        assert!(Store::open(&runtime, json!({"wrong":true})).is_err());
        fs::write(root.join("unexpected"), b"preserve").unwrap();
        assert!(store.recover().is_err());
        assert!(root.join(&id).exists());
        fs::remove_file(root.join("unexpected")).unwrap();
        store.recover().unwrap();
        assert!(!root.join(&id).exists());
        assert_eq!(fs::read(&sentinel).unwrap(), b"outside");
        assert_eq!(runtime.parent(), Some(Path::new("/source")));
        fs::remove_dir_all(runtime).unwrap();
    }
}
