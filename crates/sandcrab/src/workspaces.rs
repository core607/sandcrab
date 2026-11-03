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
    overlays: PathBuf,
    owner: Value,
}

/// Dropping this value deliberately preserves its data. Failed containment must
/// retain it for namespace-validated recovery, not trigger filesystem cleanup.
pub struct Workspace {
    store: Arc<Store>,
    id: String,
    pub usage: Arc<Account>,
    overlay: Option<crate::overlay::Mount>,
    template: Option<crate::templates::Lease>,
}

impl Store {
    /// Exercise the configured backing filesystem before publishing an epoch.
    /// This uses the same fixed helper and mount handoff as a template session.
    pub fn probe_overlay(
        self: &Arc<Self>,
        profile: &Profile,
        helper: &crate::helper::Context<'_>,
    ) -> io::Result<()> {
        let release = fs::read_to_string("/proc/sys/kernel/osrelease")?;
        let version = release
            .trim()
            .split('.')
            .take(2)
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid("Overlay requires Linux 5.11 or newer"))?;
        if version.len() != 2 || (version[0], version[1]) < (5, 11) {
            return Err(invalid("Overlay requires Linux 5.11 or newer"));
        }
        let id = sandcrab_core::new_uuid()?;
        let cancelled = AtomicBool::new(false);
        let mut workspace = self
            .create(&id, profile, &cancelled)
            .map_err(|error| error.error)?;
        let mutable = self.overlays.join(&id);
        let result = (|| -> Result<(), SetupError> {
            DirBuilder::new().mode(0o700).create(&mutable)?;
            for name in ["upper", "work", "lower"] {
                DirBuilder::new().mode(0o711).create(mutable.join(name))?;
            }
            DirBuilder::new()
                .mode(0o750)
                .create(mutable.join("lower/data"))?;
            chown(
                mutable.join("lower/data"),
                Some(Uid::from_raw(profile.uid)),
                Some(Gid::from_raw(profile.gid)),
            )
            .map_err(io::Error::from)?;
            workspace.overlay = Some(crate::overlay::create(
                helper,
                profile,
                &cancelled,
                crate::overlay::Spec {
                    lower: mutable.join("lower"),
                    upper: mutable.join("upper"),
                    work: mutable.join("work"),
                },
                &self.directory(&id)?,
            )?);
            fs::write(workspace.path().join("copy-up"), b"overlay-probe")?;
            if mutable.join("lower/data/copy-up").try_exists()?
                || !mutable.join("upper/data/copy-up").is_file()
            {
                return Err(invalid("Overlay copy-up did not preserve the lower tree").into());
            }
            Ok(())
        })();
        if result.as_ref().is_err_and(|error| !error.contained) {
            return Err(result.err().unwrap().error);
        }
        workspace.remove()?;
        result.map_err(|error| {
            invalid(format!(
                "Overlay startup check failed; verify required kernel syscalls and an overlay-capable runtime filesystem such as ext4 or XFS: {}",
                error.error
            ))
        })
    }

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
        let overlays = runtime.join("workspace-overlays");
        match DirBuilder::new().mode(0o700).create(&overlays) {
            Err(error) if error.kind() != io::ErrorKind::AlreadyExists => return Err(error),
            _ => (),
        }
        protected_directory(&overlays)?;
        match protected_file(&overlays.join("owner.json"), 4096) {
            Ok(bytes) if sandcrab_core::parse(&bytes).ok() == Some(owner.clone()) => (),
            Ok(_) => {
                return Err(invalid(
                    "Overlay workspaces belong to another runtime namespace",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if fs::read_dir(&overlays)?.next().is_some() {
                    return Err(invalid("Refusing unowned overlay workspaces"));
                }
                crate::storage::write(&overlays.join("owner.json"), &owner)?;
            }
            Err(error) => return Err(error),
        }
        Ok(Arc::new(Self {
            root,
            overlays,
            owner,
        }))
    }

    fn verify(&self) -> io::Result<()> {
        protected_directory(&self.root)?;
        protected_directory(&self.overlays)?;
        let bytes = protected_file(&self.root.join("owner.json"), 4096)?;
        if sandcrab_core::parse(&bytes).ok().as_ref() != Some(&self.owner) {
            return Err(invalid("Disk workspace ownership changed"));
        }
        if sandcrab_core::parse(&protected_file(&self.overlays.join("owner.json"), 4096)?)
            .ok()
            .as_ref()
            != Some(&self.owner)
        {
            return Err(invalid("Overlay workspace ownership changed"));
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
        let mut overlays = Vec::new();
        for entry in fs::read_dir(&self.overlays)? {
            let entry = entry?;
            if entry.file_name() == "owner.json" {
                continue;
            }
            let id = entry
                .file_name()
                .into_string()
                .map_err(|_| invalid("Invalid overlay workspace entry"))?;
            if !sandcrab_core::uuid(&id) {
                return Err(invalid("Invalid overlay workspace entry"));
            }
            protected_directory(&entry.path())?;
            crate::storage::no_mounts_below(&entry.path(), false)?;
            overlays.push(entry.path());
        }
        for id in ids {
            self.remove(&id)?;
        }
        for path in overlays {
            fs::remove_dir_all(path)?;
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
                overlay: None,
                template: None,
            })
        })();
        result.map_err(|error| SetupError {
            error,
            contained: self.remove(id).is_ok(),
        })
    }

    pub fn create_template(
        self: &Arc<Self>,
        id: &str,
        profile: &Profile,
        cancelled: &AtomicBool,
        template: crate::templates::Lease,
        helper: &crate::helper::Context<'_>,
    ) -> Result<Workspace, SetupError> {
        let mut workspace = self.create(id, profile, cancelled)?;
        let mutable = self.overlays.join(id);
        let result = (|| -> Result<(), SetupError> {
            DirBuilder::new().mode(0o700).create(&mutable)?;
            for name in ["upper", "work"] {
                DirBuilder::new().mode(0o711).create(mutable.join(name))?;
            }
            template.start();
            workspace.overlay = Some(crate::overlay::create(
                helper,
                profile,
                cancelled,
                crate::overlay::Spec {
                    lower: template.lower(),
                    upper: mutable.join("upper"),
                    work: mutable.join("work"),
                },
                &self.directory(id)?,
            )?);
            workspace.usage = Arc::new(Account::new(
                mutable.clone(),
                Usage {
                    bytes: profile.temporary_bytes,
                    inodes: profile.temporary_inodes,
                },
            ));
            workspace.usage.refresh(true, cancelled);
            workspace.usage.allow_growth().map_err(invalid)?;
            Ok(())
        })();
        workspace.template = Some(template);
        match result {
            Ok(()) => Ok(workspace),
            Err(error) => Err(SetupError {
                error: error.error,
                contained: error.contained && workspace.remove().is_ok(),
            }),
        }
    }
}

impl Workspace {
    pub fn path(&self) -> PathBuf {
        self.store.root.join(&self.id).join("data")
    }

    pub fn remove(&self) -> io::Result<()> {
        if let Some(overlay) = &self.overlay {
            overlay.release()?;
        }
        self.store.remove(&self.id)?;
        let mutable = self.store.overlays.join(&self.id);
        if mutable.try_exists()? {
            protected_directory(&mutable)?;
            crate::storage::no_mounts_below(&mutable, false)?;
            fs::remove_dir_all(mutable)?;
        }
        if let Some(template) = &self.template {
            template.release();
        }
        Ok(())
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
