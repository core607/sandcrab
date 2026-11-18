//! Private XFS projects for session-owned storage. A lost owner is recovered after containment.
use crate::{
    config::{Profile, invalid},
    runtime::OpenError,
    sessions::Open,
    storage::{Plan, Store},
};
use std::{
    io,
    sync::{Arc, atomic::AtomicBool},
    thread,
    time::{Duration, Instant},
};

pub(crate) struct Temporary {
    store: Arc<Store>,
    pub id: String,
    pub generation: String,
}

impl Temporary {
    pub(crate) fn create(
        store: &Arc<Store>,
        request: &Open,
        profile: &Profile,
        cancelled: &AtomicBool,
    ) -> Result<Self, OpenError> {
        let refused = |code| OpenError {
            code,
            contained: true,
        };
        if !store.quota_enforced() {
            return Err(refused("HARD_QUOTA_UNAVAILABLE"));
        }
        let id = sandcrab_core::new_uuid().map_err(|_| refused("STORAGE_UNAVAILABLE"))?;
        let plan = Plan {
            id: id.clone(),
            profile: request.profile.clone(),
            byte_limit: Some(profile.temporary_bytes),
            inode_limit: Some(profile.temporary_inodes),
            template_id: request.template_id.clone(),
            clone_from: None,
            workspace_key: None,
            temporary: true,
        };
        let deadline = Instant::now() + Duration::from_secs(15);
        let (_, created) = loop {
            match store.begin_create(plan.clone(), Some(profile), true, cancelled) {
                Ok(result) => break result,
                Err(e) if e.code == "STORAGE_CAPACITY" && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(20))
                }
                Err(e) => return Err(refused(e.code)),
            }
        };
        if !created {
            return Err(refused("ID_CONFLICT"));
        }
        let generation = store.record(&id).operation;
        if store.prepare(&id).is_err() {
            let removed = store.remove_data(&id).is_ok();
            store.finish(&id, "failed", Some("STORAGE_UNAVAILABLE"), removed);
            let contained = removed && store.forget(&id, Some(&generation)).is_ok();
            return Err(OpenError {
                code: "STORAGE_UNAVAILABLE",
                contained,
            });
        }
        store.finish(&id, "ready", None, true);
        Ok(Self {
            store: store.clone(),
            id,
            generation,
        })
    }

    pub(crate) fn remove(self) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(15);
        // A concurrent storage operation can briefly own the catalog. Its capacity refusal has no side effects.
        loop {
            match self
                .store
                .begin_delete(&self.id, Some(&self.generation), &AtomicBool::new(false))
            {
                Ok((_, true)) => break,
                Err(e) if e.code == "STORAGE_CAPACITY" && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(20))
                }
                Err(e) => return Err(invalid(e.code)),
                Ok(_) => return Err(invalid("Temporary storage deletion was not admitted")),
            }
        }
        let result = self.store.remove_data(&self.id);
        self.store.finish(
            &self.id,
            "deleted",
            result.as_ref().err().map(|_| "STORAGE_UNAVAILABLE"),
            result.is_ok(),
        );
        result?;
        self.store
            .forget(&self.id, Some(&self.generation))
            .map_err(|e| invalid(e.code))
    }
}
