//! Durable request identities and exclusive storage operations outlive transport connections.
use crate::{
    config::Profile,
    service::{Service, error},
    storage::{Plan, Store},
};
use serde_json::{Value, json};
use std::{
    sync::{Arc, atomic::Ordering},
    thread,
};

impl Service {
    pub(crate) fn volume_route(
        self: &Arc<Self>,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> (u16, Value) {
        let Some(store) = &self.runtime.storage else {
            return error(404, "VOLUMES_DISABLED");
        };
        if method == "GET" && (path == "/v1/volumes" || path.starts_with("/v1/volumes?")) {
            let after = if path == "/v1/volumes" {
                ""
            } else {
                let Some(after) = path
                    .strip_prefix("/v1/volumes?after=")
                    .filter(|s| sandcrab_core::uuid(s))
                else {
                    return error(400, "INVALID_REQUEST");
                };
                after
            };
            return (200, store.list(after));
        }
        if method == "POST" && self.stopped.load(Ordering::SeqCst) {
            return error(503, "STOPPING");
        }
        if method == "POST" && path == "/v1/volumes" {
            let Some(mut value) = sandcrab_core::parse(body).ok() else {
                return error(400, "INVALID_REQUEST");
            };
            let Some(server) = value
                .as_object_mut()
                .and_then(|v| v.remove("serverId"))
                .and_then(|s| {
                    s.as_str()
                        .filter(|s| sandcrab_core::uuid(s))
                        .map(str::to_owned)
                })
            else {
                return error(400, "INVALID_REQUEST");
            };
            let Ok(plan) = serde_json::from_value::<Plan>(value) else {
                return error(400, "INVALID_REQUEST");
            };
            let profile = self.runtime.config.profiles.get(&plan.profile).cloned();
            let id = plan.id.clone();
            return match store.begin_create(
                plan,
                profile.as_ref(),
                server == self.id,
                &self.stopped,
            ) {
                Ok((value, false)) => (200, value),
                Ok((value, true)) => {
                    let service = self.clone();
                    let worker = id.clone();
                    if thread::Builder::new()
                        .spawn(move || service.create_volume(&worker, &profile.unwrap()))
                        .is_err()
                    {
                        store.finish(&id, "failed", Some("STORAGE_UNAVAILABLE"), true);
                        return error(503, "STORAGE_UNAVAILABLE");
                    }
                    (202, value)
                }
                Err(e) => error(e.status, e.code),
            };
        }
        let Some(path) = path.strip_prefix("/v1/volumes/") else {
            return error(404, "NOT_FOUND");
        };
        let (id, action) = path.split_once('/').unwrap_or((path, ""));
        if !sandcrab_core::uuid(id) {
            return error(404, "VOLUME_NOT_FOUND");
        }
        if method == "GET" && action.is_empty() {
            return store
                .get(id)
                .map(|v| (200, v))
                .unwrap_or_else(|e| error(e.status, e.code));
        }
        if method != "POST" || !["delete", "forget"].contains(&action) {
            return error(404, "NOT_FOUND");
        }
        if sandcrab_core::parse(body).ok() != Some(json!({})) {
            return error(400, "INVALID_REQUEST");
        }
        if action == "forget" {
            return store
                .forget(id)
                .map(|()| (200, json!({"forgotten":true})))
                .unwrap_or_else(|e| error(e.status, e.code));
        }
        match store.begin_delete(id, &self.stopped) {
            Ok((value, false)) => (200, value),
            Ok((value, true)) => {
                let store = store.clone();
                let worker = store.clone();
                let id = id.to_owned();
                let fallback = id.clone();
                if thread::Builder::new()
                    .spawn(move || {
                        let removed = worker.remove_data(&id).is_ok();
                        worker.finish(
                            &id,
                            "deleted",
                            (!removed).then_some("STORAGE_UNAVAILABLE"),
                            removed,
                        );
                    })
                    .is_err()
                {
                    // The deletion intent is already durable; restart must finish it.
                    store.finish(&fallback, "deleted", Some("STORAGE_UNAVAILABLE"), false);
                    return error(503, "STORAGE_UNAVAILABLE");
                }
                (202, value)
            }
            Err(e) => error(e.status, e.code),
        }
    }

    fn create_volume(&self, id: &str, profile: &Profile) {
        let store = self.runtime.storage.as_ref().unwrap();
        if let Some(source) = &store.record(id).plan.clone_from
            && store.verify_record(&store.record(source)).is_err()
        {
            Self::fail_volume(store, id, "STORAGE_UNAVAILABLE", true);
            return;
        }
        let record = match store.prepare(id) {
            Ok(record) => record,
            Err(_) => {
                Self::fail_volume(store, id, "STORAGE_UNAVAILABLE", true);
                return;
            }
        };
        if let Some(source) = &record.plan.clone_from {
            let (result, contained) = self.runtime.clone_volume(
                &record.operation,
                &store.data(source),
                &store.data(id),
                profile,
                &self.stopped,
            );
            if contained.is_err() {
                Self::fail_volume(store, id, "CONTAINMENT_UNCONFIRMED", false);
                return;
            }
            let code = match result {
                Ok(result)
                    if result.end == sandcrab_daemon::job::End::Normal && result.exit_code == 0 =>
                {
                    None
                }
                Ok(result) => Some(match result.end {
                    sandcrab_daemon::job::End::Timeout => "VOLUME_TIMEOUT",
                    sandcrab_daemon::job::End::Cancelled => "INTERRUPTED",
                    sandcrab_daemon::job::End::ResourceLimit => "RESOURCE_LIMIT",
                    _ => "CLONE_FAILED",
                }),
                Err(_) => Some("CLONE_FAILED"),
            };
            if let Some(code) = code {
                Self::fail_volume(store, id, code, true);
                return;
            }
        }
        if store.verify_record(&record).is_err() {
            Self::fail_volume(store, id, "STORAGE_UNAVAILABLE", true);
            return;
        }
        store.finish(id, "ready", None, true);
    }
    fn fail_volume(store: &Store, id: &str, code: &str, contained: bool) {
        let removed = contained && store.remove_data(id).is_ok();
        store.finish(id, "failed", Some(code), removed);
    }
}
