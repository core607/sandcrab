//! A workspace file request pins the resolved session until its existing file handler returns.
use crate::service::{Service, error};
use serde_json::Value;
use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

pub(crate) fn target<'a>(method: &str, path: &'a str) -> Option<(&'a str, &'a str)> {
    let (key, tail) = path.strip_prefix("/v1/workspaces/")?.split_once('/')?;
    let action = tail.split_once('?').map_or(tail, |(name, _)| name);
    matches!(
        (method, action),
        ("GET" | "PUT" | "DELETE", "files")
            | ("POST", "files/edit" | "files/mkdir")
            | ("GET", "files/list" | "files/search")
            | ("GET", "diff")
    )
    .then_some((key, tail))
}

pub(crate) struct Pin {
    service: Arc<Service>,
    pub id: String,
    incarnation: String,
}

impl Drop for Pin {
    fn drop(&mut self) {
        let mut registry = self.service.registry.lock().unwrap();
        if let Some(session) = registry.sessions.get_mut(&self.id)
            && session.incarnation == self.incarnation
        {
            session.workspace_file_users -= 1;
            session.touch_workspace();
        }
    }
}

impl Service {
    pub(crate) fn workspace_file(
        self: &Arc<Self>,
        key: &str,
        generation: Option<&str>,
        deadline: Instant,
    ) -> Result<Pin, (u16, Value)> {
        let volume = crate::workspace_api::storage_id(key)
            .ok_or_else(|| error(400, "INVALID_WORKSPACE_KEY"))?;
        let generation = generation
            .filter(|s| sandcrab_core::uuid(s))
            .ok_or_else(|| error(400, "INVALID_WORKSPACE_GENERATION"))?;
        let store = self
            .runtime
            .storage
            .as_ref()
            .ok_or_else(|| error(404, "WORKSPACES_DISABLED"))?;
        let pin = {
            let mut shells = self.workspace_shells.lock().unwrap();
            let record = store.get(&volume).map_err(|e| {
                if e.status == 404 {
                    error(404, "WORKSPACE_NOT_FOUND")
                } else {
                    error(e.status, e.code)
                }
            })?;
            if record["workspaceKey"] != key {
                return Err(error(404, "WORKSPACE_NOT_FOUND"));
            }
            if record["workspaceGeneration"] != generation {
                return Err(error(409, "WORKSPACE_CHANGED"));
            }
            let shell = self.open_workspace_shell(key, &volume, &record, &mut shells)?;
            let mut registry = self.registry.lock().unwrap();
            let session = registry
                .sessions
                .get_mut(&shell.id)
                .filter(|s| s.incarnation == shell.incarnation && !s.terminal())
                .ok_or_else(|| error(409, "WORKSPACE_REOPENING"))?;
            session.workspace_file_users += 1;
            session.touch_workspace();
            Pin {
                service: self.clone(),
                id: shell.id.clone(),
                incarnation: shell.incarnation.clone(),
            }
        };
        loop {
            {
                let registry = self.registry.lock().unwrap();
                match registry.sessions.get(&pin.id).map(|s| s.state.as_str()) {
                    Some("ready" | "busy") => return Ok(pin),
                    Some("starting") => (),
                    Some("closing") => return Err(error(503, "WORKSPACE_CLEANUP_UNCONFIRMED")),
                    _ => return Err(error(409, "WORKSPACE_REOPENING")),
                }
            }
            if Instant::now() >= deadline {
                return Err(error(503, "WORKSPACE_START_TIMEOUT"));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}
