//! Caller keys name installation-owned storage. Shells and runs belong to one daemon epoch.
use crate::{
    service::{Service, error},
    sessions::{Command, Open},
    storage::Plan,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};

pub(crate) fn storage_id(key: &str) -> Option<String> {
    if key.len() > 128
        || !key
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !key
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
    {
        return None;
    }
    let digest = Sha256::new()
        .chain_update(b"sandcrab-workspace\0")
        .chain_update(key)
        .finalize();
    let mut bytes: [u8; 16] = digest[..16].try_into().unwrap();
    bytes[6] = bytes[6] & 0x0f | 0x80;
    bytes[8] = bytes[8] & 0x3f | 0x80;
    Some(sandcrab_core::format_uuid(bytes))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Create {
    profile: String,
    template_id: Option<String>,
}

pub(crate) struct Shell {
    pub id: String,
    pub incarnation: String,
    pub used: bool,
}

pub(crate) struct Execution {
    pub key: String,
    pub generation: String,
    pub fresh_shell: bool,
    pub init_failed: bool,
    pub window: u64,
}

impl Service {
    fn workspace(&self, value: &Value) -> Value {
        let registry = self.registry.lock().unwrap();
        let window = registry
            .workspace_windows
            .get(value["workspaceGeneration"].as_str().unwrap())
            .copied()
            .unwrap_or(0);
        json!({"id":value["id"], "key":value["workspaceKey"], "generation":value["workspaceGeneration"], "submissionWindow":window, "serverId":self.id,
        "profile":value["profile"], "templateId":value["templateId"], "state":value["state"], "code":value["code"],
        "byteLimit":value["byteLimit"], "inodeLimit":value["inodeLimit"]})
    }
    pub(crate) fn workspace_route(
        self: &Arc<Self>,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> (u16, Value) {
        let tail = path.strip_prefix("/v1/workspaces/").unwrap_or("");
        let (key, action) = tail.split_once('/').unwrap_or((tail, ""));
        let Some(id) = storage_id(key) else {
            return error(400, "INVALID_WORKSPACE_KEY");
        };
        let Some(store) = &self.runtime.storage else {
            return error(404, "WORKSPACES_DISABLED");
        };
        if method == "POST" && action.is_empty() {
            let Ok(create) = crate::sdk_types::parse::<Create>(body) else {
                return error(400, "INVALID_REQUEST");
            };
            // Serialize base selection with template deletion until the durable plan exists.
            let _admission = self.workspace_shells.lock().unwrap();
            if let Some(base) = &create.template_id {
                if !crate::file_io::digest(base) {
                    return error(400, "INVALID_TEMPLATE_ID");
                }
                let Some(profile) = self.runtime.config.profiles.get(&create.profile) else {
                    return error(400, "PROFILE_NOT_FOUND");
                };
                if let Err((status, code)) = self.runtime.templates.acquire(base, profile) {
                    return error(status, code);
                }
            }
            let plan = Plan {
                id,
                profile: create.profile,
                clone_from: None,
                byte_limit: None,
                inode_limit: None,
                workspace_key: Some(key.into()),
                template_id: create.template_id,
                temporary: false,
            };
            let (status, reply) = self.begin_volume(store, plan, true);
            return if status < 300 {
                (status, self.workspace(&reply))
            } else {
                (status, reply)
            };
        }
        // Serialize selection and admission, never guest execution or storage completion.
        let mut shells = self.workspace_shells.lock().unwrap();
        let value = match store.get(&id) {
            Ok(value) if value["workspaceKey"].as_str() == Some(key) => value,
            Ok(_) => return error(404, "WORKSPACE_NOT_FOUND"),
            Err(e) if e.status == 404 => return error(404, "WORKSPACE_NOT_FOUND"),
            Err(e) => return error(e.status, e.code),
        };
        match (method, action) {
            ("GET", "") => (200, self.workspace(&value)),
            ("POST", "commands") => self.workspace_submit(key, &id, &value, body, &mut shells),
            ("POST", "delete" | "forget") => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Expected {
                    generation: String,
                }
                let Ok(expected) = crate::sdk_types::parse::<Expected>(body) else {
                    return error(400, "INVALID_REQUEST");
                };
                if value["workspaceGeneration"].as_str() != Some(&expected.generation) {
                    return error(409, "WORKSPACE_CHANGED");
                }
                if action == "forget" {
                    return match store.forget(&id, Some(&expected.generation)) {
                        Ok(()) => {
                            shells.remove(key);
                            let mut registry = self.registry.lock().unwrap();
                            registry.workspace_windows.remove(&expected.generation);
                            registry.forget_workspace_sessions(&expected.generation);
                            (200, json!({"forgotten":true}))
                        }
                        Err(e) => error(e.status, e.code),
                    };
                }
                let (status, reply) = self.delete_volume(store, &id, Some(&expected.generation));
                if status < 300
                    && let Some(owned) = shells.remove(key)
                {
                    let mut registry = self.registry.lock().unwrap();
                    if registry
                        .sessions
                        .get(&owned.id)
                        .is_some_and(|s| s.incarnation == owned.incarnation && !s.terminal())
                    {
                        registry.stop_session(&owned.id, "closed");
                    }
                }
                if status < 300 {
                    (status, self.workspace(&reply))
                } else {
                    (status, reply)
                }
            }
            _ => error(404, "NOT_FOUND"),
        }
    }

    fn workspace_submit(
        self: &Arc<Self>,
        key: &str,
        volume: &str,
        record: &Value,
        body: &[u8],
        shells: &mut BTreeMap<String, Shell>,
    ) -> (u16, Value) {
        let Ok(mut body) = sandcrab_core::parse(body) else {
            return error(400, "INVALID_REQUEST");
        };
        let Some(window) = body
            .as_object_mut()
            .and_then(|v| v.remove("submissionWindow"))
            .and_then(|v| v.as_u64())
        else {
            return error(400, "INVALID_REQUEST");
        };
        let Some(generation) = body
            .as_object_mut()
            .and_then(|map| map.remove("generation"))
        else {
            return error(400, "INVALID_REQUEST");
        };
        let fresh_child = match body.as_object_mut().and_then(|v| v.remove("freshChild")) {
            None => false,
            Some(Value::Bool(value)) => value,
            _ => return error(400, "INVALID_REQUEST"),
        };
        let init = match body.as_object_mut().and_then(|v| v.remove("shellInit")) {
            None => None,
            Some(Value::String(source))
                if fresh_child
                    && !source.is_empty()
                    && source.len() <= 16384
                    && !source.contains('\0') =>
            {
                Some(source)
            }
            _ => return error(400, "INVALID_REQUEST"),
        };
        let Ok(mut request) = serde_json::from_value::<Command>(body) else {
            return error(400, "INVALID_REQUEST");
        };
        request.fresh_child = fresh_child;
        request.shell_init = init;
        if request.server_id != self.id {
            return error(409, "SERVER_CHANGED");
        }
        if generation != record["workspaceGeneration"] {
            return error(409, "WORKSPACE_CHANGED");
        }
        {
            let mut registry = self.registry.lock().unwrap();
            registry.expire_sessions();
            if let Some(run) = registry.runs.get(&request.id) {
                return if run.workspace.as_ref().is_some_and(|w| {
                    w.key == key && w.window == window && generation.as_str() == Some(&w.generation)
                }) && run.request["sessionId"]
                    .as_str()
                    .is_some_and(|session| run.request == request.identity(session))
                {
                    (200, run.value())
                } else {
                    error(409, "ID_CONFLICT")
                };
            }
            if window == u64::MAX
                || window
                    != registry
                        .workspace_windows
                        .get(generation.as_str().unwrap())
                        .copied()
                        .unwrap_or(0)
            {
                return error(409, "WORKSPACE_SUBMISSION_EXPIRED");
            }
        }
        if record["state"] != "ready" {
            return error(409, "WORKSPACE_NOT_READY");
        }
        let profile = record["profile"].as_str().unwrap();
        // Validate a refusal before consuming a sandbox slot for a new shell.
        let Some(config) = self.runtime.config.profiles.get(profile) else {
            return error(400, "PROFILE_NOT_FOUND");
        };
        if let Err(code) = request.limits(config) {
            return error(400, code);
        }
        let owned = match self.open_workspace_shell(key, volume, record, shells) {
            Ok(owned) => owned,
            Err(reply) => return reply,
        };
        let metadata = Execution {
            key: key.into(),
            generation: generation.as_str().unwrap().into(),
            fresh_shell: fresh_child || !owned.used,
            init_failed: false,
            window,
        };
        let result =
            self.session_command(&owned.id, request, Some(&owned.incarnation), Some(metadata));
        if result.0 == 202 && !fresh_child {
            owned.used = true;
        }
        result
    }
    pub(crate) fn open_workspace_shell<'a>(
        self: &Arc<Self>,
        key: &str,
        volume: &str,
        record: &Value,
        shells: &'a mut BTreeMap<String, Shell>,
    ) -> Result<&'a mut Shell, (u16, Value)> {
        if record["state"] != "ready" {
            return Err(error(409, "WORKSPACE_NOT_READY"));
        }
        let profile = record["profile"].as_str().unwrap();
        let generation = &record["workspaceGeneration"];
        {
            let mut registry = self.registry.lock().unwrap();
            registry.expire_sessions();
            if let Some(owned) = shells.get(key) {
                match registry.sessions.get(&owned.id) {
                    Some(s) if s.incarnation == owned.incarnation && !s.terminal() => {
                        if s.state == "closing" {
                            return Err(error(503, "WORKSPACE_CLEANUP_UNCONFIRMED"));
                        }
                        if s.state == "stopping" {
                            return Err(error(409, "WORKSPACE_REOPENING"));
                        }
                    }
                    _ => {
                        shells.remove(key);
                    }
                }
            }
        }
        if !shells.contains_key(key) {
            let Ok(id) = sandcrab_core::new_uuid() else {
                return Err(error(503, "SESSION_UNAVAILABLE"));
            };
            let open = Open {
                id: id.clone(),
                server_id: self.id.clone(),
                profile: profile.into(),
                ttl_millis: None,
                volume_id: Some(volume.into()),
                workspace_generation: Some(generation.as_str().unwrap().into()),
                template_id: record["templateId"].as_str().map(str::to_owned),
                rootfs: false,
                resources: None,
                keep_result: false,
            };
            let (status, reply) = self.open_session(open);
            if status == 200 {
                return Err(error(503, "SESSION_UNAVAILABLE"));
            }
            if status != 202 {
                return Err((status, reply));
            }
            let registry = self.registry.lock().unwrap();
            let Some(session) = registry.sessions.get(&id) else {
                return Err(error(409, "SESSION_ENDED"));
            };
            shells.insert(
                key.to_owned(),
                Shell {
                    id,
                    incarnation: session.incarnation.clone(),
                    used: false,
                },
            );
        }
        Ok(shells.get_mut(key).unwrap())
    }
}
