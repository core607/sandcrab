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
#[serde(deny_unknown_fields)]
struct Create {
    profile: String,
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
        "profile":value["profile"], "state":value["state"], "code":value["code"],
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
            let plan = Plan {
                id,
                profile: create.profile,
                clone_from: None,
                byte_limit: None,
                inode_limit: None,
                workspace_key: Some(key.into()),
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
                            self.registry
                                .lock()
                                .unwrap()
                                .workspace_windows
                                .remove(&expected.generation);
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
        let Ok(request) = serde_json::from_value::<Command>(body) else {
            return error(400, "INVALID_REQUEST");
        };
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
            if let Some(owned) = shells.get(key) {
                match registry.sessions.get(&owned.id) {
                    Some(s) if s.incarnation == owned.incarnation && !s.terminal() => {
                        if s.state == "closing" {
                            return error(503, "WORKSPACE_CLEANUP_UNCONFIRMED");
                        }
                        if s.state == "stopping" {
                            return error(409, "WORKSPACE_REOPENING");
                        }
                    }
                    _ => {
                        shells.remove(key);
                    }
                }
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
        if !shells.contains_key(key) {
            let Ok(id) = sandcrab_core::new_uuid() else {
                return error(503, "SESSION_UNAVAILABLE");
            };
            let open = Open {
                id: id.clone(),
                server_id: self.id.clone(),
                profile: profile.into(),
                ttl_millis: None,
                volume_id: Some(volume.into()),
                workspace_generation: Some(generation.as_str().unwrap().into()),
                template_id: None,
                rootfs: false,
                resources: None,
                keep_result: false,
            };
            let (status, reply) = self.open_session(open);
            if status == 200 {
                return error(503, "SESSION_UNAVAILABLE");
            }
            if status != 202 {
                return (status, reply);
            }
            let registry = self.registry.lock().unwrap();
            let Some(session) = registry.sessions.get(&id) else {
                return error(409, "SESSION_ENDED");
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
        let owned = shells.get_mut(key).unwrap();
        let metadata = Execution {
            key: key.into(),
            generation: generation.as_str().unwrap().into(),
            fresh_shell: !owned.used,
            window,
        };
        let result =
            self.session_command(&owned.id, request, Some(&owned.incarnation), Some(metadata));
        if result.0 == 202 {
            owned.used = true;
        }
        result
    }
}
