//! SDK sessions keep native shell generations; deleting one never releases the workspace.
use crate::{
    opensandbox::Sandbox,
    sdk_types::{self, Result},
    service::Service,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, atomic::Ordering},
    thread,
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct Context {
    pub id: String,
    pub incarnation: String,
    named: bool,
}
#[derive(Default)]
pub struct Contexts {
    entries: BTreeMap<String, Context>,
    default: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    cwd: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Execute {
    command: String,
    cwd: Option<String>,
    pub timeout: Option<u64>,
}
pub fn execution_path(path: &str) -> Option<&str> {
    path.strip_prefix("session/")?
        .strip_suffix("/run")
        .filter(|id| sandcrab_core::uuid(id))
}
fn initialization(environment: &BTreeMap<String, String>, cwd: &str) -> Result<String> {
    sdk_types::working_directory(cwd)?;
    let source = environment
        .iter()
        .map(|(key, value)| format!("export -- {}", sdk_types::quote(&format!("{key}={value}"))))
        .chain(std::iter::once(format!("cd -- {}", sdk_types::quote(cwd))))
        .collect::<Vec<_>>()
        .join(" && ");
    if source.len() > 16384 {
        return Err((400, "COMMAND_LIMIT"));
    }
    Ok(source)
}
impl Execute {
    pub fn source(&self) -> Result<(String, String)> {
        if self.command.is_empty() || self.command.contains('\0') {
            return Err((400, "INVALID_COMMAND"));
        }
        let source = if let Some(cwd) = &self.cwd {
            sdk_types::working_directory(cwd)?;
            format!(
                "cd -- {} && eval -- {}",
                sdk_types::quote(cwd),
                sdk_types::quote(&self.command)
            )
        } else {
            self.command.clone()
        };
        if source.len() > 16384 {
            return Err((400, "COMMAND_LIMIT"));
        }
        Ok((self.command.clone(), source))
    }
}
impl Service {
    pub(crate) fn sdk_expiration(&self, sandbox: &Sandbox) -> Result<u64> {
        let registry = self.registry.lock().unwrap();
        let session = registry
            .sessions
            .get(&sandbox.id)
            .ok_or((404, "NOT_FOUND"))?;
        if session.incarnation != sandbox.incarnation {
            return Err((409, "SANDBOX_CHANGED"));
        }
        Ok(session.expires_at)
    }
    pub(crate) fn sdk_context_native(
        self: &Arc<Self>,
        context: &Context,
        action: &str,
        body: Option<&Value>,
    ) -> Result<Value> {
        let path = format!(
            "/v1/sessions/{}{}{}",
            context.id,
            if action.is_empty() { "" } else { "/" },
            action
        );
        sdk_types::native(
            self.session_route_expected(
                if body.is_some() { "POST" } else { "GET" },
                &path,
                &body
                    .map(|v| serde_json::to_vec(v).unwrap())
                    .unwrap_or_default(),
                Some(&context.incarnation),
            ),
        )
    }
    fn sdk_drop_context(
        self: &Arc<Self>,
        sandbox: &Sandbox,
        context: &Context,
        deadline: Instant,
    ) -> Result<()> {
        match self.sdk_context_native(context, "close", Some(&json!({}))) {
            Ok(_) => loop {
                let value = self.sdk_context_native(context, "", None)?;
                if ["closed", "expired", "failed"].contains(&value["state"].as_str().unwrap_or(""))
                {
                    self.sdk_context_native(context, "forget", Some(&json!({})))?;
                    break;
                }
                if value["state"] == "closing" || Instant::now() >= deadline {
                    return Err((503, "CONTAINMENT_UNCONFIRMED"));
                }
                thread::sleep(Duration::from_millis(10));
            },
            Err((404 | 409, "NOT_FOUND" | "SANDBOX_CHANGED")) => (),
            Err(error) => return Err(error),
        }
        let mut contexts = sandbox.contexts.lock().unwrap();
        contexts.entries.remove(&context.id);
        if contexts.default.as_deref() == Some(&context.id) {
            contexts.default = None;
        }
        Ok(())
    }
    pub(crate) fn sdk_close_contexts(self: &Arc<Self>, sandbox: &Sandbox) -> Result<()> {
        let contexts = sandbox
            .contexts
            .lock()
            .unwrap()
            .entries
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let deadline = Instant::now() + Duration::from_secs(12);
        for context in contexts {
            self.sdk_drop_context(sandbox, &context, deadline)?;
        }
        Ok(())
    }
    // The sandbox gate serializes context ownership and command admission, not execution.
    fn sdk_create_context(
        self: &Arc<Self>,
        sandbox: &Sandbox,
        cwd: Option<&str>,
        named: bool,
    ) -> Result<Context> {
        let setup = if named {
            Some(initialization(
                &sandbox.environment,
                cwd.unwrap_or("/workspace"),
            )?)
        } else {
            None
        };
        if sandbox.contexts.lock().unwrap().entries.len() >= self.runtime.config.service.max_records
        {
            return Err((429, "CONTEXT_CAPACITY"));
        }
        let id = sandcrab_core::new_uuid().map_err(|_| (503, "CONTEXT_UNAVAILABLE"))?;
        self.sdk_native(
            sandbox,
            "shells",
            Some(&json!({"id":id,"serverId":self.id})),
        )?;
        let incarnation = self
            .registry
            .lock()
            .unwrap()
            .sessions
            .get(&id)
            .map(|s| s.incarnation.clone())
            .ok_or((503, "CONTEXT_OUTCOME_UNKNOWN"))?;
        let context = Context {
            id: id.clone(),
            incarnation,
            named,
        };
        {
            let mut contexts = sandbox.contexts.lock().unwrap();
            contexts.entries.insert(id.clone(), context.clone());
            if !named {
                contexts.default = Some(id);
            }
        }
        let ready = (|| {
            let deadline = Instant::now() + Duration::from_secs(12);
            loop {
                let value = self.sdk_context_native(&context, "", None)?;
                match value["state"].as_str() {
                    Some("ready") => break,
                    Some("starting") if Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Some("closing") => return Err((503, "CONTAINMENT_UNCONFIRMED")),
                    _ => return Err((503, "CONTEXT_UNAVAILABLE")),
                }
            }
            if let Some(source) = setup {
                let timeout = self.runtime.config.profiles[&sandbox.profile]
                    .timeout_millis
                    .min(5000);
                self.sdk_dispatch(
                    sandbox,
                    &context,
                    "Initialize shell context".into(),
                    source,
                    Some(timeout),
                )?
                .wait_setup()?;
            }
            Ok(())
        })();
        if let Err(error) = ready {
            self.sdk_drop_context(sandbox, &context, Instant::now() + Duration::from_secs(12))?;
            return Err(error);
        }
        Ok(context)
    }
    pub(crate) fn sdk_command_context(
        self: &Arc<Self>,
        sandbox: &Sandbox,
        named: Option<&str>,
    ) -> Result<Context> {
        self.sdk_native(sandbox, "", None)?;
        if let Some(id) = named {
            return sandbox
                .contexts
                .lock()
                .unwrap()
                .entries
                .get(id)
                .filter(|c| c.named)
                .cloned()
                .ok_or((404, "CONTEXT_NOT_FOUND"));
        }
        let current = {
            let contexts = sandbox.contexts.lock().unwrap();
            contexts
                .default
                .as_ref()
                .and_then(|id| contexts.entries.get(id))
                .cloned()
        };
        if let Some(context) = current {
            match self.sdk_context_native(&context, "", None) {
                Ok(value) if value["state"] == "ready" || value["state"] == "busy" => {
                    return Ok(context);
                }
                Ok(_) | Err((404 | 409, "NOT_FOUND" | "SANDBOX_CHANGED")) => {
                    self.sdk_drop_context(
                        sandbox,
                        &context,
                        Instant::now() + Duration::from_secs(12),
                    )?;
                }
                Err(error) => return Err(error),
            }
        }
        self.sdk_create_context(sandbox, None, false)
    }
    pub(crate) fn sdk_context_route(
        self: &Arc<Self>,
        sandbox: &Sandbox,
        method: &str,
        action: &str,
        body: &[u8],
    ) -> Result<(u16, Value)> {
        let _gate = sandbox.gate.lock().unwrap();
        if sandbox.closing.load(Ordering::SeqCst) {
            return Err((409, "SANDBOX_CLOSING"));
        }
        if method == "POST" && action == "session" {
            let input: Create = sdk_types::parse(if body.is_empty() { b"{}" } else { body })?;
            let context = self.sdk_create_context(sandbox, input.cwd.as_deref(), true)?;
            return Ok((200, json!({"session_id":context.id})));
        }
        if method == "DELETE"
            && body.is_empty()
            && let Some(id) = action
                .strip_prefix("session/")
                .filter(|id| sandcrab_core::uuid(id))
        {
            self.sdk_native(sandbox, "", None)?;
            let context = sandbox
                .contexts
                .lock()
                .unwrap()
                .entries
                .get(id)
                .filter(|c| c.named)
                .cloned()
                .ok_or((404, "CONTEXT_NOT_FOUND"))?;
            self.sdk_drop_context(sandbox, &context, Instant::now() + Duration::from_secs(12))?;
            return Ok((200, Value::Null));
        }
        Err((400, "UNSUPPORTED_OPERATION"))
    }
}
