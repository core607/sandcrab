//! Authenticated template imports share the file-transfer admission and bounded
//! helper path. Publication deduplicates by the normalized tree's SHA-256 identity.
use crate::{
    file_io::{Format, Job},
    file_records::Result,
    service::{Service, error},
    template_io::Tree,
};
use serde_json::{Value, json};
use std::{
    io::{self, Read},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

pub fn import_path(path: &str) -> bool {
    path == "/v1/templates" || path.starts_with("/v1/templates?")
}

fn profile(query: &str) -> Result<(String, Option<String>)> {
    let values = crate::sdk_types::query(query)?;
    let (mut profile, mut expected) = (None, None);
    for (key, value) in values {
        match key.as_str() {
            "profile" if profile.is_none() && crate::config::name(&value) => profile = Some(value),
            "expectedId" if expected.is_none() && crate::file_io::digest(&value) => {
                expected = Some(value)
            }
            _ => return Err((400, "INVALID_QUERY")),
        }
    }
    Ok((profile.ok_or((400, "INVALID_QUERY"))?, expected))
}

fn failure(error: &io::Error) -> (u16, &'static str) {
    match crate::files::code(error).as_str() {
        "FILE_LIMIT" | "FILE_ENTRY_LIMIT" => (413, "TEMPLATE_LIMIT"),
        "INVALID_PATH"
        | "INVALID_LINK"
        | "NOT_DIRECTORY"
        | "UNSUPPORTED_ARCHIVE_ENTRY"
        | "CONTENT_INCOMPLETE" => (400, "INVALID_TEMPLATE_ARCHIVE"),
        "FILE_CANCELLED" => (409, "TEMPLATE_CANCELLED"),
        "FILE_TIMEOUT" => (408, "TEMPLATE_TIMEOUT"),
        _ => (503, "TEMPLATE_IMPORT_FAILED"),
    }
}

impl Service {
    pub(crate) fn import_template(
        &self,
        path: &str,
        length: Option<u64>,
        body: &mut impl Read,
        deadline: Instant,
        ready: impl FnOnce() -> io::Result<()>,
    ) -> Result<Value> {
        if self.stopped.load(Ordering::SeqCst) {
            return Err((503, "STOPPING"));
        }
        let (name, expected) = profile(path.split_once('?').map_or("", |(_, query)| query))?;
        let profile = self
            .runtime
            .config
            .profiles
            .get(&name)
            .ok_or((400, "PROFILE_NOT_FOUND"))?;
        if length.is_some_and(|bytes| bytes > profile.transfer_bytes) {
            return Err((413, "TEMPLATE_LIMIT"));
        }
        self.file_count
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < self.runtime.config.service.max_file_transfers).then_some(n + 1)
            })
            .map_err(|_| (409, "FILE_CAPACITY"))?;
        let store = &self.runtime.templates;
        let stage = match store.begin(&name, profile) {
            Ok(stage) => stage,
            Err(error) => {
                self.file_count.fetch_sub(1, Ordering::SeqCst);
                return Err(error);
            }
        };
        let cancelled = Arc::new(AtomicBool::new(self.stopped.load(Ordering::SeqCst)));
        self.file_cancellations
            .lock()
            .unwrap()
            .insert(stage.id.clone(), cancelled.clone());
        let mut contained = true;
        let result = (|| {
            ready().map_err(|error| failure(&error))?;
            let staging = store.stage(&stage);
            let job = Job {
                action: "template-receive".into(),
                workspace: staging.parent().unwrap().join("data"),
                stage: staging,
                path: "data".into(),
                format: Format::Tar,
                bytes: 0,
                sha256: String::new(),
                replace: false,
                mode: 0o755,
                uid: profile.uid,
                gid: profile.gid,
                byte_limit: profile.transfer_bytes,
                entry_limit: crate::templates::ENTRY_LIMIT,
                multipart: None,
                selection: None,
            };
            let (result, ended) = self.pipe_file(&job, profile, &cancelled, body, deadline);
            contained = ended;
            let tree: Tree = serde_json::from_value(result.map_err(|error| failure(&error))?)
                .map_err(|_| (503, "TEMPLATE_HELPER_FAILED"))?;
            if !contained || cancelled.load(Ordering::SeqCst) || self.stopped.load(Ordering::SeqCst)
            {
                return Err((409, "TEMPLATE_CANCELLED"));
            }
            if expected.as_ref().is_some_and(|id| id != &tree.id) {
                return Err((409, "TEMPLATE_ID_MISMATCH"));
            }
            let tree = store.publish(&stage, tree)?;
            serde_json::to_value(tree).map_err(|_| (503, "TEMPLATE_UNAVAILABLE"))
        })();
        let finished = store.finish(&stage, contained);
        self.file_cancellations.lock().unwrap().remove(&stage.id);
        if finished.cleanup_complete {
            self.file_count.fetch_sub(1, Ordering::SeqCst);
        }
        if !finished.catalog_available {
            return Err((503, "TEMPLATE_STATE_UNCERTAIN"));
        }
        result
    }

    pub(crate) fn template_route(&self, method: &str, path: &str, body: &[u8]) -> (u16, Value) {
        let store = &self.runtime.templates;
        if method == "POST" && path == "/v1/templates/compose" {
            if self.stopped.load(Ordering::SeqCst) {
                return error(503, "STOPPING");
            }
            let Some(request) = sandcrab_core::parse(body)
                .ok()
                .and_then(|value| serde_json::from_value::<crate::recipes::Request>(value).ok())
            else {
                return error(400, "INVALID_RECIPE");
            };
            return match store.compose(request.layers) {
                Ok(recipe) => (200, serde_json::to_value(recipe).expect("recipe metadata")),
                Err((status, code)) => error(status, code),
            };
        }
        if method == "GET" && import_path(path) {
            let after = if path == "/v1/templates" {
                ""
            } else {
                let Some(after) = path
                    .strip_prefix("/v1/templates?after=")
                    .filter(|id| crate::file_io::digest(id))
                else {
                    return error(400, "INVALID_QUERY");
                };
                after
            };
            return (200, store.list(after));
        }
        let Some(id) = path
            .strip_prefix("/v1/templates/")
            .filter(|id| crate::file_io::digest(id))
        else {
            return error(404, "TEMPLATE_NOT_FOUND");
        };
        let result = match method {
            "GET" => store.object(id),
            "DELETE" if self.stopped.load(Ordering::SeqCst) => Err((503, "STOPPING")),
            "DELETE" => store.delete(id).map(|()| json!({"deleted":true})),
            _ => Err((404, "NOT_FOUND")),
        };
        match result {
            Ok(value) => (200, value),
            Err((status, code)) => error(status, code),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn template_import_requires_one_explicit_profile() {
        assert_eq!(profile("profile=python").unwrap(), ("python".into(), None));
        let id = "a".repeat(64);
        assert_eq!(
            profile(&format!("expectedId={id}&profile=python")).unwrap(),
            ("python".into(), Some(id.clone()))
        );
        assert!(profile(&format!("profile=python&expectedId={id}&expectedId={id}")).is_err());
        for query in [
            "",
            "profile=python&profile=other",
            "profile=../escape",
            "profile=python&root=/host",
            "profile=python&expectedId=invalid",
        ] {
            assert!(profile(query).is_err(), "{query}");
        }
        assert!(!import_path("/v1/templates/deadbeef"));
    }
}
