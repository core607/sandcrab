//! SDK transfers pin native workspace generations and release owned staging.
use crate::{
    config::invalid, file_io::Format, files, opensandbox::Sandbox, sdk_types::Result,
    service::Service,
};
use std::{
    io::{self, Read},
    process::Stdio,
    sync::{Arc, atomic::Ordering},
    time::Instant,
};

pub fn upload_path(path: &str) -> Option<&str> {
    path.strip_prefix("/opensandbox/")?
        .strip_suffix("/files/upload")
        .filter(|id| sandcrab_core::uuid(id))
}
pub fn download_path(path: &str) -> Option<(&str, &str)> {
    let (path, query) = path.split_once('?')?;
    let id = path
        .strip_prefix("/opensandbox/")?
        .strip_suffix("/files/download")?;
    sandcrab_core::uuid(id).then_some((id, query))
}
fn error(value: &io::Error, attempted: bool) -> (u16, &'static str) {
    if attempted {
        return (503, "PUBLICATION_UNKNOWN");
    }
    match files::code(value).as_str() {
        "FILE_LIMIT" | "FILE_ENTRY_LIMIT" => (413, "FILE_LIMIT"),
        "INVALID_MULTIPART" | "CONTENT_INCOMPLETE" => (400, "INVALID_MULTIPART"),
        "INVALID_FILE_METADATA" => (400, "INVALID_FILE_METADATA"),
        "UNSUPPORTED_FILE_OWNER" => (400, "UNSUPPORTED_FILE_OWNER"),
        "INVALID_FILE_MODE" => (400, "INVALID_FILE_MODE"),
        "INVALID_PATH" | "INVALID_LINK" | "NOT_DIRECTORY" | "NOT_REGULAR_FILE" => {
            (400, "INVALID_PATH")
        }
        "FILE_CAPACITY" => (507, "FILE_CAPACITY"),
        "FILE_CANCELLED" => (409, "FILE_CANCELLED"),
        _ => (503, "UPLOAD_FAILED"),
    }
}
fn publication(value: serde_json::Value) -> Result<()> {
    match serde_json::from_value(value) {
        Ok(crate::sdk_file_io::Publication::Succeeded) => Ok(()),
        Ok(crate::sdk_file_io::Publication::Rejected { code }) => {
            Err(if code == "FILE_NOT_FOUND" {
                (404, "FILE_NOT_FOUND")
            } else {
                error(&invalid(&code), false)
            })
        }
        Err(_) => Err((503, "PUBLICATION_UNKNOWN")),
    }
}
impl Service {
    pub(crate) fn sdk_upload(
        self: &Arc<Self>,
        id: &str,
        boundary: &str,
        length: Option<u64>,
        body: &mut impl Read,
        deadline: Instant,
    ) -> Result<()> {
        let sandbox = self.sdk.sandbox(id)?;
        if sandbox.closing.load(Ordering::SeqCst) {
            return Err((409, "SANDBOX_CLOSING"));
        }
        let lease = self.file_lease(id, Some(&sandbox.incarnation))?;
        if length.is_some_and(|n| n > lease.access.profile.transfer_bytes + 128 * 16384) {
            lease.finish(true);
            return Err((413, "FILE_LIMIT"));
        }
        let stage_id = match sandcrab_core::new_uuid() {
            Ok(id) => id,
            Err(_) => {
                lease.finish(true);
                return Err((503, "FILE_UNAVAILABLE"));
            }
        };
        let stage = files::stage(&stage_id, &lease.access);
        let mut contained = true;
        let mut attempted = false;
        let result = (|| -> io::Result<serde_json::Value> {
            let path = self
                .runtime
                .files
                .begin_stage(&stage, &self.runtime.config)?;
            let mut job = files::job("sdk-receive", "unused", Format::Raw, &lease.access, &path);
            job.multipart = Some(boundary.into());
            let (result, ended) = self.pipe_upload(&job, &lease, body, deadline);
            contained &= ended;
            result?;
            if !contained {
                return Err(invalid("FILE_CLEANUP_UNCONFIRMED"));
            }
            lease.access.frozen(true, || {
                if lease.cancelled.load(Ordering::SeqCst) {
                    return Err(invalid("FILE_CANCELLED"));
                }
                job.action = "sdk-publish".into();
                attempted = true;
                let (result, ended) = self.runtime.file_helper(
                    &job,
                    &lease.access.profile,
                    &lease.cancelled,
                    Stdio::null(),
                );
                contained &= ended;
                result
            })
        })();
        if contained {
            contained = !self.runtime.files.has_stage(&stage_id)
                || self.runtime.clean_stage(&stage).is_ok();
        }
        lease.finish(contained);
        if !contained {
            return Err((503, "FILE_CLEANUP_UNCONFIRMED"));
        }
        // Only a normal helper reply, successful unfreeze and confirmed staging
        // cleanup can prove that publication never started. A lost/failed helper
        // remains uncertain even if its I/O error resembles an input refusal.
        publication(result.map_err(|e| error(&e, attempted))?)
    }
    pub(crate) fn sdk_capture(
        self: &Arc<Self>,
        id: &str,
        query: &str,
        range: Option<&str>,
    ) -> Result<files::Snapshot> {
        let (path, selection) = crate::sdk_download::request(query, range)?;
        let sandbox: Arc<Sandbox> = self.sdk.sandbox(id)?;
        if sandbox.closing.load(Ordering::SeqCst) {
            return Err((409, "SANDBOX_CLOSING"));
        }
        self.capture(
            id,
            &serde_json::to_vec(&serde_json::json!({"path":path,"format":"raw","freeze":true}))
                .unwrap(),
            Some(&sandbox.incarnation),
            selection.as_ref(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_an_acknowledged_prepublication_refusal_is_recoverable() {
        assert_eq!(
            publication(json!({"state":"rejected","code":"FILE_NOT_FOUND"})),
            Err((404, "FILE_NOT_FOUND"))
        );
        assert_eq!(
            publication(json!({"state":"rejected","code":"NOT_REGULAR_FILE"})),
            Err((400, "INVALID_PATH"))
        );
        assert_eq!(
            error(&invalid("FILE_NOT_FOUND"), true),
            (503, "PUBLICATION_UNKNOWN")
        );
        assert_eq!(
            error(&invalid("FILE_NOT_FOUND"), false),
            (503, "UPLOAD_FAILED")
        );
        assert_eq!(
            error(&invalid("FILE_LIMIT"), true),
            (503, "PUBLICATION_UNKNOWN")
        );
        assert_eq!(
            publication(json!({"state":"rejected"})),
            Err((503, "PUBLICATION_UNKNOWN"))
        );
        assert_eq!(publication(json!({"state":"succeeded"})), Ok(()));
    }
}
