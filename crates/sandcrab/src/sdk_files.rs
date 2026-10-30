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
    match files::code(value).as_str() {
        "FILE_LIMIT" | "FILE_ENTRY_LIMIT" => (413, "FILE_LIMIT"),
        "INVALID_MULTIPART" | "CONTENT_INCOMPLETE" => (400, "INVALID_MULTIPART"),
        "INVALID_FILE_METADATA" => (400, "INVALID_FILE_METADATA"),
        "UNSUPPORTED_FILE_OWNER" => (400, "UNSUPPORTED_FILE_OWNER"),
        "INVALID_FILE_MODE" => (400, "INVALID_FILE_MODE"),
        "INVALID_PATH" | "INVALID_LINK" | "NOT_DIRECTORY" | "NOT_REGULAR_FILE" if !attempted => {
            (400, "INVALID_PATH")
        }
        "FILE_CAPACITY" if !attempted => (507, "FILE_CAPACITY"),
        "FILE_CANCELLED" if !attempted => (409, "FILE_CANCELLED"),
        _ if attempted => (503, "PUBLICATION_UNKNOWN"),
        _ => (503, "UPLOAD_FAILED"),
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
        let result = (|| -> io::Result<()> {
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
                result.map(|_| ())
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
        result.map_err(|e| error(&e, attempted))
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
