//! One-request file uploads use bounded staging and confirm publication before replying.
use crate::{
    config::invalid,
    file_io::{Format, Publication},
    file_records::Result,
    files,
    service::Service,
};
use sandcrab_core::process::Input;
use serde_json::{Value, json};
use std::{
    io::{self, Read},
    sync::atomic::Ordering,
    time::Instant,
};

pub fn endpoint(path: &str) -> Option<(&str, &str)> {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let id = path.strip_prefix("/v1/sessions/")?.strip_suffix("/files")?;
    sandcrab_core::uuid(id).then_some((id, query))
}

struct Request {
    path: String,
    replace: bool,
    mode: u32,
}
impl Request {
    fn parse(query: &str) -> Result<Self> {
        let (mut path, mut replace, mut mode) = (None, None, None);
        for (key, value) in crate::sdk_types::query(query)? {
            match key.as_str() {
                "path" if path.is_none() && crate::file_io::valid_path(&value, false) => {
                    path = Some(value);
                }
                "replace" if replace.is_none() && ["true", "false"].contains(&value.as_str()) => {
                    replace = Some(value == "true");
                }
                "mode" if mode.is_none() => {
                    mode = Some(
                        value
                            .parse::<u32>()
                            .ok()
                            .filter(|v| *v <= 0o777)
                            .ok_or((400, "INVALID_FILE_MODE"))?,
                    );
                }
                _ => return Err((400, "INVALID_QUERY")),
            }
        }
        Ok(Self {
            path: path.ok_or((400, "INVALID_PATH"))?,
            replace: replace.unwrap_or(true),
            mode: mode.unwrap_or(0o644),
        })
    }
}

fn error(value: &io::Error, attempted: bool) -> (u16, &'static str) {
    if attempted {
        return (503, "PUBLICATION_UNKNOWN");
    }
    match files::code(value).as_str() {
        "FILE_LIMIT" => (413, "FILE_LIMIT"),
        "CONTENT_INCOMPLETE" => (400, "CONTENT_INCOMPLETE"),
        "INVALID_PATH" | "INVALID_LINK" | "NOT_DIRECTORY" | "NOT_REGULAR_FILE" => {
            (400, "INVALID_PATH")
        }
        "FILE_NOT_FOUND" => (404, "FILE_NOT_FOUND"),
        "PATH_EXISTS" => (409, "PATH_EXISTS"),
        "FILE_CAPACITY" => (507, "FILE_CAPACITY"),
        "FILE_CANCELLED" => (409, "FILE_CANCELLED"),
        "FILE_TIMEOUT" => (408, "FILE_TIMEOUT"),
        _ => (503, "UPLOAD_FAILED"),
    }
}

impl Service {
    pub(crate) fn put_file(
        &self,
        target: (&str, &str),
        length: Option<u64>,
        body: &mut impl Read,
        deadline: Instant,
        ready: impl FnOnce() -> io::Result<()>,
    ) -> Result<Value> {
        let request = Request::parse(target.1)?;
        let id = sandcrab_core::new_uuid().map_err(|_| (503, "FILE_UNAVAILABLE"))?;
        let lease = self.file_lease(target.0, None)?;
        let stage = files::stage(&id, &lease.access);
        let mut contained = true;
        let result = (|| {
            lease.allow_growth().map_err(|code| (409, code))?;
            if length.is_some_and(|n| n > lease.access.profile.transfer_bytes) {
                return Err((413, "FILE_LIMIT"));
            }
            let path = self
                .runtime
                .files
                .begin_stage(&stage, &self.runtime.config)
                .map_err(|e| error(&e, false))?;
            ready().map_err(|e| error(&e, false))?;
            let mut job = files::job(
                "stream-receive",
                &request.path,
                Format::Raw,
                &lease.access,
                &path,
            );
            job.replace = request.replace;
            job.mode = request.mode;
            let (received, ended) = self.pipe_upload(&job, &lease, body, deadline);
            contained &= ended;
            let received = received.map_err(|e| error(&e, false))?;
            if !contained || lease.cancelled.load(Ordering::SeqCst) {
                return Err((409, "FILE_CANCELLED"));
            }
            job.action = "stream-publish".into();
            let (published, ended) = self.runtime.file_helper(
                &job,
                &lease.access.profile,
                &lease.cancelled,
                Input::Null,
            );
            contained &= ended;
            let receipt: Publication =
                serde_json::from_value(published.map_err(|e| error(&e, true))?)
                    .map_err(|_| (503, "PUBLICATION_UNKNOWN"))?;
            match receipt {
                Publication::Succeeded => Ok(json!({"path":request.path,
                    "bytes":received["bytes"],"sha256":received["sha256"]})),
                Publication::Rejected { code } => Err(error(&invalid(code), false)),
            }
        })();
        if contained && self.runtime.files.has_stage(&id) {
            contained = self.runtime.clean_stage(&stage).is_ok();
        }
        lease.finish(contained);
        if !contained {
            return Err((503, "FILE_CLEANUP_UNCONFIRMED"));
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_options_preserve_paths_and_reject_ambiguous_authority() {
        let request = Request::parse("path=dir%2Fhello%20world&mode=416&replace=false").unwrap();
        assert_eq!(request.path, "dir/hello world");
        assert_eq!(request.mode, 0o640);
        assert!(!request.replace);
        for query in [
            "",
            "path=../outside",
            "path=a&path=b",
            "path=a&mode=512",
            "path=a&replace=1",
            "path=a&freeze=true",
        ] {
            assert!(Request::parse(query).is_err(), "{query}");
        }
        assert_eq!(
            error(&invalid("PATH_EXISTS"), true),
            (503, "PUBLICATION_UNKNOWN")
        );
        assert_eq!(error(&invalid("PATH_EXISTS"), false), (409, "PATH_EXISTS"));
    }
}
