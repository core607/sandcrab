//! SDK filesystem request vocabulary and bounded native-helper ownership.
use crate::{
    config::invalid,
    file_io::Format,
    files,
    sdk_types::{self, Result},
    service::Service,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    process::Stdio,
    sync::{Arc, atomic::Ordering},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Permission {
    mode: Option<u32>,
    owner: Option<String>,
    group: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Mode {
    pub path: String,
    pub mode: u32,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Move {
    pub src: String,
    pub dest: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Replace {
    pub path: String,
    pub old: String,
    pub new: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Substitution {
    old: String,
    new: String,
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Search {
        path: String,
        pattern: String,
    },
    Replace {
        entries: Vec<Replace>,
        verbose: bool,
    },
    Info {
        paths: Vec<String>,
    },
    List {
        path: String,
        depth: usize,
    },
    Mkdir {
        entries: Vec<Mode>,
    },
    Chmod {
        entries: Vec<Mode>,
    },
    Move {
        entries: Vec<Move>,
    },
    Remove {
        paths: Vec<String>,
        directory: bool,
    },
}
pub fn endpoint(method: &str, path: &str) -> bool {
    matches!(
        (method, path),
        ("GET", "files/info" | "directories/list" | "files/search")
            | (
                "POST",
                "directories" | "files/permissions" | "files/mv" | "files/replace"
            )
            | ("DELETE", "files" | "directories")
    )
}
pub fn normalized(value: &str, root: bool) -> Result<String> {
    crate::sdk_file_io::path(value, root).map_err(|_| (400, "INVALID_PATH"))
}
fn distinct(paths: &[String], root: bool, overlap: bool) -> Result<()> {
    if paths.is_empty() || paths.len() > 128 {
        return Err((400, "INVALID_PATHS"));
    }
    let mut names = BTreeSet::new();
    for path in paths {
        if !names.insert(normalized(path, root)?) {
            return Err((400, "DUPLICATE_PATH"));
        }
    }
    if overlap
        && names.iter().any(|path| {
            names
                .iter()
                .any(|other| path != other && path.starts_with(&format!("{other}/")))
        })
    {
        return Err((400, "OVERLAPPING_PATHS"));
    }
    Ok(())
}
impl Request {
    pub fn mutation(&self) -> bool {
        !matches!(
            self,
            Self::Info { .. } | Self::List { .. } | Self::Search { .. }
        )
    }
    pub fn parse(
        method: &str,
        path: &str,
        pairs: &[(String, String)],
        body: &[u8],
    ) -> Result<Self> {
        let paths = || -> Result<Vec<String>> {
            if pairs.iter().any(|(k, _)| k != "path") {
                return Err((400, "INVALID_QUERY"));
            }
            Ok(pairs.iter().map(|(_, v)| v.clone()).collect())
        };
        let request = match (method, path) {
            ("GET", "files/search") => {
                let (mut path, mut pattern) = (None, None);
                for (key, value) in pairs {
                    match key.as_str() {
                        "path" if path.is_none() => path = Some(value.clone()),
                        "pattern" if pattern.is_none() => pattern = Some(value.clone()),
                        _ => return Err((400, "INVALID_QUERY")),
                    }
                }
                Self::Search {
                    path: path.ok_or((400, "INVALID_QUERY"))?,
                    pattern: pattern
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| "**".into()),
                }
            }
            ("POST", "files/replace") => {
                if pairs.len() > 1
                    || pairs
                        .iter()
                        .any(|(k, v)| k != "verbose" || !["true", "false"].contains(&v.as_str()))
                {
                    return Err((400, "INVALID_QUERY"));
                }
                let values: BTreeMap<String, Substitution> = sdk_types::parse(body)?;
                let entries = values
                    .into_iter()
                    .map(|(path, value)| Replace {
                        path,
                        old: value.old,
                        new: value.new,
                    })
                    .collect();
                Self::Replace {
                    entries,
                    verbose: pairs.first().is_some_and(|(_, v)| v == "true"),
                }
            }
            ("GET", "files/info") => Self::Info { paths: paths()? },
            ("GET", "directories/list") => {
                let (mut path, mut depth) = (None, None);
                for (key, value) in pairs {
                    match key.as_str() {
                        "path" if path.is_none() => path = Some(value.clone()),
                        "depth" if depth.is_none() => {
                            depth =
                                Some(value.parse::<usize>().map_err(|_| (400, "INVALID_DEPTH"))?)
                        }
                        _ => return Err((400, "INVALID_QUERY")),
                    }
                }
                Self::List {
                    path: path.ok_or((400, "INVALID_QUERY"))?,
                    depth: depth.unwrap_or(1),
                }
            }
            ("DELETE", "files" | "directories") => Self::Remove {
                paths: paths()?,
                directory: path == "directories",
            },
            ("POST", "files/mv") if pairs.is_empty() => Self::Move {
                entries: sdk_types::parse(body)?,
            },
            ("POST", "directories" | "files/permissions") if pairs.is_empty() => {
                let values: BTreeMap<String, Permission> = sdk_types::parse(body)?;
                let mut entries = Vec::new();
                for (path, permission) in values {
                    if permission.owner.is_some() || permission.group.is_some() {
                        return Err((400, "UNSUPPORTED_FILE_OWNER"));
                    }
                    entries.push(Mode {
                        path,
                        mode: crate::sdk_file_io::mode(permission.mode)
                            .map_err(|_| (400, "INVALID_FILE_MODE"))?,
                    });
                }
                if path == "directories" {
                    Self::Mkdir { entries }
                } else {
                    Self::Chmod { entries }
                }
            }
            _ => return Err((400, "UNSUPPORTED_OPERATION")),
        };
        request.validate()?;
        Ok(request)
    }
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Search { path, pattern } => {
                normalized(path, true)?;
                if pattern.is_empty()
                    || pattern.len() > 1024
                    || pattern.chars().any(char::is_control)
                {
                    return Err((400, "GLOB_LIMIT"));
                }
                Ok(())
            }
            Self::Replace { entries, .. } => {
                if entries.iter().any(|e| e.old.is_empty()) {
                    return Err((400, "EMPTY_REPLACEMENT_PATTERN"));
                }
                distinct(
                    &entries.iter().map(|e| e.path.clone()).collect::<Vec<_>>(),
                    false,
                    false,
                )
            }
            Self::Info { paths } => distinct(paths, true, false),
            Self::Remove { paths, .. } => distinct(paths, false, true),
            Self::List { path, depth } => {
                normalized(path, true)?;
                if *depth > 64 {
                    return Err((400, "INVALID_DEPTH"));
                }
                Ok(())
            }
            Self::Mkdir { entries } | Self::Chmod { entries } => {
                if entries.iter().any(|e| e.mode > 0o777) {
                    return Err((400, "INVALID_FILE_MODE"));
                }
                distinct(
                    &entries.iter().map(|e| e.path.clone()).collect::<Vec<_>>(),
                    true,
                    false,
                )
            }
            Self::Move { entries } => {
                let sources = entries.iter().map(|e| e.src.clone()).collect::<Vec<_>>();
                let destinations = entries.iter().map(|e| e.dest.clone()).collect::<Vec<_>>();
                distinct(&sources, false, true)?;
                distinct(&destinations, false, true)?;
                for entry in entries {
                    let src = normalized(&entry.src, false)?;
                    let dest = normalized(&entry.dest, false)?;
                    if dest.starts_with(&format!("{src}/")) {
                        return Err((400, "OVERLAPPING_PATHS"));
                    }
                }
                Ok(())
            }
        }
    }
}
fn error(value: &io::Error, mutation_started: bool) -> (u16, &'static str) {
    match files::code(value).as_str() {
        "INVALID_GLOB" => (400, "INVALID_GLOB"),
        "GLOB_LIMIT" => (400, "GLOB_LIMIT"),
        "UNSUPPORTED_GLOB_NEGATION" => (400, "UNSUPPORTED_GLOB_NEGATION"),
        "FILE_NOT_FOUND" => (404, "FILE_NOT_FOUND"),
        "FILE_ENTRY_LIMIT" | "FILE_METADATA_LIMIT" => (413, "FILE_METADATA_LIMIT"),
        "FILE_LIMIT" => (413, "FILE_LIMIT"),
        "INVALID_FILE_MODE" => (400, "INVALID_FILE_MODE"),
        "INVALID_PATH" | "INVALID_LINK" | "NOT_DIRECTORY" | "NOT_REGULAR_FILE" => {
            (400, "INVALID_PATH")
        }
        "PATH_EXISTS" => (409, "PATH_EXISTS"),
        "FILE_CANCELLED" if !mutation_started => (409, "FILE_CANCELLED"),
        "FILE_OPERATION_UNKNOWN" => (503, "FILE_OPERATION_UNKNOWN"),
        _ if mutation_started => (503, "FILE_OPERATION_UNKNOWN"),
        _ => (503, "FILE_OPERATION_FAILED"),
    }
}
impl Service {
    pub(crate) fn sdk_file_operation(
        self: &Arc<Self>,
        id: &str,
        request: &Request,
    ) -> Result<Value> {
        let bytes = serde_json::to_vec(request).map_err(|_| (400, "INVALID_REQUEST"))?;
        if bytes.len() > 65536 {
            return Err((413, "FILE_METADATA_LIMIT"));
        }
        let sandbox = self.sdk.sandbox(id)?;
        if sandbox.closing.load(Ordering::SeqCst) {
            return Err((409, "SANDBOX_CLOSING"));
        }
        let lease = self.file_lease(id, Some(&sandbox.incarnation))?;
        let id = match sandcrab_core::new_uuid() {
            Ok(id) => id,
            Err(_) => {
                lease.finish(true);
                return Err((503, "FILE_UNAVAILABLE"));
            }
        };
        let stage = files::stage(&id, &lease.access);
        let mut contained = true;
        let mut started = false;
        let result = (|| -> io::Result<Value> {
            let path = self
                .runtime
                .files
                .begin_stage(&stage, &self.runtime.config)?;
            crate::storage::write(&path.join("request.json"), request)?;
            let action = if request.mutation() {
                "sdk-mutate"
            } else {
                "sdk-query"
            };
            let job = files::job(action, "unused", Format::Raw, &lease.access, &path);
            lease.access.frozen(true, || {
                if lease.cancelled.load(Ordering::SeqCst) {
                    return Err(invalid("FILE_CANCELLED"));
                }
                started = true;
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
            contained =
                !self.runtime.files.has_stage(&id) || self.runtime.clean_stage(&stage).is_ok();
        }
        lease.finish(contained);
        if !contained {
            return Err((503, "FILE_CLEANUP_UNCONFIRMED"));
        }
        result.map_err(|e| error(&e, started && request.mutation()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_metadata_and_paths_validate_before_a_file_helper_is_admitted() {
        for body in [
            br#"{"/workspace/a":{"mode":888}}"#.as_slice(),
            br#"{"/workspace/a":{"mode":755,"owner":"root"}}"#,
            br#"{"/workspace/a":{"mode":755},"a":{"mode":755}}"#,
            br#"{"/workspace/a":{"mode":755,"unexpected":null}}"#,
        ] {
            assert!(Request::parse("POST", "directories", &[], body).is_err());
        }
        let paths = vec![("path".into(), "a".into()), ("path".into(), "a/b".into())];
        assert!(Request::parse("DELETE", "directories", &paths, &[]).is_err());
        assert!(Request::parse("GET", "files/info", &paths, &[]).is_ok());
        assert!(Request::parse("POST", "files/mv", &[], br#"[{"src":"a","dest":"a/b"}]"#).is_err());
        assert!(Request::parse("POST", "files/permissions", &[], br#"{"a":{"mode":640}}"#).is_ok());
    }
}
