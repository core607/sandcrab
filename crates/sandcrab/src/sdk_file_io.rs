//! SDK multipart staging runs only in the bounded native file helper.
use crate::{
    config::invalid,
    file_io::{self, Job},
    multipart::Multipart,
};
use rustix::fs::{AtFlags, FileType, RenameFlags, renameat_with, statat};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeSet, io};

pub fn path(value: &str, root: bool) -> io::Result<String> {
    let value = if value == "/workspace" {
        "."
    } else {
        value.strip_prefix("/workspace/").unwrap_or(value)
    };
    if !file_io::valid_path(value, root) {
        return Err(invalid("INVALID_PATH"));
    }
    Ok(value.into())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    path: String,
    owner: Option<String>,
    group: Option<String>,
    mode: Option<u32>,
}
#[derive(Deserialize, Serialize)]
pub(crate) struct Entry {
    pub path: String,
    pub mode: u32,
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Publication {
    Succeeded,
    Rejected { code: String },
}
fn metadata(bytes: &[u8]) -> io::Result<Entry> {
    let value = sandcrab_core::parse(bytes).map_err(|_| invalid("INVALID_FILE_METADATA"))?;
    let metadata: Metadata =
        serde_json::from_value(value).map_err(|_| invalid("INVALID_FILE_METADATA"))?;
    if metadata.owner.is_some() || metadata.group.is_some() {
        return Err(invalid("UNSUPPORTED_FILE_OWNER"));
    }
    let mode = mode(metadata.mode)?;
    Ok(Entry {
        path: path(&metadata.path, false)?,
        mode,
    })
}
pub fn mode(value: Option<u32>) -> io::Result<u32> {
    Ok(match value {
        Some(mode) => u32::from_str_radix(&mode.to_string(), 8)
            .ok()
            .filter(|n| *n <= 0o777)
            .ok_or_else(|| invalid("INVALID_FILE_MODE"))?,
        None => 0o755,
    })
}
pub fn receive(job: &Job) -> io::Result<()> {
    let stage = file_io::directory(&job.stage)?;
    let boundary = job
        .multipart
        .as_deref()
        .ok_or_else(|| invalid("INVALID_MULTIPART"))?;
    let mut reader = Multipart::new(io::stdin().lock(), boundary, job.byte_limit + 128 * 16384)?;
    let mut entries = Vec::new();
    let mut paths = BTreeSet::new();
    let mut bytes = 0;
    while !reader.closed() {
        if entries.len() >= 128 {
            return Err(invalid("FILE_ENTRY_LIMIT"));
        }
        reader.header("metadata")?;
        let mut description = Vec::new();
        reader.part(&mut description, 8192)?;
        let entry = metadata(&description)?;
        if !paths.insert(entry.path.clone()) {
            return Err(invalid("INVALID_FILE_METADATA"));
        }
        reader.header("file")?;
        let file = file_io::new_file(&stage, &format!("content-{}", entries.len()))?;
        bytes += reader.part(&mut &file, job.byte_limit - bytes)?;
        file_io::ownership(&file, job, entry.mode)?;
        entries.push(entry);
    }
    reader.finish()?;
    let manifest = file_io::new_file(&stage, "manifest.json")?;
    serde_json::to_writer(&manifest, &entries)?;
    manifest.sync_all()?;
    stage.sync_all()
}
pub fn publish(job: &Job, attempted: &mut bool) -> io::Result<()> {
    let stage = file_io::directory(&job.stage)?;
    let workspace = file_io::directory(&job.workspace)?;
    let manifest = sandcrab_core::fs::protected_file(&job.stage.join("manifest.json"), 1_048_576)?;
    let entries: Vec<Entry> = serde_json::from_slice(&manifest)?;
    if entries.is_empty() || entries.len() > 128 {
        return Err(invalid("INVALID_FILE_METADATA"));
    }
    let mut destinations = Vec::new();
    // Validate every destination before the first rename. I/O failure during the
    // following renames may still leave a partially published batch.
    for (index, entry) in entries.iter().enumerate() {
        let (parent, name) = file_io::parent(&workspace, &entry.path, false)?;
        match statat(&parent, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(info) if FileType::from_raw_mode(info.st_mode) != FileType::RegularFile => {
                return Err(invalid("NOT_REGULAR_FILE"));
            }
            Ok(_) | Err(rustix::io::Errno::NOENT) => (),
            Err(error) => return Err(error.into()),
        }
        file_io::regular(&stage, &format!("content-{index}"))?;
        destinations.push((parent, name));
    }
    for (index, (parent, name)) in destinations.into_iter().enumerate() {
        *attempted = true;
        renameat_with(
            &stage,
            format!("content-{index}"),
            &parent,
            &name,
            RenameFlags::empty(),
        )?;
        parent.sync_all()?;
    }
    stage.sync_all()
}

pub fn execute(job: &Job) -> io::Result<Value> {
    let mut attempted = false;
    let receipt = match publish(job, &mut attempted) {
        Ok(()) => Publication::Succeeded,
        Err(error) if !attempted => Publication::Rejected {
            code: file_io::error_code(&error).into(),
        },
        Err(error) => return Err(error),
    };
    Ok(serde_json::to_value(receipt)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sdk_paths_and_decimal_octal_modes_cannot_select_host_authority() {
        assert_eq!(path("/workspace/项目/a", false).unwrap(), "项目/a");
        assert_eq!(path("/workspace", true).unwrap(), ".");
        for bad in [
            "/etc/passwd",
            "../x",
            "/workspace/../x",
            "/workspace",
            "a//b",
        ] {
            assert!(path(bad, false).is_err());
        }
        let entry = metadata(br#"{"path":"a","mode":640,"owner":null,"group":null}"#).unwrap();
        assert_eq!(entry.mode, 0o640);
        for bad in [
            br#"{"path":"a","mode":888}"#.as_slice(),
            br#"{"path":"a","owner":"root"}"#,
            br#"{"path":"a","mode":1777}"#,
            br#"{"path":"a","unexpected":null}"#,
        ] {
            assert!(metadata(bad).is_err());
        }
    }
}
