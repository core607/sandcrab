//! Filesystem operations execute while their native workspace lease is frozen.
use crate::{
    config::invalid,
    file_io::{self, Job},
    sdk_fs::{self, Request},
};
use rustix::fs::{
    AtFlags, FileType, Gid, Mode, OFlags, RenameFlags, Uid, fchmod, fchown, mkdirat, openat,
    renameat_with, statat, unlinkat,
};
use serde_json::{Value, json};
use std::{
    fs::File,
    io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    time::UNIX_EPOCH,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const METADATA_LIMIT: usize = 60000;
fn normalize(value: &str, root: bool) -> io::Result<String> {
    sdk_fs::normalized(value, root).map_err(|_| invalid("INVALID_PATH"))
}
fn directory(root: &File, path: &str) -> io::Result<File> {
    let mut dir = root.try_clone()?;
    if path != "." {
        for name in path.split('/') {
            dir = sandcrab_core::transfer::dir(&dir, name)?;
        }
    }
    Ok(dir)
}
fn node(root: &File, path: &str) -> io::Result<File> {
    if path == "." {
        return root.try_clone();
    }
    let (parent, name) = file_io::parent(root, path, false)?;
    Ok(File::from(openat(
        &parent,
        &name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?))
}
fn names(dir: &File) -> io::Result<Vec<String>> {
    let (mut names, mut bytes) = (Vec::new(), 0usize);
    for entry in rustix::fs::Dir::read_from(dir)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| invalid("INVALID_PATH"))?;
        if matches!(name, "." | "..") {
            continue;
        }
        bytes += name.len();
        if names.len() >= 10000 || bytes > METADATA_LIMIT {
            return Err(invalid("FILE_ENTRY_LIMIT"));
        }
        names.push(name.to_owned());
    }
    names.sort();
    Ok(names)
}
fn timestamp(nanos: i128) -> io::Result<String> {
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|_| invalid("FILE_METADATA_UNAVAILABLE"))?
        .format(&Rfc3339)
        .map_err(|_| invalid("FILE_METADATA_UNAVAILABLE"))
}
fn info(root: &File, path: &str) -> io::Result<Value> {
    let metadata = node(root, path)?.metadata()?;
    let kind = metadata.file_type();
    let created = metadata
        .created()
        .map(|t| match t.duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_nanos() as i128,
            Err(error) => -(error.duration().as_nanos() as i128),
        })
        .unwrap_or_else(|_| {
            i128::from(metadata.ctime()) * 1_000_000_000 + i128::from(metadata.ctime_nsec())
        });
    Ok(
        json!({"path":if path == "." { "/workspace".into() } else { format!("/workspace/{path}") },
        "type":if kind.is_symlink() { "symlink" } else if kind.is_dir() { "directory" }
            else if kind.is_file() { "file" } else { "other" },
        "size":if kind.is_dir() { 0 } else { metadata.len() },"mode":format!("{:o}", metadata.permissions().mode() & 0o7777).parse::<u32>().unwrap(),
        "owner":metadata.uid().to_string(),"group":metadata.gid().to_string(),
        "modified_at":timestamp(i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec()))?,
        "created_at":timestamp(created)?}),
    )
}
fn bounded(value: &Value) -> io::Result<usize> {
    let bytes = serde_json::to_vec(value)?.len();
    if bytes > METADATA_LIMIT {
        return Err(invalid("FILE_METADATA_LIMIT"));
    }
    Ok(bytes)
}
fn listing(
    root: &File,
    path: &str,
    depth: usize,
    output: &mut Vec<Value>,
    bytes: &mut usize,
) -> io::Result<()> {
    let dir = directory(root, path)?;
    if depth == 0 {
        return Ok(());
    }
    for name in names(&dir)? {
        let child = if path == "." {
            name
        } else {
            format!("{path}/{name}")
        };
        if !file_io::valid_path(&child, false) {
            return Err(invalid("INVALID_PATH"));
        }
        let value = info(root, &child)?;
        let descend = value["type"] == "directory";
        *bytes += bounded(&value)? + 1;
        if *bytes > METADATA_LIMIT || output.len() >= 10000 {
            return Err(invalid("FILE_METADATA_LIMIT"));
        }
        output.push(value);
        if descend && depth > 1 {
            listing(root, &child, depth - 1, output, bytes)?;
        }
    }
    Ok(())
}
fn searching(
    root: &File,
    path: &str,
    glob: &crate::sdk_glob::Glob,
    depth: usize,
    visited: &mut usize,
    output: &mut Vec<Value>,
    bytes: &mut usize,
) -> io::Result<()> {
    *visited += 1;
    if *visited > 10000 || depth > 64 {
        return Err(invalid("FILE_ENTRY_LIMIT"));
    }
    if !file_io::valid_path(path, true) {
        return Err(invalid("INVALID_PATH"));
    }
    if node(root, path)?.metadata()?.is_dir() {
        for name in names(&directory(root, path)?)? {
            let child = if path == "." {
                name
            } else {
                format!("{path}/{name}")
            };
            searching(root, &child, glob, depth + 1, visited, output, bytes)?;
        }
    } else if glob.matches(path.rsplit('/').next().unwrap()) {
        let value = info(root, path)?;
        *bytes += bounded(&value)? + 1;
        if *bytes > METADATA_LIMIT {
            return Err(invalid("FILE_METADATA_LIMIT"));
        }
        output.push(value);
    }
    Ok(())
}
fn make_directory(
    root: &File,
    path: &str,
    mode: u32,
    job: &Job,
    apply: bool,
    attempted: &mut bool,
) -> io::Result<()> {
    let mut dir = root.try_clone()?;
    if path == "." {
        return Ok(());
    }
    for name in path.split('/') {
        let child = match sandcrab_core::transfer::dir(&dir, name) {
            Ok(child) => child,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if !apply {
                    return Ok(());
                }
                *attempted = true;
                mkdirat(&dir, name, Mode::from_raw_mode(0o700))?;
                let child = sandcrab_core::transfer::dir(&dir, name)?;
                fchown(
                    &child,
                    Some(Uid::from_raw(job.uid)),
                    Some(Gid::from_raw(job.gid)),
                )?;
                fchmod(&child, Mode::from_raw_mode(mode))?;
                child.sync_all()?;
                dir.sync_all()?;
                child
            }
            Err(error) => return Err(error),
        };
        dir = child;
    }
    Ok(())
}
fn permissions(root: &File, path: &str) -> io::Result<File> {
    let metadata = node(root, path)?.metadata()?;
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(invalid("NOT_REGULAR_FILE"));
    }
    if path == "." {
        return root.try_clone();
    }
    let (parent, name) = file_io::parent(root, path, false)?;
    Ok(File::from(openat(
        &parent,
        &name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?))
}
fn move_check(root: &File, src: &str, dest: &str) -> io::Result<()> {
    let source = node(root, src)?.metadata()?;
    let (parent, name) = file_io::parent(root, dest, false)?;
    match statat(&parent, &name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(target) => {
            let directory = FileType::from_raw_mode(target.st_mode) == FileType::Directory;
            if source.is_dir() != directory {
                return Err(invalid("NOT_DIRECTORY"));
            }
            if directory && src != dest && !names(&self::directory(root, dest)?)?.is_empty() {
                return Err(invalid("PATH_EXISTS"));
            }
        }
        Err(rustix::io::Errno::NOENT) => (),
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
fn tree_check(dir: &File, count: &mut usize, depth: usize) -> io::Result<()> {
    if depth > 64 {
        return Err(invalid("FILE_ENTRY_LIMIT"));
    }
    for name in names(dir)? {
        *count += 1;
        if *count > 10000 {
            return Err(invalid("FILE_ENTRY_LIMIT"));
        }
        let metadata = statat(dir, &name, AtFlags::SYMLINK_NOFOLLOW)?;
        if FileType::from_raw_mode(metadata.st_mode) == FileType::Directory {
            tree_check(&sandcrab_core::transfer::dir(dir, &name)?, count, depth + 1)?;
        }
    }
    Ok(())
}
fn remove_tree(parent: &File, name: &str) -> io::Result<()> {
    let dir = sandcrab_core::transfer::dir(parent, name)?;
    for child in names(&dir)? {
        let metadata = statat(&dir, &child, AtFlags::SYMLINK_NOFOLLOW)?;
        if FileType::from_raw_mode(metadata.st_mode) == FileType::Directory {
            remove_tree(&dir, &child)?;
        } else {
            unlinkat(&dir, &child, AtFlags::empty())?;
        }
    }
    dir.sync_all()?;
    unlinkat(parent, name, AtFlags::REMOVEDIR)?;
    parent.sync_all()
}
fn apply(job: &Job, root: &File, request: &Request, attempted: &mut bool) -> io::Result<Value> {
    match request {
        Request::Search { path, pattern } => {
            let glob = crate::sdk_glob::Glob::new(pattern)?;
            let mut values = Vec::new();
            searching(
                root,
                &normalize(path, true)?,
                &glob,
                0,
                &mut 0,
                &mut values,
                &mut 2,
            )?;
            return Ok(Value::Array(values));
        }
        Request::Replace { entries, verbose } => {
            let (counts, changed) = crate::sdk_replace::stage(job, entries)?;
            let value = if *verbose { counts } else { Value::Null };
            bounded(&value)?;
            if changed {
                crate::sdk_file_io::publish(job, attempted)?;
            }
            return Ok(value);
        }
        Request::Info { paths } => {
            let mut values = serde_json::Map::new();
            let mut bytes = 2;
            for original in paths {
                let value = info(root, &normalize(original, true)?)?;
                bytes += bounded(&value)? + serde_json::to_vec(original)?.len() + 2;
                if bytes > METADATA_LIMIT {
                    return Err(invalid("FILE_METADATA_LIMIT"));
                }
                values.insert(original.clone(), value);
            }
            return Ok(Value::Object(values));
        }
        Request::List { path, depth } => {
            let mut values = Vec::new();
            listing(root, &normalize(path, true)?, *depth, &mut values, &mut 2)?;
            return Ok(Value::Array(values));
        }
        Request::Mkdir { entries } => {
            let mut ordered = entries
                .iter()
                .map(|entry| Ok((normalize(&entry.path, true)?, entry.mode)))
                .collect::<io::Result<Vec<_>>>()?;
            ordered.sort();
            for (path, mode) in &ordered {
                make_directory(root, path, *mode, job, false, attempted)?;
            }
            for (path, mode) in &ordered {
                make_directory(root, path, *mode, job, true, attempted)?;
            }
        }
        Request::Chmod { entries } => {
            let files = entries
                .iter()
                .map(|entry| permissions(root, &normalize(&entry.path, true)?))
                .collect::<io::Result<Vec<_>>>()?;
            for (file, entry) in files.iter().zip(entries) {
                *attempted = true;
                fchmod(file, Mode::from_raw_mode(entry.mode))?;
                file.sync_all()?;
            }
        }
        Request::Move { entries } => {
            for entry in entries {
                move_check(
                    root,
                    &normalize(&entry.src, false)?,
                    &normalize(&entry.dest, false)?,
                )?;
            }
            for entry in entries {
                let src = normalize(&entry.src, false)?;
                let dest = normalize(&entry.dest, false)?;
                if src == dest {
                    continue;
                }
                let (from, name) = file_io::parent(root, &src, false)?;
                let (to, target) = file_io::parent(root, &dest, false)?;
                *attempted = true;
                renameat_with(&from, &name, &to, &target, RenameFlags::empty())?;
                from.sync_all()?;
                to.sync_all()?;
            }
        }
        Request::Remove {
            paths,
            directory: directories,
        } => {
            let mut count = 0;
            for path in paths {
                let path = normalize(path, false)?;
                if *directories {
                    tree_check(&directory(root, &path)?, &mut count, 0)?;
                } else if node(root, &path)?.metadata()?.is_dir() {
                    return Err(invalid("NOT_REGULAR_FILE"));
                }
            }
            for path in paths {
                let (parent, name) = file_io::parent(root, &normalize(path, false)?, false)?;
                *attempted = true;
                if *directories {
                    remove_tree(&parent, &name)?;
                } else {
                    unlinkat(&parent, &name, AtFlags::empty())?;
                    parent.sync_all()?;
                }
            }
        }
    }
    Ok(Value::Null)
}
pub fn execute(job: &Job) -> io::Result<Value> {
    let input = sandcrab_core::fs::protected_file(&job.stage.join("request.json"), 65536)?;
    let request: Request = serde_json::from_slice(&input)?;
    request.validate().map_err(|_| invalid("INVALID_PATH"))?;
    if request.mutation() != (job.action == "sdk-mutate") {
        return Err(invalid("Invalid file operation authority"));
    }
    let root = file_io::directory(&job.workspace)?;
    let mut attempted = false;
    let result = apply(job, &root, &request, &mut attempted);
    match result {
        Ok(value) => {
            bounded(&value)?;
            Ok(value)
        }
        Err(_) if attempted => Err(invalid("FILE_OPERATION_UNKNOWN")),
        error => error,
    }
}
