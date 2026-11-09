//! Explicit deletion layers translate empty tar markers inside private staging.
//! Only this fixed helper receives CAP_MKNOD; archives never supply device nodes.
use crate::{
    config::invalid,
    file_io::{self, Job},
};
use rustix::fs::{
    AtFlags, FileType, Gid, Mode, Uid, XattrFlags, chownat, fgetxattr, fsetxattr, mknodat, statat,
    unlinkat,
};
use std::{fs::File, io};

pub fn opaque(directory: &File) -> io::Result<bool> {
    let mut value = [0u8; 1];
    match fgetxattr(directory, "user.overlay.opaque", &mut value[..]) {
        Ok(1) if value == *b"y" => Ok(true),
        Err(rustix::io::Errno::NODATA | rustix::io::Errno::NOTSUP) => Ok(false),
        Ok(_) => Err(invalid("INVALID_LAYER_WHITEOUT")),
        Err(error) => Err(error.into()),
    }
}

fn mark_opaque(directory: &File) -> io::Result<()> {
    fsetxattr(directory, "user.overlay.opaque", b"y", XattrFlags::empty())?;
    directory.sync_all()
}

fn markers(
    directory: &File,
    prefix: &str,
    paths: &mut Vec<String>,
    limit: usize,
) -> io::Result<()> {
    for entry in rustix::fs::Dir::read_from(directory)? {
        let entry = entry?;
        if [c".", c".."].contains(&entry.file_name()) {
            continue;
        }
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| invalid("INVALID_PATH"))?;
        let path = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        if !file_io::valid_path(&path, false) {
            return Err(invalid("INVALID_PATH"));
        }
        let meta = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
        let kind = FileType::from_raw_mode(meta.st_mode);
        if let Some(target) = name.strip_prefix(".wh.") {
            if kind != FileType::RegularFile
                || meta.st_size != 0
                || meta.st_nlink != 1
                || (name != ".wh..wh..opq"
                    && (!file_io::valid_path(target, false) || target.starts_with(".wh.")))
            {
                return Err(invalid("INVALID_LAYER_WHITEOUT"));
            }
            paths.push(path);
            if paths.len() > limit {
                return Err(invalid("FILE_ENTRY_LIMIT"));
            }
        } else if kind == FileType::Directory {
            markers(
                &sandcrab_core::transfer::dir(directory, name)?,
                &path,
                paths,
                limit,
            )?;
        }
    }
    Ok(())
}

pub fn convert(job: &Job) -> io::Result<()> {
    let root = file_io::directory(&job.stage.join("tree"))?;
    let mut paths = Vec::new();
    markers(&root, "", &mut paths, job.entry_limit)?;
    // First validate every marker. Same-layer additions always survive deletions,
    // independent of tar order; recreated directories hide their old children.
    for path in paths {
        let (parent, name) = file_io::parent(&root, &path, false)?;
        unlinkat(&parent, &name, AtFlags::empty())?;
        if name == ".wh..wh..opq" {
            mark_opaque(&parent)?;
        } else {
            let target = name.strip_prefix(".wh.").unwrap();
            match statat(&parent, target, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(info) if FileType::from_raw_mode(info.st_mode) == FileType::Directory => {
                    mark_opaque(&sandcrab_core::transfer::dir(&parent, target)?)?;
                }
                Ok(_) => (),
                Err(rustix::io::Errno::NOENT) => {
                    mknodat(&parent, target, FileType::CharacterDevice, Mode::empty(), 0)?;
                    chownat(
                        &parent,
                        target,
                        Some(Uid::from_raw(job.uid)),
                        Some(Gid::from_raw(job.gid)),
                        AtFlags::SYMLINK_NOFOLLOW,
                    )?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        parent.sync_all()?;
    }
    root.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::Path};

    #[test]
    fn translation_preserves_same_layer_additions_and_hashes_deletion_semantics() {
        let stage = Path::new("/source").join(format!(
            "template-layer-{}",
            sandcrab_core::new_uuid().unwrap()
        ));
        fs::create_dir(&stage).unwrap();
        let job = Job {
            action: "template-layer-receive".into(),
            workspace: stage.join("unused"),
            stage: stage.clone(),
            path: "data".into(),
            format: file_io::Format::Tar,
            bytes: 0,
            sha256: String::new(),
            replace: false,
            mode: 0o755,
            uid: 65534,
            gid: 65534,
            byte_limit: 65536,
            entry_limit: 32,
            multipart: None,
            selection: None,
        };
        let mut archive = tar::Builder::new(File::create(stage.join("content")).unwrap());
        for (name, value) in [
            (".wh.reborn", ""),
            ("reborn/new", "new"),
            ("opaque/.wh..wh..opq", ""),
            ("opaque/new", "new"),
            (".wh.replaced", ""),
            ("replaced", "replacement"),
        ] {
            let mut header = tar::Header::new_ustar();
            header.set_size(value.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(&mut header, name, value.as_bytes())
                .unwrap();
        }
        archive.finish().unwrap();
        file_io::unpack(&job).unwrap();
        convert(&job).unwrap();
        let tree = stage.join("tree");
        assert_eq!(fs::read(tree.join("replaced")).unwrap(), b"replacement");
        for name in ["reborn", "opaque"] {
            assert!(opaque(&file_io::directory(&tree.join(name)).unwrap()).unwrap());
        }
        let original = crate::template_io::identify_layer(&tree, &job).unwrap();
        assert_ne!(
            crate::template_io::identify(&tree, &job).unwrap().id,
            original.id
        );
        rustix::fs::fremovexattr(
            file_io::directory(&tree.join("opaque")).unwrap(),
            "user.overlay.opaque",
        )
        .unwrap();
        assert_ne!(
            crate::template_io::identify_layer(&tree, &job).unwrap().id,
            original.id
        );
        fs::remove_file(tree.join("replaced")).unwrap();
        assert_ne!(
            crate::template_io::identify_layer(&tree, &job).unwrap().id,
            original.id
        );
        assert_eq!(stage.parent(), Some(Path::new("/source")));
        fs::remove_dir_all(stage).unwrap();
    }
}
