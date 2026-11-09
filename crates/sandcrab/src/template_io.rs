//! Template identities describe normalized trees, including modes and hard-link
//! topology. Archive ordering, compression metadata and timestamps do not affect them.
use crate::{config::invalid, file_io::Job};
use rustix::fs::{AtFlags, FileType, statat};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::Path,
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Tree {
    pub id: String,
    pub uid: u32,
    pub gid: u32,
    pub bytes: u64,
    pub allocated_bytes: u64,
    pub entries: usize,
}

fn field(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_le_bytes());
    hash.update(value);
}

struct Scan {
    hash: Sha256,
    links: BTreeMap<(u64, u64), String>,
    bytes: u64,
    allocated_bytes: u64,
    entries: usize,
    normalize: bool,
}

impl Scan {
    fn visit(&mut self, dir: &File, prefix: &str, job: &Job) -> io::Result<()> {
        let mut names = rustix::fs::Dir::read_from(dir)?
            .filter_map(|entry| match entry {
                Ok(entry) if [c".", c".."].contains(&entry.file_name()) => None,
                result => Some(result.map(|entry| entry.file_name().to_owned())),
            })
            .collect::<Result<Vec<_>, _>>()?;
        names.sort();
        for name in names {
            let name = name.to_str().map_err(|_| invalid("INVALID_PATH"))?;
            let path = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            if !crate::file_io::valid_path(&path, false) {
                return Err(invalid("INVALID_PATH"));
            }
            self.entries += 1;
            if self.entries > job.entry_limit {
                return Err(invalid("FILE_ENTRY_LIMIT"));
            }
            let meta = statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
            if !self.normalize && (meta.st_uid != job.uid || meta.st_gid != job.gid) {
                return Err(invalid("UNSUPPORTED_FILE_OWNER"));
            }
            field(&mut self.hash, path.as_bytes());
            self.hash.update((meta.st_mode & 0o777).to_le_bytes());
            match FileType::from_raw_mode(meta.st_mode) {
                FileType::Directory => {
                    self.allocate(meta.st_blocks)?;
                    self.hash.update(b"d");
                    self.visit(&sandcrab_core::transfer::dir(dir, name)?, &path, job)?;
                }
                FileType::RegularFile => {
                    let inode = (meta.st_dev, meta.st_ino);
                    if let Some(target) = self.links.get(&inode) {
                        self.hash.update(b"h");
                        field(&mut self.hash, target.as_bytes());
                        continue;
                    }
                    self.links.insert(inode, path);
                    self.allocate(meta.st_blocks)?;
                    let mut file = crate::file_io::regular(dir, name)?;
                    let size = file.metadata()?.len();
                    self.bytes = self
                        .bytes
                        .checked_add(size)
                        .ok_or_else(|| invalid("FILE_LIMIT"))?;
                    if self.bytes > job.byte_limit {
                        return Err(invalid("FILE_LIMIT"));
                    }
                    self.hash.update(b"f");
                    self.hash.update(size.to_le_bytes());
                    let mut content = Sha256::new();
                    let mut buffer = [0u8; 32768];
                    let mut copied = 0u64;
                    loop {
                        let count = file.read(&mut buffer)?;
                        if count == 0 {
                            break;
                        }
                        copied += count as u64;
                        if copied > size {
                            return Err(invalid("FILE_CHANGED"));
                        }
                        content.update(&buffer[..count]);
                    }
                    if copied != size {
                        return Err(invalid("FILE_CHANGED"));
                    }
                    self.hash.update(content.finalize());
                }
                FileType::Symlink => {
                    self.allocate(meta.st_blocks)?;
                    self.hash.update(b"s");
                    let target = rustix::fs::readlinkat(dir, name, Vec::new())?;
                    field(&mut self.hash, target.as_bytes());
                }
                _ => return Err(invalid("UNSUPPORTED_ARCHIVE_ENTRY")),
            }
        }
        Ok(())
    }

    fn allocate(&mut self, blocks: i64) -> io::Result<()> {
        let blocks = u64::try_from(blocks).map_err(|_| invalid("FILE_LIMIT"))?;
        self.allocated_bytes = blocks
            .checked_mul(512)
            .and_then(|bytes| self.allocated_bytes.checked_add(bytes))
            .ok_or_else(|| invalid("FILE_LIMIT"))?;
        Ok(())
    }
}

pub fn identify(root: &Path, job: &Job) -> io::Result<Tree> {
    identify_tree(root, job, false)
}

/// Predict import identity while the source is frozen; imports normalize owners
/// and the root mode but preserve supported entry modes and hard-link topology.
pub fn identify_capture(root: &Path, job: &Job) -> io::Result<Tree> {
    identify_tree(root, job, true)
}

fn identify_tree(root: &Path, job: &Job, normalize: bool) -> io::Result<Tree> {
    let directory = crate::file_io::directory(root)?;
    let meta = directory.metadata()?;
    if !normalize && (meta.uid() != job.uid || meta.gid() != job.gid) {
        return Err(invalid("UNSUPPORTED_FILE_OWNER"));
    }
    let mut scan = Scan {
        hash: Sha256::new(),
        links: BTreeMap::new(),
        bytes: 0,
        allocated_bytes: meta
            .blocks()
            .checked_mul(512)
            .ok_or_else(|| invalid("FILE_LIMIT"))?,
        entries: 0,
        normalize,
    };
    scan.hash.update(b"sandcrab-template-tree-v1\0");
    scan.hash.update(job.uid.to_le_bytes());
    scan.hash.update(job.gid.to_le_bytes());
    scan.hash.update(
        (if normalize {
            0o755
        } else {
            meta.mode() & 0o777
        })
        .to_le_bytes(),
    );
    scan.visit(&directory, "", job)?;
    Ok(Tree {
        id: format!("{:x}", scan.hash.finalize()),
        uid: job.uid,
        gid: job.gid,
        bytes: scan.bytes,
        allocated_bytes: scan.allocated_bytes,
        entries: scan.entries,
    })
}

pub fn receive(job: &Job) -> io::Result<serde_json::Value> {
    crate::file_io::receive(job, false)?;
    let tree = identify(&job.stage.join("tree"), job)?;
    // The archive is transport staging; the normalized tree is the stored object.
    fs::remove_file(job.stage.join("content"))?;
    Ok(serde_json::to_value(tree)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_io::Format;
    use std::{
        io::Write,
        os::unix::fs::{PermissionsExt, symlink},
    };

    #[test]
    fn identity_covers_contents_modes_links_and_execution_identity() {
        let root = Path::new("/source").join(format!(
            "template-tree-{}",
            sandcrab_core::new_uuid().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let job = Job {
            action: "template-receive".into(),
            workspace: root.join("unused"),
            stage: root.clone(),
            path: "data".into(),
            format: Format::Tar,
            bytes: 0,
            sha256: String::new(),
            replace: false,
            mode: 0o755,
            uid: 65534,
            gid: 65534,
            byte_limit: 1024,
            entry_limit: 8,
            multipart: None,
            selection: None,
        };
        let mut archive = tar::Builder::new(File::create(root.join("content")).unwrap());
        for (name, bytes) in [("z", b"same"), ("a", b"same")] {
            let mut header = tar::Header::new_ustar();
            header.set_size(4);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(&mut header, name, bytes.as_slice())
                .unwrap();
        }
        archive.finish().unwrap();
        crate::file_io::unpack(&job).unwrap();
        let tree = root.join("tree");
        let first = identify(&tree, &job).unwrap();
        assert_eq!((first.bytes, first.entries), (8, 2));
        fs::set_permissions(&tree, fs::Permissions::from_mode(0o750)).unwrap();
        rustix::fs::chown(
            &tree,
            Some(rustix::fs::Uid::ROOT),
            Some(rustix::fs::Gid::ROOT),
        )
        .unwrap();
        assert!(identify(&tree, &job).is_err());
        assert_eq!(identify_capture(&tree, &job).unwrap().id, first.id);
        crate::file_io::ownership(&crate::file_io::directory(&tree).unwrap(), &job, 0o755).unwrap();
        fs::remove_file(tree.join("z")).unwrap();
        fs::hard_link(tree.join("a"), tree.join("z")).unwrap();
        let linked = identify(&tree, &job).unwrap();
        assert_ne!(first.id, linked.id);
        assert_eq!(linked.bytes, 4);
        fs::set_permissions(tree.join("a"), fs::Permissions::from_mode(0o755)).unwrap();
        assert_ne!(identify(&tree, &job).unwrap().id, linked.id);
        File::options()
            .append(true)
            .open(tree.join("a"))
            .unwrap()
            .write_all(b"!")
            .unwrap();
        assert_eq!(identify(&tree, &job).unwrap().bytes, 5);
        symlink("/must-not-be-followed", tree.join("outside")).unwrap();
        rustix::fs::chownat(
            rustix::fs::CWD,
            tree.join("outside"),
            Some(rustix::fs::Uid::from_raw(job.uid)),
            Some(rustix::fs::Gid::from_raw(job.gid)),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .unwrap();
        assert_eq!(identify(&tree, &job).unwrap().entries, 3);
        let mut limited = job;
        limited.byte_limit = 4;
        assert!(identify(&tree, &limited).is_err());
        limited.byte_limit = 1024;
        limited.entry_limit = 2;
        assert!(identify(&tree, &limited).is_err());
        limited.entry_limit = 8;
        limited.uid = 65533;
        assert!(identify(&tree, &limited).is_err());
        assert_eq!(root.parent(), Some(Path::new("/source")));
        fs::remove_dir_all(root).unwrap();
    }
}
