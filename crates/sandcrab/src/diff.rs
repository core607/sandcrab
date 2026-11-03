//! Translate a protected overlay upper into a bounded tar changeset.
use crate::config::invalid;
use rustix::fs::fgetxattr;
use std::{
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
};

pub fn upper(stage: &Path) -> io::Result<PathBuf> {
    let session = stage
        .parent()
        .ok_or_else(|| invalid("Invalid diff stage"))?;
    let workspaces = session
        .parent()
        .ok_or_else(|| invalid("Invalid diff stage"))?;
    let runtime = workspaces
        .parent()
        .ok_or_else(|| invalid("Invalid diff stage"))?;
    let id = session
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| sandcrab_core::uuid(s))
        .ok_or_else(|| invalid("Invalid diff session"))?;
    if workspaces.file_name().and_then(|s| s.to_str()) != Some("workspaces") {
        return Err(invalid("Invalid diff workspace"));
    }
    Ok(runtime.join("workspace-overlays").join(id).join("upper"))
}

fn attribute(file: &File, name: &str) -> io::Result<Option<Vec<u8>>> {
    let mut value = [0u8; 64];
    match fgetxattr(file, name, &mut value[..]) {
        Ok(length) => Ok(Some(value[..length].to_vec())),
        Err(rustix::io::Errno::NODATA) => Ok(None),
        Err(rustix::io::Errno::RANGE) => Err(invalid("UNSUPPORTED_OVERLAY_METADATA")),
        Err(error) => Err(error.into()),
    }
}

pub struct Metadata {
    pub opaque: bool,
    pub whiteout: bool,
}

pub fn metadata(file: &File) -> io::Result<Metadata> {
    let mut result = Metadata {
        opaque: false,
        whiteout: false,
    };
    // Bundled bwrap mounts with userxattr. Also recognize the privileged form
    // when visible; neither redirect nor metadata-only copies contain a delta.
    for prefix in ["user.overlay.", "trusted.overlay."] {
        for suffix in ["redirect", "metacopy"] {
            if attribute(file, &format!("{prefix}{suffix}"))?.is_some() {
                return Err(invalid("UNSUPPORTED_OVERLAY_METADATA"));
            }
        }
        if let Some(value) = attribute(file, &format!("{prefix}opaque"))? {
            match value.as_slice() {
                b"y" => result.opaque = true,
                // The x marker accelerates regular-file whiteout lookup; it
                // does not hide all lower children like an opaque directory.
                b"x" => (),
                _ => return Err(invalid("UNSUPPORTED_OVERLAY_METADATA")),
            }
        }
        result.whiteout |= attribute(file, &format!("{prefix}whiteout"))?.is_some();
    }
    Ok(result)
}

pub fn marker<W: Write>(tar: &mut tar::Builder<W>, path: &str) -> io::Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mode(0);
    header.set_mtime(0);
    header.set_size(0);
    header.set_cksum();
    tar.append_data(&mut header, path, io::empty())
}
