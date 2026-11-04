//! Sealed workload filters and the inherited bootstrap filter for verified bubblewrap.
use super::Error;
use rustix::{
    fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create},
    io::{FdFlags, fcntl_setfd},
};
use std::{
    fs::File,
    io::{Seek, SeekFrom, Write},
    os::fd::{AsRawFd, RawFd},
};

include!(concat!(env!("OUT_DIR"), "/filter.rs"));

/// Own the immutable filter descriptor until bubblewrap consumes it at exec.
/// Creating it does not install a filter in the caller.
#[derive(Debug)]
pub struct Seccomp(File);

impl Seccomp {
    pub fn new() -> Result<Self, Error> {
        Self::from_program(WORKLOAD_FILTER)
    }

    /// Only the authenticated, fixed overlay exporter may clone its mount.
    pub fn for_overlay_export() -> Result<Self, Error> {
        Self::from_program(OVERLAY_EXPORT_FILTER)
    }

    fn from_program(program: &[seccompiler::sock_filter]) -> Result<Self, Error> {
        let descriptor = memfd_create(
            c"sandcrab-seccomp",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .map_err(std::io::Error::from)?;
        let mut file = File::from(descriptor);
        for op in program {
            file.write_all(&op.code.to_le_bytes())?;
            file.write_all(&[op.jt, op.jf])?;
            file.write_all(&op.k.to_le_bytes())?;
        }
        file.seek(SeekFrom::Start(0))?;
        fcntl_add_seals(
            &file,
            SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE,
        )
        .map_err(std::io::Error::from)?;
        Ok(Self(file))
    }

    pub(crate) fn descriptor(&self) -> RawFd {
        self.0.as_raw_fd()
    }

    pub(crate) fn prepare_exec(&self) -> Result<(), Error> {
        // bwrap applies --seccomp independently in its reaper and workload after
        // forking. Keep the base rules active during privileged setup. A workload must
        // never be able to trace an unfiltered reaper during that startup window.
        seccompiler::apply_filter(BOOTSTRAP_FILTER)
            .map_err(|error| Error(format!("Sandbox seccomp installation failed: {error}")))?;
        fcntl_setfd(&self.0, FdFlags::empty()).map_err(std::io::Error::from)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
