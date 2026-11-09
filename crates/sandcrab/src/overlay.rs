//! A fixed bwrap helper creates one overlay and transfers a detached mount into
//! the daemon's private namespace. Workload contexts only bind that shared view.
use crate::{
    config::{Profile, invalid},
    helper,
    runtime::SetupError,
};
use rustix::{
    fd::{AsFd, OwnedFd},
    fs::CWD,
    mount::{MoveMountFlags, OpenTreeFlags, UnmountFlags, move_mount, open_tree, unmount},
    net::{
        RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
        SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
    },
};
use sandcrab_core::{
    fs::{normal, protected_directory},
    job,
    process::Input,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{self, IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::UnixDatagram,
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

const VIEW: &str = "/sandcrab-overlay";
const PACKET: &[u8] = b"sandcrab-overlay-v1";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub lower: Vec<PathBuf>,
    pub upper: PathBuf,
    pub work: PathBuf,
}
impl Spec {
    pub fn arguments(&self) -> io::Result<Vec<String>> {
        if self.lower.is_empty() || self.lower.len() > crate::recipes::MAX_LAYERS {
            return Err(invalid("Invalid overlay layer count"));
        }
        for path in self.lower.iter().chain([&self.upper, &self.work]) {
            protected_directory(path)?;
        }
        if self.upper.parent() != self.work.parent()
            || self.upper == self.work
            || self.lower.iter().enumerate().any(|(index, lower)| {
                [&self.upper, &self.work]
                    .into_iter()
                    .chain(self.lower[..index].iter())
                    .any(|other| lower.starts_with(other) || other.starts_with(lower))
            })
        {
            return Err(invalid("Invalid overlay directories"));
        }
        let mut arguments = vec!["--cap-add".into(), "CAP_SYS_ADMIN".into()];
        for lower in &self.lower {
            arguments.extend(["--overlay-src".into(), lower.to_string_lossy().into()]);
        }
        arguments.extend([
            "--overlay".into(),
            self.upper.to_string_lossy().into(),
            self.work.to_string_lossy().into(),
            VIEW.into(),
        ]);
        Ok(arguments)
    }
}

/// Internal entry only: its privileged operation is fixed to the bwrap-created
/// view and inherited root socket, never a caller-selected path or executable.
pub fn export() -> io::Result<()> {
    let socket = io::stdin();
    if !rustix::process::geteuid().is_root()
        || rustix::net::sockopt::socket_type(&socket)? != rustix::net::SocketType::DGRAM
    {
        return Err(invalid("Invalid overlay export channel"));
    }
    // The launcher authenticates this inherited channel before bwrap unshares
    // PID. Here its outside peer has PID 0, which rustix UCred cannot represent.
    let view = open_tree(
        CWD,
        VIEW,
        OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC,
    )?;
    let fds = [view.as_fd()];
    let mut buffer = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut buffer);
    if !ancillary.push(SendAncillaryMessage::ScmRights(&fds)) {
        return Err(invalid("Overlay descriptor buffer is too small"));
    }
    if sendmsg(
        &socket,
        &[IoSlice::new(PACKET)],
        &mut ancillary,
        SendFlags::NOSIGNAL,
    )? != PACKET.len()
    {
        return Err(invalid("Incomplete overlay descriptor publication"));
    }
    let mut ack = [0u8; 1];
    let received = rustix::net::recv(&socket, &mut ack, RecvFlags::TRUNC)?;
    if received != (1, 1) || ack != *b"x" {
        return Err(invalid("Overlay mount was not acknowledged"));
    }
    Ok(())
}

fn receive(socket: &UnixDatagram) -> io::Result<OwnedFd> {
    let mut packet = [0u8; 64];
    let mut buffer = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut buffer);
    let result = recvmsg(
        socket,
        &mut [IoSliceMut::new(&mut packet)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )?;
    if result
        .flags
        .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || result.bytes != PACKET.len()
        || &packet[..result.bytes] != PACKET
    {
        return Err(invalid("Invalid overlay mount packet"));
    }
    let mut view = None;
    for message in ancillary.drain() {
        let RecvAncillaryMessage::ScmRights(fds) = message else {
            return Err(invalid("Unexpected overlay control message"));
        };
        for fd in fds {
            if view.replace(fd).is_some() {
                return Err(invalid("Unexpected extra overlay descriptor"));
            }
        }
    }
    let fd = view.ok_or_else(|| invalid("Missing overlay descriptor"))?;
    if rustix::fs::fstatfs(&fd)?.f_type as u64 != 0x794c7630 {
        return Err(invalid("Exported view is not overlayfs"));
    }
    Ok(fd)
}

pub struct Mount {
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl Mount {
    pub fn release(&self) -> io::Result<()> {
        protected_directory(&self.path)?;
        let metadata = fs::symlink_metadata(&self.path)?;
        if !sandcrab_core::fs::mounted(&self.path)?
            || (metadata.dev(), metadata.ino()) != (self.device, self.inode)
        {
            return Err(invalid("Owned overlay mount changed"));
        }
        crate::storage::no_mounts_below(&self.path, true)?;
        unmount(&self.path, UnmountFlags::empty())?;
        Ok(())
    }
}

pub fn create(
    context: &helper::Context<'_>,
    profile: &Profile,
    cancelled: &AtomicBool,
    spec: Spec,
    target: &Path,
) -> Result<Mount, SetupError> {
    if !normal(target) {
        return Err(invalid("Invalid overlay mount target").into());
    }
    protected_directory(target)?;
    crate::storage::no_mounts_below(target, false)?;
    let (socket, child) = UnixDatagram::pair()?;
    socket.set_read_timeout(Some(Duration::from_millis(50)))?;
    socket.set_write_timeout(Some(Duration::from_secs(1)))?;
    let id = sandcrab_core::new_uuid()?;
    let interrupt = AtomicBool::new(false);
    thread::scope(|scope| {
        let worker = thread::Builder::new()
            .spawn_scoped(scope, || {
                context.run(
                    profile,
                    &interrupt,
                    Input::File(File::from(OwnedFd::from(child))),
                    helper::Request {
                        kind: "overlay",
                        id: &id,
                        argv: vec![
                            context.executable.to_string_lossy().into(),
                            "__overlay-export".into(),
                        ],
                        read_only: Vec::new(),
                        writable: Vec::new(),
                        overlay: Some(spec),
                        timeout: Duration::from_secs(15),
                        output_limit: 16384,
                    },
                )
            })
            .map_err(SetupError::from)?;
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut attached = false;
        let result = (|| -> io::Result<Mount> {
            let fd = loop {
                if cancelled.load(Ordering::SeqCst) || Instant::now() >= deadline {
                    return Err(invalid("Overlay setup cancelled or timed out"));
                }
                match receive(&socket) {
                    Ok(fd) => break fd,
                    Err(error)
                        if [
                            io::ErrorKind::WouldBlock,
                            io::ErrorKind::TimedOut,
                            io::ErrorKind::Interrupted,
                        ]
                        .contains(&error.kind()) =>
                    {
                        if worker.is_finished() {
                            return Err(invalid("Overlay helper exited before exporting a mount"));
                        }
                    }
                    Err(error) => return Err(error),
                }
            };
            move_mount(
                &fd,
                "",
                CWD,
                target,
                MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
            )?;
            attached = true;
            drop(fd);
            protected_directory(target)?;
            // The mounted wrapper replaces a 0711 directory. The workload must traverse it to bind data/.
            fs::set_permissions(target, fs::Permissions::from_mode(0o711))?;
            let metadata = fs::symlink_metadata(target)?;
            socket.send(b"x")?;
            Ok(Mount {
                path: target.into(),
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        })();
        if result.is_err() {
            interrupt.store(true, Ordering::SeqCst);
        }
        while !worker.is_finished() {
            if cancelled.load(Ordering::SeqCst) {
                interrupt.store(true, Ordering::SeqCst);
            }
            thread::sleep(Duration::from_millis(5));
        }
        let (finished, contained) = worker.join().unwrap_or_else(|_| {
            (
                Err(invalid("Overlay helper panicked")),
                Err(invalid("Overlay helper containment unknown")),
            )
        });
        let ok = finished
            .as_ref()
            .is_ok_and(|value| value.end == job::End::Normal && value.exit_code == 0);
        if ok && contained.is_ok() && result.is_ok() && !cancelled.load(Ordering::SeqCst) {
            return result.map_err(SetupError::from);
        }
        let mut contained = contained.is_ok();
        if attached && contained {
            contained = unmount(target, UnmountFlags::empty()).is_ok();
        }
        let detail = match &finished {
            Ok(value) => format!(
                "helper exit {}: {}",
                value.exit_code,
                String::from_utf8_lossy(&value.output[1])
                    .chars()
                    .take(4096)
                    .collect::<String>()
            ),
            Err(error) => error.to_string(),
        };
        let cause = result
            .err()
            .map(|error| error.to_string())
            .unwrap_or_else(|| "helper failed".into());
        Err(SetupError {
            error: invalid(format!("Overlay setup: {cause}; {detail}")),
            contained,
        })
    })
}
