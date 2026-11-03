#![deny(unsafe_op_in_unsafe_fn)]
//! Linux process creation directly into a caller-owned cgroup v2 leaf. This
//! boundary owns spawn, stdio, the child handle and daemon mount-namespace entry; callers own identity,
//! isolation, resource limits, deadlines and descendant containment.
use rustix::{
    fs::{Mode, OFlags, open},
    io::fcntl_dupfd_cloexec,
    pipe::{PipeFlags, pipe_with},
};
use std::{
    ffi::CString,
    fs::File,
    io,
    os::{
        fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
        unix::{ffi::OsStrExt, process::ExitStatusExt},
    },
    path::Path,
    process::ExitStatus,
};

/// Only these descriptors cross exec. Pipe returns a writable parent stdin;
/// File transfers ownership of a caller-supplied readable descriptor.
pub enum Input {
    Null,
    Pipe,
    File(File),
}

/// Start a daemon-private mount tree before creating threads. Restricting this
/// entry to CLONE_NEWNS preserves the descriptor table and existing Rust I/O
/// ownership; namespace publication and mount cleanup remain the caller's job.
pub fn private_mount_namespace() -> io::Result<()> {
    let tasks = std::fs::read_dir("/proc/self/task")?.collect::<io::Result<Vec<_>>>()?;
    if !rustix::process::geteuid().is_root() || tasks.len() != 1 {
        return Err(io::Error::other(
            "Mount namespace entry requires a single-threaded root daemon",
        ));
    }
    // SAFETY: This fixed flag never unshares FILES or changes descriptor numbers.
    // No userspace pointers are passed, and failure leaves the caller to abort.
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: The target is a static NUL-terminated path; all unused pointers are
    // null. Recursively private propagation prevents mount changes reaching the host.
    if unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_PRIVATE | libc::MS_REC,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A real child, signaled through pidfd and reaped only by its parent. Like
/// std::process::Child, dropping this handle does not terminate or reap it.
pub struct Child {
    pub stdin: Option<File>,
    pub stdout: Option<File>,
    pub stderr: Option<File>,
    pid: libc::pid_t,
    pidfd: OwnedFd,
    status: Option<ExitStatus>,
}
impl Child {
    pub fn id(&self) -> u32 {
        self.pid as u32
    }

    pub fn kill(&mut self) -> io::Result<()> {
        if self.status.is_some() {
            return Ok(());
        }
        // SAFETY: pidfd is owned and live; a null siginfo selects the ordinary
        // SIGKILL operation, with no userspace memory read by the kernel.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn observe(&mut self, flags: libc::c_int) -> io::Result<Option<ExitStatus>> {
        if self.status.is_some() {
            return Ok(self.status);
        }
        let mut status = 0;
        loop {
            // SAFETY: status is writable, and pid is this unreaped child. No
            // wildcard wait or unrelated child can be consumed by this handle.
            let result = unsafe { libc::waitpid(self.pid, &mut status, flags) };
            if result == self.pid {
                self.status = Some(ExitStatus::from_raw(status));
                return Ok(self.status);
            }
            if result == 0 {
                return Ok(None);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.observe(libc::WNOHANG)
    }

    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        self.stdin.take();
        self.observe(0)?
            .ok_or_else(|| io::Error::other("Child wait returned no status"))
    }
}

// clone3 UAPI version 2, including its cgroup descriptor field. No shared VM,
// fd table, handlers, parent or thread group: the child has a private stack and
// address space, and the caller retains the normal waitpid ownership relation.
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}
const _: () = assert!(std::mem::size_of::<CloneArgs>() == 88);
const CLONE_CLEAR_SIGHAND: u64 = 1 << 32;
const CLONE_INTO_CGROUP: u64 = 1 << 33;
const CLOSE_RANGE_CLOEXEC: u32 = 4;

fn above_stdio(fd: OwnedFd) -> io::Result<OwnedFd> {
    if fd.as_raw_fd() < 3 {
        Ok(fcntl_dupfd_cloexec(&fd, 3)?)
    } else {
        Ok(fd)
    }
}
fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let (read, write) = pipe_with(PipeFlags::CLOEXEC)?;
    Ok((above_stdio(read)?, above_stdio(write)?))
}
struct Io {
    input: OwnedFd,
    output: OwnedFd,
    error: OwnedFd,
    stdin: Option<File>,
    stdout: File,
    stderr: File,
}
impl Io {
    fn new(input: Input) -> io::Result<Self> {
        let (input, stdin) = match input {
            Input::Null => (
                above_stdio(open(
                    "/dev/null",
                    OFlags::RDONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                )?)?,
                None,
            ),
            Input::File(file) => (above_stdio(file.into())?, None),
            Input::Pipe => {
                let (read, write) = pipe()?;
                (read, Some(File::from(write)))
            }
        };
        let (stdout, output) = pipe()?;
        let (stderr, error) = pipe()?;
        Ok(Self {
            input,
            output,
            error,
            stdin,
            stdout: stdout.into(),
            stderr: stderr.into(),
        })
    }
}

/// The caller supplies a verified cgroup fd whose limits are already applied,
/// and an absolute trusted executable. There is no PATH search or fallback.
/// Success means the child was created in that cgroup, not that exec succeeded;
/// child setup/exec failure exits 127. Return immediately so its owner can cancel
/// even before exec; retain this handle until reaping and cgroup containment.
pub fn spawn(
    executable: &Path,
    arguments: &[String],
    cgroup: BorrowedFd<'_>,
    input: Input,
) -> io::Result<Child> {
    if !executable.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "An absolute executable is required",
        ));
    }
    let invalid = |_| io::Error::new(io::ErrorKind::InvalidInput, "Process argument contains NUL");
    let executable = CString::new(executable.as_os_str().as_bytes()).map_err(invalid)?;
    let mut strings = vec![executable.clone()];
    strings.extend(
        arguments
            .iter()
            .map(|s| CString::new(s.as_bytes()).map_err(invalid))
            .collect::<io::Result<Vec<_>>>()?,
    );
    let mut argv: Vec<_> = strings.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());
    let env = [c"PATH=/usr/bin:/bin".as_ptr(), std::ptr::null()];
    let io = Io::new(input)?;
    let mut pidfd: libc::c_int = -1;
    let args = CloneArgs {
        flags: CLONE_INTO_CGROUP | CLONE_CLEAR_SIGHAND | libc::CLONE_PIDFD as u64,
        pidfd: (&mut pidfd as *mut libc::c_int) as u64,
        exit_signal: libc::SIGCHLD as u64,
        cgroup: cgroup.as_raw_fd() as u64,
        ..CloneArgs::default()
    };
    // SAFETY: sigaction is plain C data, initialized before clone. SIG_DFL with
    // an empty mask/flags needs no function pointer or restorer.
    let mut sigpipe: libc::sigaction = unsafe { std::mem::zeroed() };
    sigpipe.sa_sigaction = libc::SIG_DFL;
    // SAFETY: the mask points to initialized, writable sigset_t storage.
    if unsafe { libc::sigemptyset(&mut sigpipe.sa_mask) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let (program, argv, env) = (executable.as_ptr(), argv.as_ptr(), env.as_ptr());
    let (input, output, error) = (
        io.input.as_raw_fd(),
        io.output.as_raw_fd(),
        io.error.as_raw_fd(),
    );
    // SAFETY: clone_args has the kernel UAPI layout and its output pointer stays
    // valid through the syscall. No memory/stack/fd table is shared with the
    // child. All command buffers and descriptors were prepared in the parent.
    // CLEAR_SIGHAND atomically prevents inherited Rust handlers from executing
    // in the child. The child branch only calls the audited exec boundary below;
    // it never allocates, logs, locks, unwinds, drops Rust values or returns.
    let pid = unsafe { libc::syscall(libc::SYS_clone3, &args, std::mem::size_of::<CloneArgs>()) };
    if pid == 0 {
        // SAFETY: all pointers refer to inherited live buffers in this private
        // address space; descriptors are distinct and above standard stdio.
        unsafe { exec_child(program, argv, env, input, output, error, &sigpipe) }
    }
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Child {
        stdin: io.stdin,
        stdout: Some(io.stdout),
        stderr: Some(io.stderr),
        pid: pid as libc::pid_t,
        // SAFETY: successful CLONE_PIDFD returns a fresh owned descriptor; it is
        // not shared with any Rust owner and remains live until Child is dropped.
        pidfd: unsafe { OwnedFd::from_raw_fd(pidfd) },
        status: None,
    })
}

// No Rust cleanup is permitted after clone. These libc operations are syscall
// wrappers; execve and _exit do not return through inherited application state.
unsafe fn exec_child(
    program: *const libc::c_char,
    argv: *const *const libc::c_char,
    env: *const *const libc::c_char,
    input: RawFd,
    output: RawFd,
    error: RawFd,
    sigpipe: *const libc::sigaction,
) -> ! {
    // SAFETY: spawn established pointer lifetimes and fd ownership before clone.
    // The copied fd table is private. close_range(CLOEXEC) also excludes ambient
    // descriptors opened without CLOEXEC elsewhere in the multithreaded parent.
    unsafe {
        if libc::dup2(input, 0) < 0
            || libc::dup2(output, 1) < 0
            || libc::dup2(error, 2) < 0
            || libc::sigaction(libc::SIGPIPE, sigpipe, std::ptr::null_mut()) < 0
            || libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, CLOSE_RANGE_CLOEXEC) < 0
        {
            libc::_exit(127);
        }
        libc::execve(program, argv, env);
        libc::_exit(127);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        os::fd::AsFd,
        process::Command,
    };

    #[test]
    fn closed_stdio_and_failure_paths_release_prepared_descriptors() {
        const CHILD: &str = "SANDCRAB_SPAWN_FD_TEST";
        if std::env::var_os(CHILD).is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::closed_stdio_and_failure_paths_release_prepared_descriptors",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            return;
        }
        // SAFETY: this is a dedicated subprocess. Only its stdin/stderr are
        // closed, never the concurrent test runner's descriptors.
        unsafe {
            libc::close(0);
            libc::close(2);
        }
        let count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
        let before = count();
        for _ in 0..32 {
            let mut streams = Io::new(Input::Pipe).unwrap();
            for descriptor in [&streams.input, &streams.output, &streams.error] {
                assert!(descriptor.as_raw_fd() >= 3);
            }
            streams.stdin.take().unwrap().write_all(b"input").unwrap();
            let mut input = Vec::new();
            File::from(streams.input).read_to_end(&mut input).unwrap();
            assert_eq!(input, b"input");
            File::from(streams.output).write_all(b"output").unwrap();
            let mut output = Vec::new();
            streams.stdout.read_to_end(&mut output).unwrap();
            assert_eq!(output, b"output");
            File::from(streams.error).write_all(b"error").unwrap();
            let mut error = Vec::new();
            streams.stderr.read_to_end(&mut error).unwrap();
            assert_eq!(error, b"error");
        }
        assert_eq!(count(), before);
        for _ in 0..32 {
            let target = File::open("/dev/null").unwrap();
            assert!(spawn(Path::new("/bin/sh"), &[], target.as_fd(), Input::Pipe).is_err());
            drop(target);
            assert_eq!(count(), before);
            drop(Io::new(Input::Null).unwrap());
            drop(Io::new(Input::File(File::open("/dev/null").unwrap())).unwrap());
            assert_eq!(count(), before);
        }
        // SAFETY: limits are plain C data; this process alone lowers its soft
        // descriptor limit, observes setup refusal, then restores the old limit.
        unsafe {
            let mut old: libc::rlimit = std::mem::zeroed();
            assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut old), 0);
            let limited = libc::rlimit {
                rlim_cur: 3,
                rlim_max: old.rlim_max,
            };
            assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limited), 0);
            let result = Io::new(Input::Pipe);
            assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &old), 0);
            assert!(result.is_err());
        }
        assert_eq!(count(), before);
    }

    #[test]
    fn invalid_inputs_never_fall_back_to_an_uncontained_process() {
        let target = File::open("/dev/null").unwrap();
        assert!(spawn(Path::new("sh"), &[], target.as_fd(), Input::Null).is_err());
        assert!(
            spawn(
                Path::new("/bin/sh"),
                &["bad\0argument".into()],
                target.as_fd(),
                Input::Null
            )
            .is_err()
        );
        for _ in 0..32 {
            assert!(
                spawn(
                    Path::new("/bin/sh"),
                    &["-c".into(), "exit 0".into()],
                    target.as_fd(),
                    Input::Pipe
                )
                .is_err()
            );
        }
    }
}
