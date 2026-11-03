//! Diagnose kernel prerequisites and prove one command through the installed service.
use crate::config::{Config, invalid};
use sandcrab_core::fs::{protected_directory, protected_file};
use std::os::unix::process::CommandExt;
use std::{
    fs, io,
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant},
};

fn kernel() -> io::Result<String> {
    let release = fs::read_to_string("/proc/sys/kernel/osrelease")?;
    for namespace in ["pid", "mnt", "net", "user"] {
        fs::read_link(format!("/proc/self/ns/{namespace}"))?;
    }
    sandcrab_core::cgroup::Cgroup::open(Path::new("/sys/fs/cgroup"))?;
    Ok(release.trim().into())
}

fn user_namespaces() -> io::Result<String> {
    for (path, optional) in [
        ("/proc/sys/user/max_user_namespaces", false),
        ("/proc/sys/kernel/unprivileged_userns_clone", true),
    ] {
        match fs::read_to_string(path) {
            Ok(value) if value.trim().parse::<u64>().is_ok_and(|v| v > 0) => (),
            Err(error) if optional && error.kind() == io::ErrorKind::NotFound => (),
            Ok(_) => return Err(invalid(format!("{path} is disabled"))),
            Err(error) => return Err(error),
        }
    }
    Ok("enabled in the kernel; the sandbox check exercises the host policy".into())
}

fn delegation(cfg: &Config) -> io::Result<String> {
    let path = &cfg.service.cgroup_root;
    let group = sandcrab_core::cgroup::Cgroup::open(path)?;
    crate::delegation::verify_pool(&group)?;
    let enabled = fs::read_to_string(path.join("cgroup.subtree_control"))?;
    if !["cpu", "memory", "pids"]
        .into_iter()
        .all(|s| enabled.split_whitespace().any(|c| c == s))
    {
        return Err(invalid(
            "cpu, memory and pids must be delegated to children",
        ));
    }
    fs::metadata(path.join("cgroup.kill"))?;
    Ok(format!("bounded v2 delegation at {}", path.display()))
}

fn storage(cfg: &Config) -> io::Result<String> {
    protected_directory(&cfg.service.runtime_root)?;
    match &cfg.storage {
        Some(pool) => Ok(format!(
            "{}; {}",
            pool.root.display(),
            if crate::storage::verify_pool(pool)? {
                "enforced project quotas"
            } else {
                "periodic accounting"
            }
        )),
        None => Ok("protected runtime directory; durable volumes disabled".into()),
    }
}

fn cli(cfg: &Config) -> io::Result<Command> {
    let mut command = Command::new(std::env::current_exe()?);
    if rustix::process::geteuid().as_raw() == 0 {
        command
            .gid(cfg.service.client_gid)
            .uid(cfg.service.client_uid);
    }
    Ok(command)
}

pub(crate) fn wait_for_service(cfg: &Config) -> io::Result<()> {
    // A local process may already own the TCP port. Never send it an installation token.
    // The CLI checks both the root-owned Unix socket and the peer's credentials.
    let mut command = cli(cfg)?;
    command.args(["info", "--socket"]).arg(&cfg.service.socket);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let output = command.output()?;
        if output.status.success() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(invalid(
                "Service discovery failed on the protected Unix socket; check the service journal and listener addresses",
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn sandbox(cfg: &Config) -> io::Result<String> {
    let profile = cfg
        .profiles
        .get("default")
        .ok_or_else(|| invalid("No default profile"))?;
    wait_for_service(cfg)?;
    let output = cli(cfg)?
        .args(["run", "--socket"])
        .arg(&cfg.service.socket)
        .args([
            "--profile",
            "default",
            "--timeout-ms",
            &profile.timeout_millis.min(5000).to_string(),
            "--",
            "/bin/bash",
            "-c",
            "exec /usr/bin/python3 -c 'import os; assert os.geteuid() != 0; print(6*7)'",
        ])
        .output()?;
    let result: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| invalid("The diagnostic command did not return a run result"))?;
    if !output.status.success()
        || result["state"] != "succeeded"
        || result["result"]["stdout"] != "42\n"
    {
        return Err(invalid(format!(
            "Default sandbox did not return 42 (state {})",
            result["state"]
        )));
    }
    Ok("default profile ran bash and Python as a non-root user".into())
}

fn report(label: &str, result: io::Result<String>, fix: &str) -> bool {
    match result {
        Ok(detail) => {
            println!("OK  {label}: {detail}");
            true
        }
        Err(e) => {
            eprintln!("FAIL {label}: {e}. Fix: {fix}");
            false
        }
    }
}

pub fn doctor(path: &Path) -> io::Result<i32> {
    let mut ok = report(
        "kernel",
        kernel(),
        "Use a Linux host with user, mount, PID and network namespaces and cgroup v2.",
    );
    ok &= report(
        "user namespaces",
        user_namespaces(),
        "Enable user namespaces and allow them for the Sandcrab service.",
    );
    ok &= report(
        "bubblewrap",
        sandcrab_launch::verify_bundled_bwrap(&std::env::current_exe()?)
            .map(|p| p.display().to_string())
            .map_err(io::Error::other),
        "Install the matching bwrap next to sandcrab in the protected release directory.",
    );
    let config = (|| {
        protected_directory(
            path.parent()
                .ok_or_else(|| invalid("Invalid configuration path"))?,
        )?;
        let text = protected_file(path, 65536)?;
        Config::parse(std::str::from_utf8(&text).map_err(io::Error::other)?)
    })();
    match config {
        Err(e) => {
            report(
                "configuration",
                Err(e),
                "Run sandcrab install or pass a protected --config FILE.",
            );
            return Ok(1);
        }
        Ok(cfg) => {
            ok &= report(
                "cgroup",
                delegation(&cfg),
                "Start the service with delegated cpu, memory and pids, finite aggregate limits and zero swap.",
            );
            ok &= report(
                "storage",
                storage(&cfg),
                "Create the protected runtime and storage directories on writable storage; check the configured quota mode.",
            );
            ok &= report(
                "sandbox",
                sandbox(&cfg),
                "Start the configured service and check its journal, default profile, token and user-namespace policy.",
            );
        }
    }
    Ok(i32::from(!ok))
}
