//! Ported from the former launcher.py tests. They run as root in the build image, so tool
//! ownership is exercised on real files rather than mocked metadata.
use super::*;
use std::os::unix::fs::{DirBuilderExt, symlink};

/// A root-owned directory whose ancestors other accounts cannot write.
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        assert!(
            rustix::process::geteuid().is_root(),
            "launch tests need root-owned files"
        );
        let mut bytes = [0u8; 8];
        fs::File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut bytes)
            .unwrap();
        let name: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let path = Path::new("/var/lib/sandcrab-launch-tests").join(name);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(&path)
            .unwrap();
        for directory in [path.parent().unwrap(), &path] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Self(path)
    }
    fn file(&self, relative: &str, bytes: &[u8], mode: u32) -> PathBuf {
        let path = self.0.join(relative);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(path.parent().unwrap())
            .unwrap();
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The repository worker's shell policy, as the supervisor writes it.
fn policy() -> Value {
    json!({"network":{"allowedDomains":[],"deniedDomains":[],"allowAllUnixSockets":false},
        "filesystem":{"denyRead":["/","/sys"],
            "allowRead":["/usr","/bin","/lib","/lib64","/dev","/proc","/etc/ld.so.cache",
                "/opt/poketto/tools","/run/poketto/sessions/x/bootstrap","/opt/poketto/bin",
                "/run/poketto/sessions/x/bridge/lock","/run/poketto/sessions/x/bridge/state",
                "/run/poketto/sessions/x/bridge/responses"],
            "denyWrite":[],
            "allowWrite":["/run/poketto/sessions/x/work","/run/poketto/sessions/x/home",
                "/run/poketto/sessions/x/bridge/requests","/tmp"]},
        "enableWeakerNestedSandbox":false})
}
fn command() -> Vec<String> {
    ["/bin/bash", "-c", "printf \"$HOME\""]
        .map(String::from)
        .to_vec()
}
fn arguments(policy: &Value) -> Result<Vec<String>, Error> {
    sandbox_arguments(
        Path::new("/tools/bwrap"),
        &Seccomp::new()?,
        policy,
        &command(),
    )
}
fn pair(args: &[String], flag: &str) -> Vec<String> {
    let index = args.iter().position(|a| a == flag).unwrap();
    args[index..index + 2].to_vec()
}

#[test]
fn the_policy_reaches_the_filter_with_a_literal_command_and_every_namespace() {
    let args = arguments(&policy()).unwrap();
    let mut tail = vec!["--".to_string()];
    tail.extend(command());
    assert_eq!(args[args.len() - 4..], tail[..]);
    assert!(pair(&args, "--seccomp")[1].parse::<i32>().unwrap() >= 0);
    for flag in [
        "--unshare-net",
        "--unshare-user",
        "--unshare-pid",
        "--die-with-parent",
        "--new-session",
    ] {
        assert!(args.contains(&flag.to_string()), "{flag}");
    }
    assert_eq!(pair(&args, "--cap-drop"), ["--cap-drop", "ALL"]);
    assert_eq!(pair(&args, "--remount-ro"), ["--remount-ro", "/"]);
    let triples: Vec<_> = args.windows(3).collect();
    for source in ["/", "/dev", "/proc"] {
        assert!(!triples.contains(&&["--ro-bind".to_string(), source.into(), source.into()][..]));
    }
    assert!(triples.contains(&&["--bind".to_string(), "/tmp".into(), "/tmp".into()][..]));
    assert_eq!(args[0], "/tools/bwrap");
}

#[test]
fn policy_extensions_and_overlapping_grants_fail_closed() {
    let mutations: [fn(&mut Value); 12] = [
        |p| p["network"]["allowAllUnixSockets"] = true.into(),
        |p| p["network"]["allowedDomains"] = json!(["example.invalid"]),
        |p| p["enableWeakerNestedSandbox"] = true.into(),
        |p| p["filesystem"]["denyWrite"] = json!(["/tmp/secret"]),
        |p| p["filesystem"]["denyRead"] = json!(["/", "/sys", "/usr/secret"]),
        |p| push(p, "allowWrite", "/usr/local"),
        |p| push(p, "allowRead", "/tmp/subdir"),
        |p| push(p, "allowRead", "/"),
        |p| push(p, "allowRead", "/var/../root"),
        |p| push(p, "allowRead", "/usr"),
        |p| p["extra"] = json!({}),
        |p| p["network"]["allowAllUnixSockets"] = 0.into(),
    ];
    fn push(policy: &mut Value, key: &str, path: &str) {
        policy["filesystem"][key]
            .as_array_mut()
            .unwrap()
            .push(path.into());
    }
    for mutate in mutations {
        let mut changed = policy();
        mutate(&mut changed);
        assert!(arguments(&changed).is_err(), "{changed}");
    }
}

#[test]
fn grants_are_accepted_only_in_their_normalized_spelling() {
    for path in [
        "/usr/",
        "/usr/./lib",
        "/usr//lib",
        "relative",
        "/usr\0x",
        "/a/b/..",
    ] {
        let mut changed = policy();
        changed["filesystem"]["allowRead"] = json!([path]);
        assert!(arguments(&changed).is_err(), "{path:?}");
    }
    assert_eq!(normalized("//usr"), "//usr");
    assert_eq!(normalized("///usr/./lib/../bin/"), "/usr/bin");
    assert_eq!(normalized("../a"), "../a");
    assert_eq!(normalized(""), ".");
}

#[test]
fn unverified_helpers_are_rejected_without_executing_them() {
    let root = Root::new();
    let executable = root.0.join("sandcrab");
    let script = format!(
        "#!/bin/sh\ntouch {}/ran\nprintf 'bubblewrap 0.13.1\\n'\n",
        root.0.display()
    );
    let mut bytes = script.into_bytes();
    bytes.resize(BWRAP_BYTES as usize, b' ');
    for candidate in [
        bytes.clone(),
        bytes[..bytes.len() - 1].to_vec(),
        [bytes, vec![0]].concat(),
    ] {
        root.file("bwrap", &candidate, 0o755);
        assert!(
            verify_bundled_bwrap(&executable)
                .unwrap_err()
                .0
                .contains("checksum mismatch")
        );
        assert!(!root.0.join("ran").exists());
    }
}

#[test]
fn tool_and_ancestor_ownership_cannot_be_bypassed_by_links_or_modes() {
    let root = Root::new();
    let safe = root.file("safe/bwrap", b"#!/bin/sh\n", 0o755);
    trusted_executable(&safe).unwrap();
    let writable = root.file("writable/bwrap", b"#!/bin/sh\n", 0o775);
    let foreign = root.file("foreign/bwrap", b"#!/bin/sh\n", 0o755);
    rustix::fs::chown(&foreign, Some(rustix::fs::Uid::from_raw(1000)), None).unwrap();
    let linked = root.0.join("linked/bwrap");
    fs::create_dir(linked.parent().unwrap()).unwrap();
    symlink(&safe, &linked).unwrap();
    let parent = root.file("open/bwrap", b"#!/bin/sh\n", 0o755);
    fs::set_permissions(parent.parent().unwrap(), fs::Permissions::from_mode(0o777)).unwrap();
    let plain = root.file("plain/bwrap", b"data", 0o644);
    for path in [&writable, &foreign, &linked, &parent] {
        let error = trusted_executable(path).unwrap_err();
        assert!(error.0.contains("root-owned and not writable"), "{error}");
    }
    assert_eq!(
        trusted_executable(&plain).unwrap_err().0,
        "Sandbox tool is not executable"
    );
    for path in ["relative/bwrap", "/usr/../usr/bin/env"] {
        assert_eq!(
            trusted_executable(Path::new(path)).unwrap_err().0,
            "Sandbox tool paths must be absolute"
        );
    }
}

#[test]
fn the_program_directory_holds_exactly_the_trusted_programs() {
    let root = Root::new();
    let programs = ["poketto", "poketto-shell"];
    for name in programs {
        root.file(&format!("bin/{name}"), b"#!/bin/sh\n", 0o755);
    }
    let directory = root.0.join("bin");
    verify_programs(&directory, &programs).unwrap();
    assert!(verify_programs(&directory, &["poketto"]).is_err());
    let link = root.0.join("linked-bin");
    symlink(&directory, &link).unwrap();
    assert!(verify_programs(&link, &programs).is_err());
    root.file("bin/extra", b"#!/bin/sh\n", 0o755);
    assert!(verify_programs(&directory, &programs).is_err());
    fs::remove_file(directory.join("extra")).unwrap();
    fs::set_permissions(directory.join("poketto"), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(verify_programs(&directory, &programs).is_err());
}

#[test]
fn startup_enters_bootstrap_without_following_links() {
    let root = Root::new();
    let session = root.0.join("session");
    fs::create_dir_all(session.join("elsewhere")).unwrap();
    symlink(session.join("elsewhere"), session.join("bootstrap")).unwrap();
    assert!(enter_bootstrap(&session).is_err());
    let link = root.0.join("link");
    symlink(&session, &link).unwrap();
    fs::remove_file(session.join("bootstrap")).unwrap();
    fs::create_dir(session.join("bootstrap")).unwrap();
    assert!(enter_bootstrap(&link).is_err());
    let previous = std::env::current_dir().unwrap();
    enter_bootstrap(&session).unwrap();
    assert_eq!(std::env::current_dir().unwrap(), session.join("bootstrap"));
    std::env::set_current_dir(previous).unwrap();
}
