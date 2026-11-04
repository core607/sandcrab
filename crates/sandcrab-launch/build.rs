#![forbid(unsafe_code)]
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch, sock_filter,
};
use std::{collections::BTreeMap, env, fs, path::PathBuf};

fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=bwrap/lock.json");
    let lock: serde_json::Value =
        serde_json::from_str(&fs::read_to_string("bwrap/lock.json").unwrap()).unwrap();
    let digest = lock["binarySha256"].as_str().unwrap();
    assert_eq!(digest.len(), 64);
    let digest: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&digest[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("bwrap.rs"),
        format!(
            "const BWRAP_SHA256: [u8; 32] = {digest:?};\nconst BWRAP_BYTES: u64 = {};\n",
            lock["binaryBytes"].as_u64().unwrap()
        ),
    )
    .unwrap();
    assert_eq!(env::var("CARGO_CFG_TARGET_OS").unwrap(), "linux");
    assert_eq!(env::var("CARGO_CFG_TARGET_ARCH").unwrap(), "x86_64");
    assert_eq!(env::var("CARGO_CFG_TARGET_ENDIAN").unwrap(), "little");

    let mut source = String::new();
    emit(&mut source, "BOOTSTRAP_FILTER", base_rules(), false);
    emit(&mut source, "WORKLOAD_FILTER", workload_rules(false), true);
    emit(
        &mut source,
        "OVERLAY_EXPORT_FILTER",
        workload_rules(true),
        true,
    );
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("filter.rs"),
        source,
    )
    .unwrap();
}

type Rules = BTreeMap<i64, Vec<SeccompRule>>;

fn condition(arg: u8, width: SeccompCmpArgLen, op: SeccompCmpOp, value: u64) -> SeccompCondition {
    SeccompCondition::new(arg, width, op, value).unwrap()
}

fn rule(conditions: Vec<SeccompCondition>) -> SeccompRule {
    SeccompRule::new(conditions).unwrap()
}

fn base_rules() -> Rules {
    // Preserve SRT 0.0.75's 32-bit AF_UNIX comparison and its three io_uring denials.
    BTreeMap::from([
        (
            41,
            vec![rule(vec![condition(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                1,
            )])],
        ),
        (425, vec![]),
        (426, vec![]),
        (427, vec![]),
    ])
}

fn namespace_bit(flag: u64) -> SeccompRule {
    rule(vec![condition(
        0,
        SeccompCmpArgLen::Qword,
        SeccompCmpOp::MaskedEq(flag),
        flag,
    )])
}

fn workload_rules(overlay_export: bool) -> Rules {
    use SeccompCmpArgLen::Dword;
    use SeccompCmpOp::{Eq, Ne};
    let mut rules = base_rules();
    rules
        .get_mut(&41)
        .unwrap()
        .push(rule(vec![condition(0, Dword, Eq, 40)])); // AF_VSOCK
    // Native x86-64 syscall numbers, including old and new mount entry points.
    for number in [
        101, // ptrace
        155, 165, 166, // pivot_root, mount, umount2
        174, 175, 176, 313, // create_module, init_module, delete_module, finit_module
        246, 320, // kexec_load, kexec_file_load
        248, 249, 250, // add_key, request_key, keyctl
        298, 308, 321, 323, // perf_event_open, setns, bpf, userfaultfd
        428, 429, 430, 431, 432,
        433, // open_tree, move_mount, fsopen, fsconfig, fsmount, fspick
        442, 457, 458, 467, // mount_setattr, statmount, listmount, open_tree_attr
    ] {
        rules.insert(number, vec![]);
    }
    if overlay_export {
        // The fixed daemon helper clones its private VIEW using AT_FDCWD and OPEN_TREE_CLONE|O_CLOEXEC.
        rules.insert(
            428,
            vec![
                rule(vec![condition(0, Dword, Ne, u64::from((-100i32) as u32))]),
                rule(vec![condition(2, Dword, Ne, 0x80001)]),
            ],
        );
    }
    let namespace_flags = [
        0x80,
        0x0002_0000,
        0x0200_0000,
        0x0400_0000,
        0x0800_0000,
        0x1000_0000,
        0x2000_0000,
        0x4000_0000,
    ];
    let mut clone: Vec<_> = namespace_flags.into_iter().map(namespace_bit).collect();
    clone.push(namespace_bit(1 << 37)); // CLONE_EMPTY_MNTNS
    rules.insert(56, clone);
    let mut unshare: Vec<_> = namespace_flags.into_iter().map(namespace_bit).collect();
    // This unshare-only bit is CLONE_PARENT_SETTID for ordinary clone callers.
    unshare.push(namespace_bit(0x0010_0000));
    rules.insert(272, unshare);
    // Linux truncates personality to unsigned int; querying with 0xffffffff does not change it.
    rules.insert(
        135,
        vec![rule(vec![
            condition(0, Dword, Ne, 0),
            condition(0, Dword, Ne, u64::from(u32::MAX)),
        ])],
    );
    rules
}

fn emit(source: &mut String, name: &str, rules: Rules, clone_fallback: bool) {
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(1),
        TargetArch::x86_64,
    )
    .unwrap();
    let compiled: BpfProgram = filter.try_into().unwrap();
    // Preserve the pinned helper's ABI guard actions, including its -1 syscall exception.
    let mut program = vec![
        instruction(0x20, 0, 0, 4),
        instruction(0x15, 1, 0, 0xc000_003e),
        instruction(0x06, 0, 0, 0),
        instruction(0x20, 0, 0, 0),
        instruction(0x35, 0, 2, 0x4000_0000),
        instruction(0x15, 1, 0, u32::MAX),
        instruction(0x06, 0, 0, 0),
    ];
    if clone_fallback {
        // clone3 carries flags behind a pointer. ENOSYS selects libc's observable clone fallback.
        program.extend([
            instruction(0x15, 0, 1, 435),
            instruction(0x06, 0, 0, 0x0005_0026),
        ]);
    }
    program.extend(compiled);
    source.push_str(&format!("const {name}: &[seccompiler::sock_filter] = &[\n"));
    for op in program {
        source.push_str(&format!(
            "seccompiler::sock_filter {{ code: {}, jt: {}, jf: {}, k: {} }},\n",
            op.code, op.jt, op.jf, op.k
        ));
    }
    source.push_str("];\n");
}
