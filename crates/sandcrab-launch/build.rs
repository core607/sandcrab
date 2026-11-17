#![forbid(unsafe_code)]
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch, sock_filter,
};
use std::{collections::BTreeMap, env, fs, path::PathBuf};

fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

struct ArchSpec {
    prefix: &'static str,
    target: TargetArch,
    audit_arch: u32,
    socket: i64,
    io_uring: [i64; 3],
    denied: &'static [i64],
    open_tree: i64,
    clone: i64,
    unshare: i64,
    clone3: u32,
    personality: i64,
}

const X86_64: ArchSpec = ArchSpec {
    prefix: "X86_64",
    target: TargetArch::x86_64,
    audit_arch: 0xc000_003e,
    socket: 41,
    io_uring: [425, 426, 427],
    // Native x86-64 syscall numbers, including old and new mount entry points.
    denied: &[
        101, // ptrace
        155, 165, 166, // pivot_root, mount, umount2
        174, 175, 176, 313, // create_module, init_module, delete_module, finit_module
        246, 320, // kexec_load, kexec_file_load
        248, 249, 250, // add_key, request_key, keyctl
        298, 308, 321, 323, // perf_event_open, setns, bpf, userfaultfd
        428, 429, 430, 431, 432,
        433, // open_tree, move_mount, fsopen, fsconfig, fsmount, fspick
        442, 457, 458, 467, // mount_setattr, statmount, listmount, open_tree_attr
    ],
    open_tree: 428,
    clone: 56,
    unshare: 272,
    clone3: 435,
    personality: 135,
};

const AARCH64: ArchSpec = ArchSpec {
    prefix: "AARCH64",
    target: TargetArch::aarch64,
    audit_arch: 0xc000_00b7,
    socket: 198,
    io_uring: [425, 426, 427],
    // Native Linux AArch64 (asm-generic/unistd.h) syscall numbers.
    denied: &[
        117, // ptrace
        41, 40, 39, // pivot_root, mount, umount2
        105, 106, 273, // init_module, delete_module, finit_module
        104, 294, // kexec_load, kexec_file_load
        217, 218, 219, // add_key, request_key, keyctl
        241, 268, 280, 282, // perf_event_open, setns, bpf, userfaultfd
        428, 429, 430, 431, 432,
        433, // open_tree, move_mount, fsopen, fsconfig, fsmount, fspick
        442, 457, 458, 467, // mount_setattr, statmount, listmount, open_tree_attr
    ],
    open_tree: 428,
    clone: 220,
    unshare: 97,
    clone3: 435,
    personality: 92,
};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=bwrap/lock.json");
    assert_eq!(env::var("CARGO_CFG_TARGET_OS").unwrap(), "linux");
    assert_eq!(env::var("CARGO_CFG_TARGET_ENDIAN").unwrap(), "little");
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let active_prefix = match target_arch.as_str() {
        "x86_64" => "X86_64",
        "aarch64" => "AARCH64",
        other => panic!("Unsupported Sandcrab target architecture: {other}"),
    };

    let lock: serde_json::Value =
        serde_json::from_str(&fs::read_to_string("bwrap/lock.json").unwrap()).unwrap();
    let target_lock = &lock["targets"][&target_arch];
    let digest = target_lock["binarySha256"].as_str().unwrap();
    assert_eq!(digest.len(), 64);
    let digest: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&digest[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("bwrap.rs"),
        format!(
            "const BWRAP_SHA256: [u8; 32] = {digest:?};\nconst BWRAP_BYTES: u64 = {};\n",
            target_lock["binaryBytes"].as_u64().unwrap()
        ),
    )
    .unwrap();

    let mut source = String::new();
    for spec in [&X86_64, &AARCH64] {
        let attr = if spec.prefix == active_prefix {
            ""
        } else {
            "#[cfg(test)]\n"
        };
        emit(
            &mut source,
            attr,
            &format!("{}_BOOTSTRAP_FILTER", spec.prefix),
            spec,
            base_rules(spec),
            false,
        );
        emit(
            &mut source,
            attr,
            &format!("{}_WORKLOAD_FILTER", spec.prefix),
            spec,
            workload_rules(spec, false),
            true,
        );
        emit(
            &mut source,
            attr,
            &format!("{}_OVERLAY_EXPORT_FILTER", spec.prefix),
            spec,
            workload_rules(spec, true),
            true,
        );
    }
    for kind in [
        "BOOTSTRAP_FILTER",
        "WORKLOAD_FILTER",
        "OVERLAY_EXPORT_FILTER",
    ] {
        source.push_str(&format!(
            "const {kind}: &[seccompiler::sock_filter] = {active_prefix}_{kind};\n"
        ));
    }
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

fn base_rules(spec: &ArchSpec) -> Rules {
    // Preserve SRT 0.0.75's 32-bit AF_UNIX comparison and its three io_uring denials.
    BTreeMap::from([
        (
            spec.socket,
            vec![rule(vec![condition(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                1,
            )])],
        ),
        (spec.io_uring[0], vec![]),
        (spec.io_uring[1], vec![]),
        (spec.io_uring[2], vec![]),
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

fn workload_rules(spec: &ArchSpec, overlay_export: bool) -> Rules {
    use SeccompCmpArgLen::Dword;
    use SeccompCmpOp::{Eq, Ne};
    let mut rules = base_rules(spec);
    rules
        .get_mut(&spec.socket)
        .unwrap()
        .push(rule(vec![condition(0, Dword, Eq, 40)])); // AF_VSOCK
    for &number in spec.denied {
        rules.insert(number, vec![]);
    }
    if overlay_export {
        // The fixed daemon helper clones its private VIEW using AT_FDCWD and OPEN_TREE_CLONE|O_CLOEXEC.
        rules.insert(
            spec.open_tree,
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
    rules.insert(spec.clone, clone);
    let mut unshare: Vec<_> = namespace_flags.into_iter().map(namespace_bit).collect();
    // This unshare-only bit is CLONE_PARENT_SETTID for ordinary clone callers.
    unshare.push(namespace_bit(0x0010_0000));
    rules.insert(spec.unshare, unshare);
    // Linux truncates personality to unsigned int; querying with 0xffffffff does not change it.
    rules.insert(
        spec.personality,
        vec![rule(vec![
            condition(0, Dword, Ne, 0),
            condition(0, Dword, Ne, u64::from(u32::MAX)),
        ])],
    );
    rules
}

fn emit(
    source: &mut String,
    attr: &str,
    name: &str,
    spec: &ArchSpec,
    rules: Rules,
    clone_fallback: bool,
) {
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(1),
        spec.target,
    )
    .unwrap();
    let compiled: BpfProgram = filter.try_into().unwrap();
    // Preserve the pinned helper's ABI guard actions, including its -1 syscall exception.
    let mut program = vec![
        instruction(0x20, 0, 0, 4),
        instruction(0x15, 1, 0, spec.audit_arch),
        instruction(0x06, 0, 0, 0),
        instruction(0x20, 0, 0, 0),
        instruction(0x35, 0, 2, 0x4000_0000),
        instruction(0x15, 1, 0, u32::MAX),
        instruction(0x06, 0, 0, 0),
    ];
    if clone_fallback {
        // clone3 carries flags behind a pointer. ENOSYS selects libc's observable clone fallback.
        program.extend([
            instruction(0x15, 0, 1, spec.clone3),
            instruction(0x06, 0, 0, 0x0005_0026),
        ]);
    }
    program.extend(compiled);
    source.push_str(&format!(
        "{attr}const {name}: &[seccompiler::sock_filter] = &[\n"
    ));
    for op in program {
        source.push_str(&format!(
            "seccompiler::sock_filter {{ code: {}, jt: {}, jf: {}, k: {} }},\n",
            op.code, op.jt, op.jf, op.k
        ));
    }
    source.push_str("];\n");
}
