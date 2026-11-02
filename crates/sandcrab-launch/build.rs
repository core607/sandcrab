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
    assert_eq!(env::var("CARGO_CFG_TARGET_OS").unwrap(), "linux");
    assert_eq!(env::var("CARGO_CFG_TARGET_ARCH").unwrap(), "x86_64");
    assert_eq!(env::var("CARGO_CFG_TARGET_ENDIAN").unwrap(), "little");

    // SRT 0.0.75 compares socket's 32-bit domain, including when the register's
    // high bits are nonzero. Its three io_uring denials are unconditional.
    let unix = SeccompRule::new(vec![
        SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 1).unwrap(),
    ])
    .unwrap();
    let filter = SeccompFilter::new(
        BTreeMap::from([
            (41, vec![unix]),
            (425, vec![]),
            (426, vec![]),
            (427, vec![]),
        ]),
        SeccompAction::Allow,
        SeccompAction::Errno(1),
        TargetArch::x86_64,
    )
    .unwrap();
    let compiled: BpfProgram = filter.try_into().unwrap();

    // Preserve the helper's libseccomp ABI guards, including KILL_THREAD rather
    // than seccompiler's KILL_PROCESS and the special -1 syscall exception.
    // seccomp_data: nr at byte 0, arch at byte 4. The generated filter's own
    // architecture rejection is unreachable after this exact compatibility guard.
    let mut program = vec![
        instruction(0x20, 0, 0, 4),
        instruction(0x15, 1, 0, 0xc000_003e),
        instruction(0x06, 0, 0, 0),
        instruction(0x20, 0, 0, 0),
        instruction(0x35, 0, 2, 0x4000_0000),
        instruction(0x15, 1, 0, u32::MAX),
        instruction(0x06, 0, 0, 0),
    ];
    program.extend(compiled);
    let mut source = String::from("const FILTER: &[seccompiler::sock_filter] = &[\n");
    for op in program {
        source.push_str(&format!(
            "seccompiler::sock_filter {{ code: {}, jt: {}, jf: {}, k: {} }},\n",
            op.code, op.jt, op.jf, op.k
        ));
    }
    source.push_str("];\n");
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("filter.rs"),
        source,
    )
    .unwrap();
}
