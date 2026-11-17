use super::*;
use rustix::{fs::fcntl_get_seals, io::fcntl_getfd};
use seccompiler::sock_filter;
use std::io::Read;

// The 17 instructions baked into SRT 0.0.75's x64 helper, SHA-256
// 64fa7514fa7199584b836159885e59b9ce3684fb8fef7e13de49965b23f54f6b.
// Its generator is vendor/seccomp-src/seccomp-unix-block.c at upstream commit
// 40804af269e1616092e9971de12a1f358f58eba9. This reference preserves the actual
// ABI guard actions, which differ from seccompiler's default architecture guard.
fn reference(audit_arch: u32, socket_nr: u32) -> Vec<sock_filter> {
    [
        (0x20, 0, 0, 4),
        (0x15, 0, 14, audit_arch),
        (0x20, 0, 0, 0),
        (0x35, 0, 1, 0x4000_0000),
        (0x15, 0, 11, u32::MAX),
        (0x15, 9, 0, 425),
        (0x15, 8, 0, 426),
        (0x15, 7, 0, 427),
        (0x15, 0, 5, socket_nr),
        (0x20, 0, 0, 20),
        (0x54, 0, 0, 0),
        (0x15, 0, 2, 0),
        (0x20, 0, 0, 16),
        (0x15, 1, 0, 1),
        (0x06, 0, 0, 0x7fff_0000),
        (0x06, 0, 0, 0x0005_0001),
        (0x06, 0, 0, 0),
    ]
    .map(|(code, jt, jf, k)| sock_filter { code, jt, jf, k })
    .to_vec()
}

fn action(program: &[sock_filter], nr: u32, arch: u32, arg0: u64) -> u32 {
    evaluate(program, nr, arch, [arg0, 0, 0])
}

fn evaluate(program: &[sock_filter], nr: u32, arch: u32, args: [u64; 3]) -> u32 {
    let mut data = [0u8; 64];
    data[..4].copy_from_slice(&nr.to_le_bytes());
    data[4..8].copy_from_slice(&arch.to_le_bytes());
    for (slot, arg) in data[16..40].as_chunks_mut::<8>().0.iter_mut().zip(args) {
        slot.copy_from_slice(&arg.to_le_bytes());
    }
    let (mut pc, mut value) = (0usize, 0u32);
    for _ in 0..program.len() {
        let op = &program[pc];
        pc += 1;
        match op.code {
            0x20 => {
                let offset = op.k as usize;
                value = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            }
            0x54 => value &= op.k,
            0x15 => pc += usize::from(if value == op.k { op.jt } else { op.jf }),
            0x35 => pc += usize::from(if value >= op.k { op.jt } else { op.jf }),
            0x05 => pc += op.k as usize,
            0x06 => return op.k,
            other => panic!("Unexpected BPF instruction {other:x}"),
        }
    }
    panic!("Filter has no terminal action")
}

#[test]
fn compiled_filters_match_the_pinned_reference_across_x86_64_and_aarch64_abi_boundaries() {
    for (bootstrap, audit_arch, socket_nr) in [
        (X86_64_BOOTSTRAP_FILTER, 0xc000_003e, 41),
        (AARCH64_BOOTSTRAP_FILTER, 0xc000_00b7, 198),
    ] {
        let reference = reference(audit_arch, socket_nr);
        let calls = (0..=512).chain([
            0x4000_0000,
            0x4000_0029,
            0x4000_00c6,
            0x4000_01a9,
            u32::MAX - 1,
            u32::MAX,
        ]);
        for nr in calls {
            for arch in [0xc000_003e, 0x4000_0003, 0xc000_00b7, 0x4000_0028] {
                for domain in [
                    0,
                    1,
                    2,
                    10,
                    40,
                    0x0000_0001_0000_0001,
                    0xffff_ffff_0000_0001,
                    u64::MAX,
                ] {
                    assert_eq!(
                        action(bootstrap, nr, arch, domain),
                        action(&reference, nr, arch, domain),
                        "target={audit_arch:x}, nr={nr:x}, arch={arch:x}, domain={domain:x}"
                    );
                }
            }
        }
        let mut seed = 20261102u64;
        for _ in 0..10000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let nr = seed as u32;
            let arch = if seed & 1 == 0 {
                audit_arch
            } else {
                (seed >> 32) as u32
            };
            let domain = seed.rotate_left(17);
            assert_eq!(
                action(bootstrap, nr, arch, domain),
                action(&reference, nr, arch, domain)
            );
        }
    }
}

#[test]
fn workloads_deny_kernel_admin_calls_on_both_x86_64_and_aarch64() {
    let allow = 0x7fff_0000;
    let denied = 0x0005_0001;
    let x86_denied: &[u32] = &[
        101, 155, 165, 166, 174, 175, 176, 246, 248, 249, 250, 298, 308, 313, 320, 321, 323, 425,
        426, 427, 428, 429, 430, 431, 432, 433, 442, 457, 458, 467,
    ];
    let aarch64_denied: &[u32] = &[
        117, 41, 40, 39, 105, 106, 273, 104, 294, 217, 218, 219, 241, 268, 280, 282, 425, 426, 427,
        428, 429, 430, 431, 432, 433, 442, 457, 458, 467,
    ];
    for (
        program,
        arch,
        foreign_arch,
        admin_calls,
        socket_nr,
        socketpair_nr,
        clone_nr,
        unshare_nr,
        personality_nr,
    ) in [
        (
            X86_64_WORKLOAD_FILTER,
            0xc000_003e,
            0xc000_00b7,
            x86_denied,
            41,
            53,
            56,
            272,
            135,
        ),
        (
            AARCH64_WORKLOAD_FILTER,
            0xc000_00b7,
            0xc000_003e,
            aarch64_denied,
            198,
            199,
            220,
            97,
            92,
        ),
    ] {
        assert_eq!(action(program, 0, foreign_arch, 0), 0);
        for &nr in admin_calls {
            assert_eq!(
                action(program, nr, arch, 0),
                denied,
                "arch={arch:x} syscall {nr}"
            );
        }
        for bits in [1, 40, 0x1_0000_0028, 0xffff_ffff_0000_0001] {
            assert_eq!(action(program, socket_nr, arch, bits), denied);
        }
        for flag in [
            0x80,
            0x0002_0000,
            0x0200_0000,
            0x0400_0000,
            0x0800_0000,
            0x1000_0000,
            0x2000_0000,
            0x4000_0000,
        ] {
            for nr in [clone_nr, unshare_nr] {
                assert_eq!(
                    action(program, nr, arch, flag | 0x100),
                    denied,
                    "{arch:x} {nr} {flag:x}"
                );
            }
        }
        assert_eq!(action(program, clone_nr, arch, 1 << 37), denied);
        assert_eq!(action(program, unshare_nr, arch, 0x0010_0000), denied);
        assert_eq!(action(program, clone_nr, arch, 0x0010_0000 | 17), allow);
        assert_eq!(action(program, unshare_nr, arch, 0), allow);
        assert_eq!(action(program, 435, arch, u64::MAX), 0x0005_0026);
        for value in [0, u64::from(u32::MAX), u64::MAX] {
            assert_eq!(action(program, personality_nr, arch, value), allow);
        }
        for value in [8, 0x40000, 0x1_0000_0008] {
            assert_eq!(action(program, personality_nr, arch, value), denied);
        }
        assert_eq!(action(program, socket_nr, arch, 2), allow);
        assert_eq!(action(program, socketpair_nr, arch, 1), allow);
    }
}

#[test]
fn only_the_fixed_overlay_exporter_can_clone_its_mount() {
    assert_eq!(u64::from(rustix::fs::OFlags::CLOEXEC.bits()) | 1, 0x80001);
    let dirfd = (-100i64) as u64;
    for (export_filter, workload_filter, arch) in [
        (
            X86_64_OVERLAY_EXPORT_FILTER,
            X86_64_WORKLOAD_FILTER,
            0xc000_003e,
        ),
        (
            AARCH64_OVERLAY_EXPORT_FILTER,
            AARCH64_WORKLOAD_FILTER,
            0xc000_00b7,
        ),
    ] {
        for (nr, args, expected) in [
            (428, [dirfd, 0, 0x80001], 0x7fff_0000),
            (428, [dirfd, 0, 1], 0x0005_0001),
            (428, [5, 0, 0x80001], 0x0005_0001),
            (429, [dirfd, 0, 0x80001], 0x0005_0001),
        ] {
            assert_eq!(evaluate(export_filter, nr, arch, args), expected);
            assert_eq!(evaluate(workload_filter, nr, arch, args), 0x0005_0001);
        }
    }
}

#[test]
fn the_filter_fd_is_sealed_complete_and_close_on_exec_until_launch() {
    let filter = Seccomp::new().unwrap();
    assert!(fcntl_getfd(&filter.0).unwrap().contains(FdFlags::CLOEXEC));
    let seals = SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE;
    assert!(fcntl_get_seals(&filter.0).unwrap().contains(seals));
    let mut reader = filter.0.try_clone().unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes.len(), WORKLOAD_FILTER.len() * 8);
    for (encoded, op) in bytes.as_chunks::<8>().0.iter().zip(WORKLOAD_FILTER) {
        assert_eq!(
            u16::from_le_bytes(encoded[..2].try_into().unwrap()),
            op.code
        );
        assert_eq!(&encoded[2..4], &[op.jt, op.jf]);
        assert_eq!(u32::from_le_bytes(encoded[4..].try_into().unwrap()), op.k);
    }
    assert_eq!(
        reader.write_all(b"modified").unwrap_err().raw_os_error(),
        Some(1)
    );
    assert_eq!(reader.set_len(0).unwrap_err().raw_os_error(), Some(1));
}
