"""Run inside a real x86_64 sandbox; emit only independent seccomp observations."""
import ctypes
import errno
import json
import mmap
import os
from pathlib import Path
import signal
import socket
import resource

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
checks = []


def syscall(number, *arguments):
    ctypes.set_errno(0)
    return libc.syscall(ctypes.c_long(number), *(ctypes.c_ulonglong(value) for value in arguments))


def denied(name, number, *arguments):
    result = syscall(number, *arguments)
    observed = ctypes.get_errno()
    if number == 41 and result >= 0:
        os.close(result)
    assert result == -1 and observed == errno.EPERM, (name, result, observed)
    checks.append(name)


for domain in (1, 0x100000001, 0xffffffff00000001):
    denied('socket-af-unix-' + hex(domain), 41, domain, socket.SOCK_STREAM, 0)
for name, number in (('io-uring-setup', 425), ('io-uring-enter', 426), ('io-uring-register', 427)):
    denied(name, number, 0, 0, 0, 0, 0, 0)

for domain in (40, 0x100000028):
    denied('socket-af-vsock-' + hex(domain), 41, domain, socket.SOCK_STREAM, 0)
for name, number in (
    ('ptrace', 101), ('pivot-root', 155), ('mount', 165), ('umount2', 166),
    ('create-module', 174), ('init-module', 175), ('delete-module', 176), ('finit-module', 313),
    ('kexec-load', 246), ('kexec-file-load', 320), ('add-key', 248), ('request-key', 249), ('keyctl', 250),
    ('perf-event-open', 298), ('setns', 308), ('bpf', 321), ('userfaultfd', 323),
    ('open-tree', 428), ('move-mount', 429), ('fsopen', 430), ('fsconfig', 431), ('fsmount', 432),
    ('fspick', 433), ('mount-setattr', 442), ('statmount', 457), ('listmount', 458), ('open-tree-attr', 467),
):
    # Invalid descriptors, requests and addresses cannot perform administrative work even if the filter regresses.
    denied(name, number, -1, 0, -1, 0, -1, 0)

namespace_bits = {'time': 0x80, 'mount': 0x20000, 'cgroup': 0x02000000, 'uts': 0x04000000,
                  'ipc': 0x08000000, 'user': 0x10000000, 'pid': 0x20000000, 'net': 0x40000000}
for name, bit in namespace_bits.items():
    # CLONE_SIGHAND without CLONE_VM is invalid even in the absence of seccomp.
    denied('clone-new-' + name, 56, bit | 0x800, 0, 0, 0, 0)
    denied('unshare-new-' + name, 272, bit)
denied('clone-empty-mount', 56, (1 << 37) | 0x800, 0, 0, 0, 0)
denied('unshare-empty-mount', 272, 0x00100000)
assert syscall(435, 0, 0) == -1 and ctypes.get_errno() == errno.ENOSYS
checks.append('clone3-libc-fallback')
for value in (8, 0x40000):
    denied('personality-change-' + hex(value), 135, value)
assert syscall(135, 0xffffffff) >= 0 and syscall(135, 0) >= 0
checks.append('personality-query-and-default-allowed')

# socketpair supports Python/Node event loops. AF_INET is available inside the isolated network.
with socket.socket(socket.AF_INET):
    checks.append('inet-creation-allowed')
left, right = socket.socketpair()
with left, right:
    left.sendall(b'allowed')
    assert right.recv(7) == b'allowed'
checks.append('unix-socketpair-allowed')
assert syscall(39) == os.getpid()
assert syscall(-1) == -1 and ctypes.get_errno() == errno.ENOSYS
checks.append('native-and-negative-one-syscalls-preserved')


def abi_guard(name, compat=False):
    child = os.fork()
    if child == 0:
        if compat:
            # i386 getpid via int 0x80; it has no side effect if a guard is absent.
            with mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC) as code:
                code.write(bytes.fromhex('b8 14 00 00 00 cd 80 c3'))
                pointer = ctypes.addressof(ctypes.c_char.from_buffer(code))
                ctypes.CFUNCTYPE(ctypes.c_long)(pointer)()
        else:
            syscall(0x40000000 + 39)
        os._exit(2)
    _, status = os.waitpid(child, 0)
    assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGSYS, (name, status)
    checks.append(name)


abi_guard('x32-abi-killed')
abi_guard('i386-abi-killed', compat=True)
visible = []
for process in Path('/proc').iterdir():
    if not process.name.isdecimal():
        continue
    try:
        status = dict(line.split(':', 1) for line in (process / 'status').read_text().splitlines() if ':' in line)
    except FileNotFoundError:
        continue
    assert status['Seccomp'].strip() == '2' and status['NoNewPrivs'].strip() == '1', process.name
    visible.append(int(process.name))
assert 1 in visible and os.getpid() in visible
checks.append('every-visible-process-filtered-including-init')
for descriptor in Path('/proc/self/fd').iterdir():
    try:
        target = os.readlink(descriptor)
    except FileNotFoundError:
        continue
    assert 'memfd:sandcrab-seccomp' not in target, target
checks.append('filter-descriptor-consumed-before-workload')
print(json.dumps({'checks': checks, 'visiblePids': sorted(visible)}))
