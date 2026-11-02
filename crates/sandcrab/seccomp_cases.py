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

# Equivalence includes allowed calls: socketpair is needed by Python/Node event
# loops, and AF_INET creation is allowed inside the isolated network namespace.
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
