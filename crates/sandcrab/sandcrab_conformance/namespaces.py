"""Observe namespace identities and SysV IPC from two real same-UID shells."""
import json
import os
import secrets
import shlex


OBSERVE = """import json, os, socket, subprocess
from pathlib import Path
names = ('mnt', 'user', 'net', 'ipc', 'pid', 'uts', 'cgroup')
child = subprocess.run(['unshare', '-U', 'true'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
print(json.dumps({'uid': os.geteuid(), 'hostname': socket.gethostname(), 'nestedExit': child.returncode,
                  'cgroup': Path('/proc/self/cgroup').read_text().strip(),
                  'ns': {name: os.readlink('/proc/self/ns/' + name) for name in names}}))
"""
LIBC = 'import ctypes, json\nlibc = ctypes.CDLL(None, use_errno=True)\n'


def check_namespaces(probe):
    def guest(session, program):
        run, value = probe.session_exec(session, 'python3 -c ' + shlex.quote(program))
        assert value['state'] == 'succeeded', value
        probe.forget(run)
        return json.loads(value['result']['stdout'])

    sessions = []
    try:
        for _ in range(2):
            sessions.append(probe.session_open())
        first, second = (guest(shell, OBSERVE) for shell in sessions)
        assert first['uid'] == second['uid'] == probe.uid
        for name, namespace in first['ns'].items():
            assert len({namespace, second['ns'][name], os.readlink('/proc/self/ns/' + name)}) == 3, (name, first, second)
        assert first['nestedExit'] != 0 and second['nestedExit'] != 0
        probe.done('two-same-uid-shells-own-private-namespaces-and-refuse-nested-unshare-user')
        assert first['hostname'] == second['hostname'] == 'sandcrab'
        assert first['cgroup'] == second['cgroup'] == '0::/'
        probe.done('private-uts-hostname-and-cgroup-root-hide-host-unit-names')

        key = secrets.randbelow(0x7ffffffe) + 1
        segment = guest(sessions[0], LIBC + f'print(libc.shmget({key}, 4096, 0o3600))')
        assert segment >= 0, 'Could not create the SysV shared memory segment'
        try:
            assert guest(sessions[0], LIBC + f'print(libc.shmget({key}, 0, 0))') == segment
            lookup = LIBC + f'import errno\nvalue = libc.shmget({key}, 0, 0)\nprint(json.dumps([value, ctypes.get_errno() == errno.ENOENT]))'
            assert guest(sessions[1], lookup) == [-1, True]
        finally:
            assert guest(sessions[0], LIBC + f'print(libc.shmctl({segment}, 0, None))') == 0
        probe.done('sysv-shared-memory-remains-visible-only-to-its-owning-session')
    finally:
        for session in sessions:
            probe.session_close(session)
            probe.session_forget(session)
