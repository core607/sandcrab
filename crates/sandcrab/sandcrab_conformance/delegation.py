#!/usr/bin/env python3
"""Run the native service directly under an owned, bounded cgroup v2 subtree.

Use --initialize-container only as PID 1 of a disposable private-cgroup container.
The ordinary mode uses an already delegated parent on a root Linux host.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from .native import call, http
from .resources import ResourcesProbe


class DirectProbe(ResourcesProbe):
    def __init__(self, binary, tools, report, parent):
        super().__init__(binary, tools, report)
        old = self.delegated_root
        self.delegated_root = parent / (self.name + '-direct')
        self.config.write_text(self.config.read_text().replace(str(old), str(self.delegated_root)))
        self.workloads_group = self.delegated_root / ('sandcrab-' + hashlib.sha256(str(self.socket.parent).encode()).hexdigest()) / 'workloads'
        self.process, self.log, self.created = None, None, False
        self.receipt.update(scope='Direct root daemon under real delegated cgroup v2; no service manager calls',
                            deployment='delegated-container' if os.getpid() == 1 else 'root-host-direct',
                            pid1=Path('/proc/1/comm').read_text().strip(),
                            delegationProbeSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())

    def setup(self):
        available = (self.delegated_root.parent / 'cgroup.subtree_control').read_text().split()
        assert {'cpu', 'memory', 'pids'} <= set(available), 'Parent must delegate cpu, memory and pids'
        self.delegated_root.mkdir()
        self.created = True
        for name, value in {'memory.max': '402653184', 'memory.swap.max': '0',
                            'pids.max': '256', 'cpu.max': '50000 100000'}.items():
            (self.delegated_root / name).write_text(value)
            assert (self.delegated_root / name).read_text().strip() == value
        self.start()

    def start(self):
        assert self.process is None or self.process.poll() is not None
        if self.log is None:
            self.log = self.report.with_suffix('.daemon.log').open('x')
        self.process = subprocess.Popen([str(self.binary), 'serve', '--config', str(self.config)],
            env={'PATH': '/usr/bin:/bin'}, stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log,
            start_new_session=True)
        self.wait_ready()

    def wait_ready(self):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError('Direct daemon stopped before readiness; inspect daemon log')
            try:
                status, self.info = http(self.socket, 'GET', '/v1/info')
                if status == 200:
                    return
            except (OSError, ValueError):
                pass
            time.sleep(.025)
        raise AssertionError('Direct daemon did not become ready')

    def stop(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait(timeout=10)
            self.process = None

    def tests(self):
        super().tests()
        request = self.submit('import os, errno\nassert os.umask(0o077)==0o077\n'
            'assert os.getgroups()==[]\nassert open("/proc/self/oom_score_adj").read().strip()=="0"\n'
            'try:\n open("/tmp/private", "wb").write(b"x"*(16*1024*1024))\n'
            'except OSError as e:\n assert e.errno==errno.ENOSPC\n'
            'else:\n raise Exception("private tmp is unbounded")\nprint("bounded")')
        result = self.wait(request)
        assert result['state'] == 'succeeded' and result['result']['stdout'] == 'bounded\n', result
        self.forget(request)
        request = self.submit('from pathlib import Path; assert not Path("/tmp/private").exists(); print("private")')
        assert self.wait(request)['result']['stdout'] == 'private\n'
        self.forget(request)
        self.done('direct-private-tmp-identity-umask-and-neutral-oom-priority')

        epoch = self.info['serverId']
        request = self.submit('x=bytearray(128*1024*1024)')
        result = self.wait(request)
        assert result['state'] == 'resource_limit', result
        self.forget(request)
        assert http(self.socket, 'GET', '/v1/info')[1]['serverId'] == epoch
        self.done('direct-leaf-oom-does-not-stop-the-daemon')

        session = self.session_open()
        self.session_exec(session, 'sleep 30 & printf pending')
        self.stop()
        foreign = self.workloads_group.parent / 'unowned'
        foreign.mkdir()
        try:
            self.start()
        except AssertionError:
            assert self.process.wait(timeout=5) != 0
        else:
            raise AssertionError('Foreign cgroup was adopted')
        assert foreign.is_dir() and (self.socket.parent / 'jobs' / session['id']).exists()
        foreign.rmdir()
        self.start()
        assert self.info['serverId'] != epoch
        assert http(self.socket, 'GET', '/v1/sessions/' + session['id'])[0] == 404
        assert not list((self.socket.parent / 'jobs').iterdir())
        assert not [path for path in self.workloads_group.iterdir() if path.is_dir()]
        self.done('direct-restart-refuses-foreign-cgroups-and-contains-old-leaves-before-epoch')

        self.stop()
        original = self.config.read_text()
        fake = self.root / 'ordinary-directory'
        fake.mkdir()
        sentinel = fake / 'memory.max'
        sentinel.write_text('12345')
        self.config.write_text(original.replace(str(self.delegated_root), str(fake)))
        try:
            self.start()
        except AssertionError:
            assert self.process.wait(timeout=5) != 0
        else:
            raise AssertionError('Ordinary filesystem was accepted as a cgroup')
        assert sentinel.read_text() == '12345'
        self.config.write_text(original)
        self.start()
        self.done('direct-delegation-requires-the-actual-cgroup2-filesystem')

    def cleanup(self):
        self.stop()
        if self.created:
            assert self.delegated_root.name == self.name + '-direct' and not self.delegated_root.is_symlink()
            (self.delegated_root / 'cgroup.kill').write_text('1')
            deadline = time.monotonic() + 10
            while 'populated 1' in (self.delegated_root / 'cgroup.events').read_text():
                assert time.monotonic() < deadline, 'Direct fixture descendants survived cgroup.kill'
                time.sleep(.01)
            groups = [path for path in self.delegated_root.rglob('*') if path.is_dir()]
            for path in sorted(groups, key=lambda path: len(path.parts), reverse=True):
                path.rmdir()
            self.delegated_root.rmdir()
        mounts = [Path(line.split()[4]) for line in Path('/proc/self/mountinfo').read_text().splitlines()
                  if line.split()[4].startswith(str(self.root) + '/')]
        for path in sorted(mounts, key=lambda path: len(path.parts), reverse=True):
            self.unmount_fixture(path)
        assert not any(line.split()[4].startswith(str(self.root) + '/') for line in Path('/proc/self/mountinfo').read_text().splitlines())
        assert self.secret.read_text() == 'host-sentinel-is-not-mounted\n'
        self.remove_fixture_directory()
        if self.log is not None:
            self.log.close()
        self.receipt['cleanup'] = 'PASS'
