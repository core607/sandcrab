#!/usr/bin/env python3
"""Measure the current manual installation recipe on a disposable systemd machine."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'executor-service/rust/sandcrab'))
import sandcrab_conformance.native as native_probe


def save(path, receipt):
    temporary = path.with_name(path.name + '.pending')
    with temporary.open('w') as stream:
        json.dump(receipt, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


class Recipe:
    def __init__(self, args):
        if os.geteuid() != 0 or Path('/proc/1/comm').read_text().strip() != 'systemd':
            raise RuntimeError('A root disposable systemd host is required')
        if os.environ.get('SANDCRAB_READINESS_DISPOSABLE') != '1':
            raise RuntimeError('This manual recipe is only for disposable test machines')
        self.report = args.report.resolve()
        if self.report.exists() or self.report.with_name(self.report.name + '.pending').exists():
            raise RuntimeError('Preserve the previous receipt; choose a new path')
        self.report.parent.mkdir(parents=True, exist_ok=True)
        self.name = 'sandcrab-ready-' + uuid.uuid4().hex[:10]
        self.root = Path('/var/lib') / self.name
        self.slice = self.name + '.slice'
        self.unit = self.name + '.service'
        self.slice_file = Path('/run/systemd/system') / self.slice
        self.user = 'scrab-' + self.name.rsplit('-', 1)[1]
        self.created_user = False
        self.claimed_root = False
        self.command_units = []
        self.ops_slice = self.name + 'ops.slice'
        self.previous_policy = None
        self.source = args.source.resolve()
        self.binary = args.binary.resolve()
        self.started = args.acquisition_started_ns or time.monotonic_ns()
        if self.started > time.monotonic_ns():
            raise RuntimeError('Acquisition clock is not from this machine')
        self.receipt = {
            'schema': 1, 'kind': 'sandcrab-manual-readiness-baseline',
            'sourceRevision': args.revision, 'started': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'scope': 'Automated replay of the current README manual operator steps, using a prebuilt candidate. '
                     'Human editing time and source compilation are excluded; this is a lower bound, not turnkey readiness. '
                     'Operator commands have temporary resource limits; their wrapper overhead is included.',
            'acquisition': {'source': 'repository checkout plus candidate binary', 'operatorCommands': 2},
            'acquisitionClockIncluded': args.acquisition_started_ns is not None,
            'initialEnvironment': {'osRelease': Path('/etc/os-release').read_text(), 'kernel': os.uname().release,
                                   'logicalCpuCount': os.cpu_count(), 'controllerPythonPreinstalled': True,
                                   'rootCgroupLimits': {name: ((Path('/sys/fs/cgroup') / name).read_text().strip()
                                                               if (Path('/sys/fs/cgroup') / name).is_file() else None)
                                                       for name in ('memory.max', 'memory.swap.max', 'pids.max', 'cpu.max')},
                                   'programs': {name: shutil.which(name) is not None for name in
                                                ('curl', 'python3', 'node', 'npm', 'bwrap', 'git')}},
            'inputSha256': {'binary': hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                            'readme': hashlib.sha256((self.source / 'executor-service/rust/sandcrab/README.md').read_bytes()).hexdigest(),
                            'recipe': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
            'steps': [], 'measurementStatus': 'STARTING', 'cleanup': 'NOT_RUN',
            'modelTokens': 0, 'containsProductionContent': False,
        }
        save(self.report, self.receipt)

    def observe(self, *arguments, check=True):
        return subprocess.run(arguments, check=check, capture_output=True, text=True, timeout=30)

    def command(self, label, arguments, timeout=300):
        step = {'kind': 'command', 'label': label, 'argv': list(map(str, arguments)), 'status': 'STARTING'}
        self.receipt['steps'].append(step)
        save(self.report, self.receipt)
        started = time.monotonic_ns()
        try:
            unit = self.name + 'command-' + str(len(self.command_units)) + '.service'
            self.command_units.append(unit)
            wrapped = ['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit', unit, '--slice', self.ops_slice,
                       '-p', 'MemoryMax=768M', '-p', 'MemorySwapMax=0', '-p', 'TasksMax=128', '-p', 'CPUQuota=100%',
                       '-p', 'RuntimeMaxSec=' + str(timeout), '-p', 'TimeoutStopSec=5', '-p', 'KillMode=control-group',
                       '/usr/bin/env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'DEBIAN_FRONTEND=noninteractive',
                       'LC_ALL=C', *step['argv']]
            result = subprocess.run(wrapped, capture_output=True, text=True, timeout=timeout + 15)
            step.update(exitCode=result.returncode, stdoutTail=result.stdout[-8192:], stderrTail=result.stderr[-8192:])
            if len(result.stdout) + len(result.stderr) > 4 * 1024 * 1024:
                raise RuntimeError('Operator command output exceeded its receipt bound')
            if result.returncode:
                raise RuntimeError('Operator command failed: ' + label)
            step['status'] = 'PASS'
            return result.stdout
        except BaseException as error:
            step.update(status='FAIL', errorType=type(error).__name__)
            raise
        finally:
            step['elapsedNs'] = time.monotonic_ns() - started
            save(self.report, self.receipt)

    def configuration(self, path, contents, mode, fields):
        if path != self.slice_file and path != self.root / 'config.toml':
            raise RuntimeError('Unexpected manual configuration target')
        step = {'kind': 'manual-configuration', 'path': str(path), 'fields': fields, 'status': 'STARTING'}
        self.receipt['steps'].append(step)
        started = time.monotonic_ns()
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
            with os.fdopen(descriptor, 'w') as output:
                output.write(contents)
                output.flush()
                os.fsync(output.fileno())
            step.update(status='PASS', sha256=hashlib.sha256(contents.encode()).hexdigest())
        finally:
            step['elapsedNs'] = time.monotonic_ns() - started
            save(self.report, self.receipt)

    def install(self):
        if self.root.exists() or self.slice_file.exists():
            raise RuntimeError('The installation namespace is already occupied')
        if self.observe('systemctl', 'list-units', '--all', '--plain', '--no-legend', 'sandcrab*.service', 'sandcrab*.slice').stdout.strip():
            raise RuntimeError('The baseline requires a fresh machine without Sandcrab units')
        try:
            pwd.getpwnam(self.user)
        except KeyError:
            pass
        else:
            raise RuntimeError('The execution account already exists')
        self.command('create protected installation directory', ['mkdir', '-m', '755', self.root])
        self.claimed_root = True
        self.command('refresh package indexes', ['apt-get', 'update'])
        self.command('install preparation and Python workload dependencies',
                     ['apt-get', 'install', '--yes', '--no-install-recommends', 'python3', 'procps'])
        self.command('install candidate executables',
                     ['install', '-m', '755', self.binary, self.binary.with_name('bwrap'), self.root])
        self.command('install bundled helper source and notices',
                     ['install', '-m', '644', self.binary.with_name('bwrap-notices.txt'),
                      self.binary.with_name('bwrap-source.tar.xz'), self.root])
        self.command('prepare pinned sandbox toolchain',
                     ['bash', self.source / 'executor-service/prepare-tools.sh', self.root / 'tools'])
        self.created_user = True
        self.command('create separate execution account',
                     ['useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', self.user])
        text = (self.source / 'executor-service/rust/sandcrab/config.example.toml').read_text()
        values = {'runtime_root': str(self.root / 'runtime'), 'socket': str(self.root / 'runtime/control.sock'),
                  'client_uid': 0, 'client_gid': 0,
                  'cgroup_root': str(native_probe.service_cgroup(self.slice, self.unit)),
                  'exec_user': self.user, 'tools': str(self.root / 'tools')}
        for name, value in values.items():
            text, count = re.subn(r'(?m)^' + name + r' = .*$', name + ' = ' + json.dumps(value), text, count=1)
            if count != 1:
                raise RuntimeError('Example configuration no longer matches the manual recipe')
        self.configuration(self.root / 'config.toml', text, 0o600, list(values))
        self.configuration(self.slice_file, '[Unit]\nDescription=Disposable manual readiness baseline\n[Slice]\n'
                           'MemoryMax=1G\nMemorySwapMax=0\nTasksMax=256\nCPUQuota=50%\n', 0o644,
                           ['MemoryMax', 'MemorySwapMax', 'TasksMax', 'CPUQuota'])
        restriction = Path('/proc/sys/kernel/apparmor_restrict_unprivileged_userns')
        if restriction.exists() and restriction.read_text().strip() != '0':
            self.previous_policy = restriction.read_text().strip()
            self.receipt['manualHostPolicyEdits'] = 1
            self.command('allow capability-bearing user namespaces on this disposable host',
                         ['sysctl', '-w', 'kernel.apparmor_restrict_unprivileged_userns=0'])
        self.command('load the resource slice', ['systemctl', 'daemon-reload'])
        self.command('start the resource slice', ['systemctl', 'start', self.slice])
        self.command('start the root service in its bounded unit',
                     ['systemd-run', '--quiet', '--collect', '--unit', self.unit, '--slice', self.slice,
                      '-p', 'Delegate=yes', '-p', 'MemorySwapMax=0', '-p', 'TasksMax=infinity',
                      '-p', 'KillMode=control-group', '-p', 'RuntimeMaxSec=180',
                      self.root / 'sandcrab', 'serve', '--config', self.root / 'config.toml'])
        deadline = time.monotonic() + 20
        while not (self.root / 'runtime/control.sock').exists():
            if time.monotonic() >= deadline:
                raise RuntimeError('Service socket did not become ready')
            time.sleep(.05)
        output = self.command('first README sandboxed command',
                              [self.root / 'sandcrab', 'run', '--socket', self.root / 'runtime/control.sock',
                               '--profile', 'python', '--', 'python3', '-c', 'print(6 * 7)'])
        result = json.loads(output)
        if result.get('state') != 'succeeded' or result.get('result', {}).get('stdout') != '42\n':
            raise RuntimeError('First sandboxed command did not produce its expected result')
        self.receipt['measurementStatus'] = 'COMPLETED'

    def summarize(self):
        elapsed = time.monotonic_ns() - self.started
        commands = 2 + sum(step['kind'] == 'command' for step in self.receipt['steps'])
        edits = sum(step['kind'] == 'manual-configuration' for step in self.receipt['steps']) + self.receipt.get('manualHostPolicyEdits', 0)
        first = 'PASS' if self.receipt['measurementStatus'] == 'COMPLETED' else 'NOT_RUN'
        if first != 'PASS' and any(step.get('label') == 'first README sandboxed command' for step in self.receipt['steps']):
            first = 'FAIL'
        self.receipt['readiness'] = {'firstSandboxedCommand': first, 'operatorCommands': commands,
                                     'manualConfigurationEdits': edits, 'automatedWallNs': elapsed,
                                     'humanEditingTimeIncluded': False,
                                     'targetPass': first == 'PASS' and commands <= 3 and edits == 0 and elapsed < 300_000_000_000}

    def cleanup(self):
        for unit in self.command_units:
            self.observe('systemctl', 'stop', unit, check=False)
        self.verify_empty(self.ops_slice)
        self.observe('systemctl', 'stop', self.ops_slice, check=False)
        if not self.claimed_root:
            self.receipt['cleanup'] = 'NO_INSTALLATION_CREATED'
            return
        self.observe('systemctl', 'stop', self.unit, check=False)
        units = self.observe('systemctl', 'list-units', '--all', '--plain', '--no-legend', self.name + '-*.service').stdout
        for line in units.splitlines():
            self.observe('systemctl', 'stop', line.split()[0])
        self.verify_empty(self.slice)
        if any(line.split()[4].startswith(str(self.root) + '/') for line in Path('/proc/self/mountinfo').read_text().splitlines()):
            raise RuntimeError('Readiness mounts survived containment; preserve resources')
        self.observe('systemctl', 'stop', self.slice, check=False)
        self.slice_file.unlink(missing_ok=True)
        self.observe('systemctl', 'daemon-reload')
        if self.created_user:
            try:
                pwd.getpwnam(self.user)
            except KeyError:
                pass
            else:
                self.observe('userdel', self.user)
        if self.previous_policy is not None:
            policy = Path('/proc/sys/kernel/apparmor_restrict_unprivileged_userns')
            if policy.read_text().strip() != self.previous_policy:
                self.observe('sysctl', '-w', 'kernel.apparmor_restrict_unprivileged_userns=' + self.previous_policy)
            if policy.read_text().strip() != self.previous_policy:
                raise RuntimeError('Readiness host policy was not restored')
            self.receipt['hostPolicyRestored'] = True
        if self.root.exists():
            if self.root.parent != Path('/var/lib') or not re.fullmatch(r'sandcrab-ready-[a-f0-9]{10}', self.root.name) or self.root.is_symlink():
                raise RuntimeError('Refuse cleanup outside the readiness fixture')
            shutil.rmtree(self.root)
        self.receipt['cleanup'] = 'PASS'

    def verify_empty(self, unit):
        group = self.observe('systemctl', 'show', unit, '-p', 'ControlGroup', '--value', check=False).stdout.strip()
        if group:
            path = Path('/sys/fs/cgroup') / group.lstrip('/')
            if not group.startswith('/') or '..' in Path(group).parts or path.name != unit:
                raise RuntimeError('Unexpected readiness cgroup')
            for processes in path.rglob('cgroup.procs'):
                if processes.read_text().strip():
                    raise RuntimeError('Readiness processes survived containment')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--acquisition-started-ns', type=int)
    args = parser.parse_args()
    if not re.fullmatch('[a-f0-9]{40}', args.revision):
        raise SystemExit('An exact source revision is required')
    recipe = Recipe(args)
    def interrupted(signum, frame):
        raise KeyboardInterrupt('Readiness recipe interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    try:
        recipe.install()
    except BaseException as error:
        recipe.receipt.update(measurementStatus='ERROR', errorType=type(error).__name__, error=str(error))
        raise
    finally:
        recipe.summarize()
        try:
            recipe.cleanup()
        except BaseException:
            recipe.receipt.update(measurementStatus='ERROR', cleanup='UNCONFIRMED')
            raise
        finally:
            recipe.receipt['finished'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            save(recipe.report, recipe.receipt)


if __name__ == '__main__':
    main()
