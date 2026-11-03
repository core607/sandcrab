"""Own one disposable native service, bounded resource slice and storage image."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

NATIVE = Path(__file__).resolve().parents[2] / 'executor-service/rust/sandcrab'
sys.path.insert(0, str(NATIVE))
import native_probe
from native_probe import Probe, call


def fields(path):
    return {key: int(value) for key, value in (line.split() for line in Path(path).read_text().splitlines())}


def group(unit):
    relative = call('systemctl', 'show', unit, '-p', 'ControlGroup', '--value').stdout.strip()
    if not relative.startswith('/') or '..' in Path(relative).parts:
        raise RuntimeError('Invalid fixture cgroup')
    return Path('/sys/fs/cgroup') / relative.lstrip('/')


def host_memory():
    return {line.split(':')[0]: int(line.split()[1]) * 1024
            for line in Path('/proc/meminfo').read_text().splitlines() if line.split(':')[0] in ('MemTotal', 'MemAvailable')}


def other_loads():
    count = 0
    for process in Path('/proc').iterdir():
        if not process.name.isdecimal() or int(process.name) in (os.getpid(), os.getppid()):
            continue
        try:
            arguments = (process / 'cmdline').read_bytes().split(b'\0')[:3]
        except OSError:
            continue
        if any(argument.endswith((b'/sandcrab-density/density.py', b'/sandcrab-density/footprint.py',
                                  b'/sandcrab-density/page_cache.py', b'/sandcrab-density/cold_start.py',
                                  b'/agent-load.py', b'/load-suite.py'))
               for argument in arguments):
            count += 1
    return count


class Fixture(Probe):
    def __init__(self, binary, tools, report, budget, smoke=False, storage_mode='xfs'):
        if storage_mode not in ('xfs', 'plain'):
            raise ValueError('Unsupported benchmark storage mode')
        self.storage_mode = storage_mode
        if os.geteuid() != 0 or Path('/proc/1/comm').read_text().strip() != 'systemd':
            raise RuntimeError('The native benchmark requires a root systemd/cgroup-v2 host')
        if not Path('/sys/fs/cgroup/cgroup.controllers').is_file():
            raise RuntimeError('cgroup v2 is required')
        memory = host_memory()
        self.fixture_parent = Path(os.environ.get('SANDCRAB_PROBE_ROOT', '/var/lib'))
        self.pool_bytes = 512 * 1024**2 if smoke else 8 * 1024**3
        free = shutil.disk_usage(self.fixture_parent).free
        if budget < 512 * 1024**2 or memory['MemAvailable'] < budget + 512 * 1024**2:
            raise RuntimeError('Insufficient host memory outside the requested benchmark slice')
        if free < self.pool_bytes + 2 * 1024**3 or other_loads():
            raise RuntimeError('Insufficient free storage or another load controller is active')
        if any(self.fixture_parent.glob('poketto-java-native-*')) or any(self.fixture_parent.glob('sandcrab-native-*')):
            raise RuntimeError('Another native fixture directory is present; reconcile it before measuring')
        if call('systemctl', 'list-units', '--all', '--plain', '--no-legend', 'sandcrab-probe-*.service').stdout.strip():
            raise RuntimeError('Another native fixture is present; reconcile it before measuring')
        formatter = 'mkfs.xfs' if storage_mode == 'xfs' else 'mkfs.ext4'
        for program in ('systemd-run', formatter, 'findmnt', 'git', 'rg', 'bash', 'python3'):
            if shutil.which(program) is None:
                raise RuntimeError('Missing benchmark dependency: ' + program)
        self.host_lock = os.open('/var/lib/sandcrab-density.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        self.budget = budget
        try:
            fcntl.flock(self.host_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            super().__init__(binary, tools, report)
            self.configure(tools, memory, free)
        except BaseException:
            # Construction has not started units or mounted anything yet.
            try:
                root = getattr(self, 'root', None)
                if root is not None:
                    if root.parent != self.fixture_parent or not root.name.startswith('sandcrab-native-') or root.is_symlink():
                        raise RuntimeError('Refusing to remove an unexpected partial fixture')
                    shutil.rmtree(root)
            finally:
                os.close(self.host_lock)
            raise

    def configure(self, tools, memory, free):
        # Only setup's readiness check uses the existing probe client; workload
        # requests use the independent asynchronous client without UID mutation.
        native_probe.CLIENT = (0, 0)
        self.storage = self.root / 'storage'
        self.data = self.storage / 'data'
        self.storage_mount = self.data if self.storage_mode == 'xfs' else self.storage
        self.data.mkdir(parents=True)
        self.storage.chmod(0o755)
        self.data.chmod(0o755)
        self.image = self.root / ('data.xfs' if self.storage_mode == 'xfs' else 'data.ext4')
        self.config.write_text(f'''[service]
runtime_root = {json.dumps(str(self.socket.parent))}
socket = {json.dumps(str(self.socket))}
client_uid = 0
client_gid = 0
cgroup_root = "{self.delegated_root}"
daemon_memory_bytes = 536870912
daemon_tasks_max = 2048
max_sandboxes = 512
max_records = 1024
max_output_bytes = 16777216
max_connections = 256
max_event_streams = 128
max_file_records = 1024
max_file_transfers = 2
[storage]
root = {json.dumps(str(self.storage))}
require_quota = {str(self.storage_mode == 'xfs').lower()}
pool_bytes = {self.pool_bytes}
max_volume_bytes = 268435456
max_volume_inodes = 65536
max_volumes = 512
max_records = 1024
[profiles.python]
exec_user = "nobody"
tools = {json.dumps(str(tools))}
read_only = {json.dumps(['/usr', '/bin', '/lib', '/lib64', '/etc/ld.so.cache', *getattr(self, 'extra_reads', [])])}
memory_bytes = 268435456
temporary_bytes = 16777216
temporary_inodes = 4096
tasks_max = 64
cpu_quota_percent = 100
timeout_millis = 60000
session_ttl_millis = 3600000
output_limit_bytes = 65536
transfer_bytes = 67108864
network = "none"
''')
        self.receipt.update(scope='Independent native benchmark fixture; no application, model or private content',
                            preflight={'memory': memory, 'freeDiskBytes': free, 'otherLoadControllers': 0,
                                       'logicalCpuCount': os.cpu_count(), 'controllerCpuAffinityCount': len(os.sched_getaffinity(0))},
                            requestedMemoryBytes=self.budget, configuredSandboxCeiling=512,
                            storagePoolBytes=self.pool_bytes, storageMode=self.storage_mode,
                            configSha256=hashlib.sha256(self.config.read_bytes()).hexdigest(),
                            kernel=os.uname().release,
                            operatingSystem=Path('/etc/os-release').read_text(),
                            fixtureSourceSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())

    def setup(self):
        with self.image.open('xb') as image:
            os.fchmod(image.fileno(), 0o600)
            os.posix_fallocate(image.fileno(), 0, self.pool_bytes)
            os.fsync(image.fileno())
        if self.storage_mode == 'xfs':
            call('mkfs.xfs', '-m', 'reflink=1', str(self.image))
            options = 'loop,prjquota,nosuid,nodev'
        else:
            # One inode per data block avoids an artificial low-inode fixture cap.
            # Finish initialization before observing accounting or workload CPU.
            call('mkfs.ext4', '-F', '-q', '-m', '0', '-i', '4096',
                 '-E', 'lazy_itable_init=0,lazy_journal_init=0', str(self.image))
            options = 'loop,nosuid,nodev'
        call('mount', '-o', options, str(self.image), str(self.storage_mount))
        if self.storage_mode == 'plain':
            # Keep ext4's lost+found outside the daemon-owned data directory.
            self.storage.chmod(0o755)
            self.data.mkdir(mode=0o755)
        self.slice_file.write_text('[Unit]\nDescription=Disposable Sandcrab density benchmark\n[Slice]\n'
                                   f'MemoryMax={self.budget}\nMemorySwapMax=0\nTasksMax=8192\nCPUQuota=200%\n')
        call('systemctl', 'daemon-reload')
        call('systemctl', 'start', self.slice)
        self.pool_group = group(self.slice)
        page = os.sysconf('SC_PAGE_SIZE')
        expected = {'memory.max': self.budget // page * page, 'memory.swap.max': 0, 'pids.max': 8192}
        actual = {name: int((self.pool_group / name).read_text()) for name in expected}
        if actual != expected:
            raise RuntimeError('The enclosing slice limits differ from the requested budget')
        quota, period = map(int, (self.pool_group / 'cpu.max').read_text().split())
        if quota != 2 * period:
            raise RuntimeError('The enclosing slice must have exactly two CPUs of quota')
        self.receipt['effectiveLimits'] = {**actual, 'cpu.max': [quota, period]}
        ancestors = []
        self.receipt['resourceAncestors'] = ancestors
        for current in (self.pool_group, *self.pool_group.parents):
            if not current.is_relative_to('/sys/fs/cgroup'):
                break
            limits = {name: (current / name).read_text().strip() for name in
                      ('memory.max', 'cpu.max', 'pids.max', 'cpuset.cpus.effective') if (current / name).is_file()}
            ancestors.append({'group': str(current.relative_to('/sys/fs/cgroup')), 'limits': limits})
            memory = limits.get('memory.max', 'max')
            if memory != 'max' and int(memory) < actual['memory.max']:
                raise RuntimeError('An ancestor supplies less memory than the experiment budget')
            cpu = limits.get('cpu.max', 'max 100000').split()
            if cpu[0] != 'max' and int(cpu[0]) < 2 * int(cpu[1]):
                raise RuntimeError('An ancestor supplies less than two CPUs of quota')
        self.start()
        actual_quotas = self.info['storage']['quotaEnforced']
        if actual_quotas != (self.storage_mode == 'xfs'):
            raise RuntimeError('Actual quota enforcement differs from the benchmark storage mode')
        self.receipt['quotaEnforced'] = actual_quotas
        self.daemon_pid = int(call('systemctl', 'show', self.unit, '-p', 'MainPID', '--value').stdout)
        membership = Path(f'/proc/{self.daemon_pid}/cgroup').read_text().strip().split(':', 2)
        if membership[:2] != ['0', ''] or not membership[2].startswith('/'):
            raise RuntimeError('Invalid daemon cgroup v2 membership')
        self.daemon_group = Path('/sys/fs/cgroup') / membership[2].lstrip('/')
        if not self.daemon_group.is_relative_to(self.pool_group):
            raise RuntimeError('Daemon is outside the measured slice')
        self.workloads_group = self.daemon_group.parent / 'workloads'
        if self.daemon_group.name != 'daemon' or not self.workloads_group.is_dir():
            raise RuntimeError('Missing distinct daemon and workload cgroups')
        daemon_limits = {name: int((self.daemon_group / name).read_text()) for name in
                         ('memory.max', 'memory.swap.max', 'pids.max')}
        if daemon_limits != {'memory.max': 536870912, 'memory.swap.max': 0, 'pids.max': 2048}:
            raise RuntimeError('Daemon leaf no longer has the W0 limits')
        self.receipt['daemonEffectiveLimits'] = daemon_limits
        self.receipt['binaryBytes'] = self.binary.stat().st_size

    def start(self):
        call('systemd-run', '--quiet', '--collect', '--unit', self.unit, '--slice', self.slice,
             '-p', 'Delegate=yes', '-p', 'MemorySwapMax=0', '-p', 'TasksMax=infinity',
             '-p', 'OOMPolicy=continue', '-p', 'OOMScoreAdjust=-900', '-p', 'RuntimeMaxSec=5400',
             '-p', 'Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin', '-p', 'KillMode=control-group',
             str(self.binary), 'serve', '--config', str(self.config))
        self.wait_ready()

    def unmount_fixture(self, mount):
        if mount == self.storage_mount:
            call('umount', str(mount))
        elif mount.name == 'work' and mount.parent.parent == self.socket.parent / 'jobs':
            import uuid
            uuid.UUID(mount.parent.name)
            call('umount', str(mount))
        else:
            super().unmount_fixture(mount)

    def cleanup(self):
        try:
            super().cleanup()
        finally:
            os.close(self.host_lock)
