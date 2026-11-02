"""Read hierarchical kernel counters without moving processes or resetting counters."""
import os
from pathlib import Path
import time
import uuid

from host import fields, host_memory


def process_cpu(pid):
    values = (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
    return (int(values[11]) + int(values[12])) / os.sysconf('SC_CLK_TCK')


class Metrics:
    def __init__(self, fixture):
        self.fixture = fixture

    def sample(self, executing=0):
        fixture = self.fixture
        memory = fields(fixture.pool_group / 'memory.stat')
        missing = {'anon', 'file', 'shmem', 'kernel'} - memory.keys()
        if missing:
            raise RuntimeError('Missing required memory.stat fields: ' + ','.join(sorted(missing)))
        total = fields(fixture.pool_group / 'cpu.stat')['usage_usec']
        daemon = fields(fixture.daemon_group / 'cpu.stat')['usage_usec']
        if daemon > total:
            # Counters are not one atomic snapshot. Resample the ancestor after the child.
            total = fields(fixture.pool_group / 'cpu.stat')['usage_usec']
        if daemon > total:
            raise RuntimeError('Inconsistent hierarchical CPU counters')
        live = 0
        for entry in fixture.workloads_group.glob('session-*'):
            try:
                live += fields(entry / 'cgroup.events')['populated'] == 1
            except FileNotFoundError:
                continue
        finite = 0
        for entry in fixture.workloads_group.glob('run-*'):
            identity = entry.name.removeprefix('run-')
            try:
                uuid.UUID(identity)
                finite += fields(entry / 'cgroup.events')['populated'] == 1
            except (ValueError, FileNotFoundError):
                continue
        rss = next(int(line.split()[1]) * 1024 for line in
                   (Path('/proc') / str(fixture.daemon_pid) / 'status').read_text().splitlines() if line.startswith('VmRSS:'))
        return {'monotonicNs': time.monotonic_ns(), 'memoryCurrentBytes': int((fixture.pool_group / 'memory.current').read_text()),
                'memoryStat': {name: memory[name] for name in ('anon', 'file', 'shmem', 'kernel')},
                'cpuUsec': {'pool': total, 'daemon': daemon, 'sandboxes': total - daemon},
                'oomKills': fields(fixture.pool_group / 'memory.events')['oom_kill'],
                'pidsCurrent': int((fixture.pool_group / 'pids.current').read_text()),
                'daemonRssBytes': rss, 'liveKernelSandboxes': live + finite,
                'liveKernelSessions': live, 'liveKernelFiniteRuns': finite,
                'executingObserved': executing, 'systemManagerCpuSecondsOutsideSlice': process_cpu(1),
                'hostAvailableBytes': host_memory()['MemAvailable']}
