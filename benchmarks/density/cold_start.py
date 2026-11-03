#!/usr/bin/env python3
"""Trace a new session's cgroup creation, launcher placement and sandbox exec."""
import argparse
import asyncio
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time
import traceback

from density import save
from engine import Engine
from host import Fixture


def program(name, daemon_group, workloads_group, launcher=None):
    if not re.fullmatch(r'sandcrab-probe-[a-f0-9]{10}', name) or min(daemon_group, workloads_group) <= 0:
        raise ValueError('Invalid trace namespace')
    # Parent cgroup IDs avoid path truncation and work in a cgroup namespace.
    # Exec identity comes from the kernel; no process argv pointers are read.
    source = f'''
BEGIN {{ printf("READY\\t%llu\\n", nsecs); }}
rawtracepoint:cgroup_mkdir {{
 $group = (struct cgroup *)arg0;
 $parent = $group->self.parent;
 if ((uint64)$parent != 0) {{
  $parent_id = $parent->cgroup->kn->id;
  if ($parent_id == {workloads_group} || @owned[$parent_id]) {{
   $id = $group->kn->id;
   @owned[$id] = 1;
   printf("%llu\\tgroup\\t%llu\\t%llu\\n", nsecs, $id, $parent_id);
  }}
 }}
}}
rawtracepoint:sched_process_fork {{
 $child = (struct task_struct *)arg1;
 $id = $child->cgroups->dfl_cgrp->kn->id;
 if ($child->pid == $child->tgid && @owned[$id]) {{
  printf("%llu\\tbirth\\t%u\\t%llu\\n", nsecs, $child->tgid, $id);
 }}
}}
tracepoint:cgroup:cgroup_attach_task /@owned[args->dst_id]/ {{
 printf("%llu\\tattach\\t%u\\t%llu\\n", nsecs, args->pid, args->dst_id);
}}
tracepoint:sched:sched_process_exec /cgroup == {daemon_group} || @owned[cgroup]/ {{
 printf("%llu\\texec\\t%u\\t%llu\\t%s\\n", nsecs, pid, cgroup, str(args->filename));
}}
tracepoint:sched:sched_process_exit /pid == tid && (cgroup == {daemon_group} || @owned[cgroup])/ {{
 printf("%llu\\texit\\t%u\\t%llu\\n", nsecs, pid, cgroup);
}}
'''
    cleanup = 'clear(@owned);'
    if launcher is not None:
        if not re.fullmatch(r'/var/lib/sandcrab-native-[a-zA-Z0-9_-]+/sandcrab', launcher):
            raise ValueError('Invalid traced launcher path')
        source += f'''
tracepoint:sched:sched_process_exec /cgroup == {daemon_group}/ {{
 if (str(args->filename) == "{launcher}") {{ @tracking[pid] = 1; }}
}}
tracepoint:raw_syscalls:sys_enter /@tracking[pid] && @count[pid] < 256/ {{
 @count[pid] = @count[pid] + 1;
 @started[tid] = nsecs;
 @number[tid] = args->id;
}}
tracepoint:raw_syscalls:sys_exit /@started[tid]/ {{
 printf("%llu\\tsyscall\\t%u\\t%u\\t%llu\\t%lld\\n", nsecs, pid, @number[tid], nsecs - @started[tid], args->ret);
 delete(@started[tid]); delete(@number[tid]);
}}
tracepoint:cgroup:cgroup_attach_task /@tracking[args->pid]/ {{
 delete(@tracking[args->pid]); delete(@count[args->pid]);
}}
tracepoint:sched:sched_process_exit /@tracking[pid]/ {{
 delete(@tracking[pid]); delete(@count[pid]); delete(@started[tid]); delete(@number[tid]);
}}
'''
        cleanup += ' clear(@tracking); clear(@count); clear(@started); clear(@number);'
    return source + 'END { ' + cleanup + ' }\n'


def parse_event(line):
    values = line.rstrip('\n').split('\t')
    if len(values) == 4 and values[1] == 'group':
        return {'bootNs': int(values[0]), 'event': 'cgroup-created', 'cgroupId': int(values[2]),
                'parentCgroupId': int(values[3])}
    if len(values) == 5 and values[1] == 'exec' and values[4]:
        return {'bootNs': int(values[0]), 'event': 'exec', 'pid': int(values[2]),
                'cgroupId': int(values[3]), 'filename': values[4]}
    if len(values) == 4 and values[1] == 'exit':
        return {'bootNs': int(values[0]), 'event': 'exit', 'pid': int(values[2]), 'cgroupId': int(values[3])}
    if len(values) == 4 and values[1] == 'attach':
        return {'bootNs': int(values[0]), 'event': 'cgroup-placement', 'pid': int(values[2]), 'cgroupId': int(values[3])}
    if len(values) == 4 and values[1] == 'birth':
        return {'bootNs': int(values[0]), 'event': 'process-birth', 'pid': int(values[2]), 'cgroupId': int(values[3])}
    if len(values) == 6 and values[1] == 'syscall':
        return {'bootNs': int(values[0]), 'event': 'syscall', 'pid': int(values[2]),
                'number': int(values[3]), 'durationNs': int(values[4]), 'result': int(values[5])}
    raise ValueError('Unrecognized trace event')


def timeline(events, started, ready, session_group, launcher):
    observed = sorted((event for event in events if started <= event['bootNs'] <= ready), key=lambda event: event['bootNs'])
    points = {'apiSubmit': 0, 'apiReadyObserved': ready - started}
    launchers, candidates, births = {}, {}, {}
    owned = {session_group}
    placement = None
    for event in observed:
        label = None
        if event['event'] == 'cgroup-created':
            if event['parentCgroupId'] in owned:
                owned.add(event['cgroupId'])
            if event['cgroupId'] == session_group:
                label = 'sessionCgroupCreated'
        elif event['event'] == 'process-birth':
            births[event['pid']] = event
        elif event['event'] == 'cgroup-placement' and event['pid'] in candidates and event['cgroupId'] in owned:
            launchers[event['pid']] = event['cgroupId']
            points.setdefault('trustedLauncherExec', candidates[event['pid']]['bootNs'] - started)
            if 'launcherPlaced' not in points:
                placement = 'cgroup-attach-task'
                label = 'launcherPlaced'
        elif event['event'] == 'exec':
            if event['filename'] == launcher:
                candidates[event['pid']] = event
                birth = births.get(event['pid'])
                if event['cgroupId'] in owned and birth is not None and birth['cgroupId'] == event['cgroupId']:
                    launchers[event['pid']] = event['cgroupId']
                    label = 'trustedLauncherExec'
                    if 'launcherPlaced' not in points:
                        points['launcherPlaced'] = birth['bootNs'] - started
                        placement = 'sched-process-fork-child-cgroup'
            name = Path(event['filename']).name
            if name == 'bash' and event['cgroupId'] in owned:
                label = 'bashExec'
            # sandcrab_launch::exec replaces the launcher process with bwrap;
            # its version check is a separate child, never that same identity.
            if name == 'bwrap' and launchers.get(event['pid']) == event['cgroupId']:
                label = 'bwrapSandboxExec'
        elif event['event'] == 'exit':
            launchers.pop(event['pid'], None)
            candidates.pop(event['pid'], None)
            births.pop(event['pid'], None)
        if label and label not in points:
            points[label] = event['bootNs'] - started
    required = {'sessionCgroupCreated', 'trustedLauncherExec', 'launcherPlaced', 'bwrapSandboxExec', 'bashExec'}
    missing = sorted(required - points.keys())
    return {'status': 'INCOMPLETE' if missing else 'COMPLETE', 'missing': missing,
            'placementObservation': placement, 'nanosecondsFromSubmit': points, 'events': observed}


class Trace:
    def __init__(self, fixture):
        self.fixture = fixture
        self.events, self.diagnostics, self.errors = [], [], []
        self.ready = asyncio.Event()
        self.ready_ns, self.process = None, None
        self.readers = []
        self.bytes = 0
        self.unit = fixture.name + 'trace.service'

    async def consume(self, stream, stderr=False):
        line = ''
        try:
            while raw := await stream.readline():
                self.bytes += len(raw)
                if self.bytes > 262144:
                    raise RuntimeError('Fixture trace exceeds its output bound')
                line = raw.decode('utf-8', errors='strict')
                if stderr:
                    self.diagnostics.append(line)
                elif line.startswith('READY\t'):
                    self.ready_ns = int(line.split()[1])
                    self.ready.set()
                elif line.strip():
                    self.events.append(parse_event(line))
        except Exception as error:
            self.errors.append({'type': type(error).__name__, 'detail': str(error), 'line': line[:1024]})
            self.ready.set()
        finally:
            if not stderr:
                self.ready.set()

    async def start(self):
        if shutil.which('bpftrace') is None:
            raise RuntimeError('Install bpftrace on the isolated measurement host')
        kernel = tuple(int(value) for value in os.uname().release.split('-')[0].split('.')[:2])
        if kernel < (5, 7):
            raise RuntimeError('The trace clock requires Linux 5.7+ CLOCK_BOOTTIME')
        self.version = subprocess.check_output(['bpftrace', '--version'], text=True, timeout=10).strip()
        source = program(self.fixture.name, self.fixture.daemon_group.stat().st_ino,
                         self.fixture.workloads_group.stat().st_ino,
                         str(self.fixture.binary) if getattr(self.fixture, 'trace_syscalls', False) else None)
        self.source_sha256 = hashlib.sha256(source.encode()).hexdigest()
        before = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        self.process = await asyncio.create_subprocess_exec(
            'systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit', self.unit,
            '--slice', self.fixture.slice, '-p', 'MemoryMax=512M', '-p', 'MemorySwapMax=0',
            '-p', 'TasksMax=128', '-p', 'CPUQuota=100%', '-p', 'RuntimeMaxSec=120',
            '-p', 'TimeoutStopSec=5', '-p', 'KillMode=control-group',
            '-p', 'BindsTo=' + self.fixture.unit, '-p', 'After=' + self.fixture.unit,
            '/usr/bin/env', 'BPFTRACE_MAX_STRLEN=128', 'bpftrace', '-q', '-B', 'line', '-e', source,
            start_new_session=True,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        self.readers = [asyncio.create_task(self.consume(self.process.stdout)),
                        asyncio.create_task(self.consume(self.process.stderr, True))]
        await asyncio.wait_for(self.ready.wait(), 30)
        after = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        if self.ready_ns is None or not before <= self.ready_ns <= after or self.errors:
            raise RuntimeError('Trace attachment or CLOCK_BOOTTIME handshake failed')

    async def stop(self):
        if self.process is None:
            return {'status': 'NOT_STARTED'}
        forced = False
        if self.process.returncode is None:
            await asyncio.to_thread(subprocess.run, ['systemctl', 'kill', '--kill-whom=main', '--signal=SIGINT', self.unit],
                                    capture_output=True, timeout=10)
            try:
                await asyncio.wait_for(self.process.wait(), 10)
            except asyncio.TimeoutError:
                forced = True
                await asyncio.to_thread(subprocess.run, ['systemctl', 'stop', self.unit], capture_output=True, timeout=10)
                if self.process.returncode is None:
                    self.process.kill()
                await asyncio.wait_for(self.process.wait(), 5)
        await asyncio.gather(*self.readers)
        diagnostic = ''.join(self.diagnostics)
        valid = (self.process.returncode == 0 and not forced and not self.errors
                 and not re.search(r'lost\s+\d+\s+events|failed to probe_read', diagnostic, re.I))
        return {'status': 'PASS' if valid else 'FAIL', 'processExitCode': self.process.returncode,
                'forcedKill': forced, 'errors': self.errors, 'diagnostic': diagnostic,
                'clock': 'CLOCK_BOOTTIME', 'version': getattr(self, 'version', None),
                'resourceLimits': {'memoryBytes': 536870912, 'swapBytes': 0, 'tasks': 128, 'cpuQuotaPercent': 100,
                                   'runtimeSeconds': 120, 'insideMeasuredSlice': True},
                'sourceSha256': getattr(self, 'source_sha256', None), 'events': self.events}


async def measure(fixture, receipt, report, trials, with_volume=False, with_template=False):
    engine = Engine(fixture.socket, fixture.info['serverId'])
    trace = Trace(fixture)
    receipt['trials'] = []
    try:
        volume = await engine.volume() if with_volume else None
        template = await engine.template() if with_template else None
        receipt['volumeId'] = volume
        receipt['templateId'] = template
        await trace.start()
        for _ in range(trials):
            item = {'status': 'STARTING', 'submitBootNs': time.clock_gettime_ns(time.CLOCK_BOOTTIME)}
            receipt['trials'].append(item)
            session, elapsed = await engine.session(volume, template=template)
            item.update(readyBootNs=time.clock_gettime_ns(time.CLOCK_BOOTTIME), session=session,
                        apiElapsedMonotonicNs=elapsed)
            group = fixture.workloads_group / ('session-' + session)
            item['sessionCgroupId'] = group.stat().st_ino
            await engine.close(session)
            item['status'] = 'OBSERVED'
            save(report, receipt)
        receipt['measurementStatus'] = 'COMPLETED'
    finally:
        try:
            receipt['tracer'] = await trace.stop()
        finally:
            receipt['apiCleanup'] = await engine.cleanup()
            if receipt['apiCleanup']['result'] != 'PASS':
                receipt['measurementStatus'] = 'ERROR'
            save(report, receipt)
    for item in receipt['trials']:
        item['timeline'] = timeline(receipt['tracer']['events'], item['submitBootNs'], item['readyBootNs'],
                                    item['sessionCgroupId'], str(fixture.binary))
        item['status'] = item['timeline']['status']
    if receipt['tracer']['status'] != 'PASS' or any(item['status'] != 'COMPLETE' for item in receipt['trials']):
        receipt['measurementStatus'] = 'ERROR'
        raise RuntimeError('Required startup events were not completely observed')
    save(report, receipt)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--budget', type=int, choices=(4, 5, 8), default=5)
    parser.add_argument('--smoke', action='store_true')
    workspace = parser.add_mutually_exclusive_group()
    workspace.add_argument('--volume', action='store_true', help='Trace attachment of a prepared empty XFS volume')
    workspace.add_argument('--template', action='store_true', help='Trace attachment of an imported empty template')
    parser.add_argument('--syscalls', action='store_true', help='Record at most 256 pre-placement syscalls per launcher, without arguments')
    args = parser.parse_args()
    report = args.report.resolve()
    if report.exists() or report.with_name(report.name + '.pending').exists():
        raise SystemExit('Preserve the previous receipt; select a new report path')
    report.parent.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).resolve().parents[2]
    git = ['git', '-c', 'safe.directory=' + str(source), '-C', str(source)]
    receipt = {'schema': 1, 'kind': 'sandcrab-cold-start-smoke' if args.smoke else 'sandcrab-cold-start',
               'started': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'sourceCommit': subprocess.check_output([*git, 'rev-parse', 'HEAD'], text=True).strip(),
               'sourceDirty': bool(subprocess.check_output([*git, 'status', '--porcelain'], text=True).strip()),
               'sourceSha256': {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in Path(__file__).parent.glob('*.py')},
               'scope': 'Traced persistent-session startup, diagnostic timing with observer overhead. '
                        'Use density coldStartNs for untraced latency distributions. No model or private content.',
               'parameters': {'trials': 3, 'workspace': 'empty-template' if args.template else ('empty-volume' if args.volume else 'ephemeral'),
                              'prePlacementSyscalls': args.syscalls},
               'measurementStatus': 'STARTING', 'apiCleanup': 'NOT_RUN', 'hostCleanup': 'NOT_RUN',
               'modelTokens': 0, 'containsProductionContent': False}
    with report.open('x') as output:
        json.dump(receipt, output)
    def interrupted(signum, frame):
        raise KeyboardInterrupt('Startup trace interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    fixture = None
    try:
        fixture = Fixture(args.binary.resolve(), args.tools.resolve(), report,
                          1024**3 if args.smoke else args.budget * 1_000_000_000, args.smoke)
        fixture.trace_syscalls = args.syscalls
        fixture.setup()
        receipt['fixture'] = fixture.receipt
        asyncio.run(measure(fixture, receipt, report, receipt['parameters']['trials'], args.volume, args.template))
    except BaseException as error:
        receipt.update(measurementStatus='ERROR', errorType=type(error).__name__)
        report.with_suffix('.diagnostic.txt').write_text(traceback.format_exc())
        raise
    finally:
        try:
            if fixture is not None:
                fixture.cleanup()
                receipt['hostCleanup'] = 'PASS'
        except BaseException:
            receipt.update(measurementStatus='ERROR', hostCleanup='UNCONFIRMED')
            raise
        finally:
            if fixture is not None:
                receipt['fixture'] = fixture.receipt
            receipt['finished'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            save(report, receipt)
    if receipt['measurementStatus'] != 'COMPLETED':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
