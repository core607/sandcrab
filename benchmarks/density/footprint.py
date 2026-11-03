#!/usr/bin/env python3
"""Native idle-session and finite-run cost; minimal workload bytes remain in the measurement."""
import argparse
import asyncio
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import statistics
import struct
import subprocess
import time
import traceback

from density import save
from engine import Engine
from host import Fixture
from metrics import Metrics

COUNTS = (1, 10, 50)
SAMPLES = 5


def binary_footprint(path):
    data = path.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01' or len(data) < 64 or struct.unpack_from('<H', data, 18)[0] != 62:
        raise ValueError('Expected an ELF64 little-endian x86_64 executable')
    offset = struct.unpack_from('<Q', data, 32)[0]
    entry_size, count = struct.unpack_from('<HH', data, 54)
    if entry_size != 56 or not 1 <= count <= 4096 or offset + count * entry_size > len(data):
        raise ValueError('Invalid ELF program-header bounds')
    interpreter, needed = False, 0
    for index in range(count):
        header = struct.unpack_from('<IIQQQQQQ', data, offset + index * entry_size)
        kind, _, start, _, _, size, _, _ = header
        if start + size > len(data):
            raise ValueError('ELF segment exceeds the file')
        interpreter |= kind == 3
        if kind == 2:
            if size % 16:
                raise ValueError('Invalid ELF dynamic segment')
            for position in range(start, start + size, 16):
                tag, _ = struct.unpack_from('<QQ', data, position)
                if tag == 0:
                    break
                needed += tag == 1
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'elfInterpreter': interpreter, 'dynamicNeededEntries': needed,
            'static': not interpreter and needed == 0}


def cost(baseline, active, count):
    """Retain negative deltas: a shared-cache release must not be rewritten as zero."""
    def med(rows, name):
        return statistics.median(row[name] for row in rows)

    result = {name: (med(active, name) - med(baseline, name)) / count
              for name in ('memoryCurrentBytes', 'daemonRssBytes', 'pidsCurrent')}
    result['memoryStat'] = {key: (statistics.median(row['memoryStat'][key] for row in active)
                                  - statistics.median(row['memoryStat'][key] for row in baseline)) / count
                            for key in ('anon', 'file', 'shmem', 'kernel')}
    return result


def dependency_inventory(binary, tools):
    # Required executable surfaces, not a distribution package/dependency-closure count.
    groups = {
        'core': {'id': 'validate the execution account during service startup',
                 'mount': 'bounded workspace and private temporary storage',
                 'umount': 'workspace cleanup'},
        'sessions': {'bash': 'persistent shell'},
        'durableVolumes': {'/usr/bin/cp': 'clone volume data with reflink or ordinary copy'},
        'projectQuotas': {'findmnt': 'verify the optional XFS mount',
                          '/usr/sbin/xfs_io': 'project identity', '/usr/sbin/xfs_quota': 'project quotas'},
    }
    import shutil
    observed = {}
    for group, programs in groups.items():
        observed[group] = [{'program': name, 'purpose': purpose, 'present': shutil.which(name) is not None}
                           for name, purpose in programs.items()]
    helper = binary.with_name('bwrap')
    observed['core'].append({'program': 'bundled bwrap',
                             'purpose': 'namespace, mount isolation and compiled seccomp filter',
                             'present': helper.is_file(), **binary_footprint(helper)})
    return {'runtimeExecutables': observed,
            'runtimeExecutableCount': sum(len(rows) for rows in observed.values()),
            'runtimeExecutableCountWithoutProjectQuotas': sum(len(rows) for group, rows in observed.items()
                                                               if group != 'projectQuotas'),
            'countScope': 'Distinct command executables used by the current native implementation; '
                          'includes optional sessions and durable volumes; excludes shared-library closure and workload tools',
            'preparationOnly': [{'name': 'apt/dpkg-deb', 'purpose': 'extract distribution sandbox tools'}],
            'preparedTreeBytes': sum(path.stat().st_size for path in tools.rglob('*') if path.is_file() and not path.is_symlink()),
            'platform': ['Linux cgroup v2 delegation', 'user namespaces', 'ordinary directories for durable volumes'],
            'optionalPlatform': ['Dedicated XFS mount with project quotas for enforced storage limits']}


async def measure(fixture, receipt, counts, report, ledger, workspace_mode='ephemeral'):
    def emit(phase, row):
        ledger.write(json.dumps({'event': phase, **row}, separators=(',', ':')) + '\n')
        ledger.flush()

    engine = Engine(fixture.socket, fixture.info['serverId'], emit)
    metrics = Metrics(fixture)

    async def samples(sessions, finite):
        values = []
        for _ in range(SAMPLES):
            value = metrics.sample(sum(state == 'running' for state in engine.executing.values()))
            if (value['liveKernelSessions'], value['liveKernelFiniteRuns']) != (sessions, finite):
                raise RuntimeError('The requested idle/finite cohort is not alive')
            if value['oomKills'] or value['hostAvailableBytes'] < 256 * 1024**2:
                raise RuntimeError('OOM or host reserve failure during footprint sampling')
            values.append(value)
            await asyncio.sleep(1)
        return values

    try:
        receipt['binary'] = binary_footprint(fixture.binary)
        if not receipt['binary']['static']:
            raise RuntimeError('The footprint artifact is not static')
        receipt['dependencies'] = dependency_inventory(fixture.binary, fixture.tools_path)
        receipt['daemonIdle'] = await samples(0, 0)
        template = await engine.template() if workspace_mode == 'template' else None
        baseline = receipt['daemonIdle']
        if template:
            receipt['emptyTemplateId'] = template
            receipt['templateBaseline'] = await samples(0, 0)
            baseline = receipt['templateBaseline']
        receipt['idleSessions'] = []
        live = 0
        for count in counts:
            item = {'count': count, 'status': 'STARTING', 'coldStartNs': []}
            receipt['idleSessions'].append(item)
            save(report, receipt)
            while live < count:
                _, elapsed = await engine.session(template=template)
                item['coldStartNs'].append(elapsed)
                live += 1
            await asyncio.sleep(2)
            item['samples'] = await samples(count, 0)
            item['medianDeltaPerSession'] = cost(baseline, item['samples'], count)
            item['status'] = 'COMPLETED'
            save(report, receipt)
        receipt['idleCleanup'] = await engine.cleanup()
        if receipt['idleCleanup']['result'] != 'PASS':
            raise RuntimeError('Idle cohort cleanup unconfirmed')
        receipt['finiteRuns'] = []
        for count in counts:
            item = {'count': count, 'status': 'STARTING', 'baseline': await samples(0, 0)}
            receipt['finiteRuns'].append(item)
            save(report, receipt)
            tasks = [asyncio.create_task(engine.execute(None, ['/bin/sleep', '30'], timeout_ms=45000, kind='finite'))
                     for _ in range(count)]
            try:
                deadline = time.monotonic() + 15
                while metrics.sample()['liveKernelFiniteRuns'] != count:
                    if time.monotonic() >= deadline or any(task.done() for task in tasks):
                        raise RuntimeError('Finite cohort did not reach its full holding population')
                    await asyncio.sleep(.05)
                await asyncio.sleep(2)
                item['samples'] = await samples(0, count)
                item['medianDeltaPerRun'] = cost(item['baseline'], item['samples'], count)
                item['results'] = await asyncio.gather(*tasks)
                if any(row['outcome'] != 'OK' or row.get('fatal') for row in item['results']):
                    raise RuntimeError('Finite footprint command failed')
                item['status'] = 'COMPLETED'
            finally:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
            item['apiCleanup'] = await engine.cleanup()
            if item['apiCleanup']['result'] != 'PASS':
                raise RuntimeError('Finite cohort cleanup unconfirmed')
            save(report, receipt)
        receipt['measurementStatus'] = 'COMPLETED'
    finally:
        receipt['apiCleanup'] = await engine.cleanup()
        if receipt['apiCleanup']['result'] != 'PASS':
            receipt['measurementStatus'] = 'ERROR'
        save(report, receipt)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--budget', type=int, choices=(4, 5, 8), default=5)
    parser.add_argument('--smoke', action='store_true')
    parser.add_argument('--workspace', choices=('ephemeral', 'template'), default='ephemeral')
    args = parser.parse_args()
    report = args.report.resolve()
    ledger = report.with_suffix('.attempts.jsonl')
    if any(path.exists() for path in (report, ledger, report.with_name(report.name + '.pending'))):
        raise SystemExit('Preserve the previous receipt; select a new report path')
    report.parent.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).resolve().parents[2]
    git = ['git', '-c', 'safe.directory=' + str(source), '-C', str(source)]
    receipt = {'schema': 1, 'kind': 'sandcrab-footprint-smoke' if args.smoke else 'sandcrab-footprint',
               'started': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'sourceCommit': subprocess.check_output([*git, 'rev-parse', 'HEAD'], text=True).strip(),
               'sourceDirty': bool(subprocess.check_output([*git, 'status', '--porcelain'], text=True).strip()),
               'sourceSha256': {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in Path(__file__).parent.glob('*.py')},
               'parameters': {'counts': [1] if args.smoke else list(COUNTS), 'samples': SAMPLES, 'workspace': args.workspace,
                              'sampleIntervalSeconds': 1, 'settleSeconds': 2, 'finiteHoldSeconds': 30},
               'scope': 'Idle bash sessions and minimal finite /bin/sleep workloads; includes their memory. '
                        'Volume capability enabled, with no volume data. No density or readiness claim.',
               'measurementStatus': 'STARTING', 'apiCleanup': 'NOT_RUN', 'hostCleanup': 'NOT_RUN',
               'modelTokens': 0, 'containsProductionContent': False}
    with report.open('x') as output:
        json.dump(receipt, output)
    def interrupted(signum, frame):
        raise KeyboardInterrupt('Footprint measurement interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    fixture = None
    try:
        fixture = Fixture(args.binary.resolve(), args.tools.resolve(), report,
                          1024**3 if args.smoke else args.budget * 1_000_000_000, args.smoke)
        fixture.tools_path = args.tools.resolve()
        fixture.setup()
        receipt['fixture'] = fixture.receipt
        with ledger.open('x', buffering=1) as output:
            asyncio.run(measure(fixture, receipt, receipt['parameters']['counts'], report, output, args.workspace))
            os.fsync(output.fileno())
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
