#!/usr/bin/env python3
"""Compare monolithic environments with shared recipe layers on a disposable host."""
import argparse
import asyncio
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import shlex
import signal
import stat
import time
import traceback

from density import save
from engine import Engine
from host import Fixture, fields
from metrics import Metrics
from page_cache import reader, residency
from workload import document_path
from sandcrab_conformance.runner import execute_fixture

SEED = 20261109
FILE_BYTES = 65536
SETTLE_SECONDS = 2.1


def corpus(root, files):
    root.mkdir()
    digest, changed = hashlib.sha256(), hashlib.sha256()
    for index in range(files):
        name = document_path(index)
        body = hashlib.sha256(f'{SEED}:{index}'.encode()).digest() * (FILE_BYTES // 32)
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        path.chmod(0o644)
        digest.update(name.encode() + b'\0' + body)
        changed.update(name.encode() + b'\0!' + body[1:])
    shape = {'files': files, 'bytes': files * FILE_BYTES}
    return {**shape, 'sha256': digest.hexdigest()}, {**shape, 'sha256': changed.hexdigest()}


def pressure(path):
    return {line.split()[0]: {key: (int(value) if key == 'total' else float(value))
            for key, value in (field.split('=') for field in line.split()[1:])}
            for line in path.read_text().splitlines()}


def sample(fixture):
    result = Metrics(fixture).sample()
    result['cpuStat'] = fields(fixture.pool_group / 'cpu.stat')
    result['workloadMemoryStat'] = {key: value for key, value in fields(fixture.workloads_group / 'memory.stat').items()
                                    if key in ('anon', 'file', 'kernel', 'shmem')}
    result['pressure'] = {kind: pressure(fixture.pool_group / (kind + '.pressure')) for kind in ('cpu', 'io', 'memory')}
    result['ioByDevice'] = {line.split()[0]: {key: int(value) for key, value in
        (field.split('=') for field in line.split()[1:])} for line in (fixture.pool_group / 'io.stat').read_text().splitlines()}
    return result


def latency(rows):
    elapsed = sorted(row['elapsedNs'] for row in rows)
    success = sum(row['outcome'] == 'OK' and not row.get('fatal') for row in rows)
    return {'attempts': len(rows), 'successful': success, 'refusedOrFailed': len(rows) - success,
            'p50Ns': elapsed[math.ceil(len(elapsed) * .5) - 1],
            'p95Ns': elapsed[math.ceil(len(elapsed) * .95) - 1],
            'p99Ns': elapsed[math.ceil(len(elapsed) * .99) - 1]}


def upper_files(fixture, sessions):
    total = {'files': 0, 'logicalBytes': 0, 'allocatedBytes': 0}
    identities = set()
    for identity in sessions:
        root = fixture.socket.parent / 'workspace-overlays' / identity / 'upper/data/corpus'
        if not root.exists():
            continue
        for path in root.rglob('*'):
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) in identities:
                raise RuntimeError('Copy-up file type or private identity changed')
            identities.add((info.st_dev, info.st_ino))
            total['files'] += 1
            total['logicalBytes'] += info.st_size
            total['allocatedBytes'] += info.st_blocks * 512
    return {**total, 'distinctInodes': len(identities)}


def writer():
    code = '''import os,pathlib
for path in sorted(pathlib.Path('corpus').glob('group-*/document-*.md')):
 with path.open('r+b') as output:
  output.write(b'!'); output.flush(); os.fsync(output.fileno())
'''
    return 'python3 -c ' + shlex.quote(code) + ' && ' + reader('/workspace')


class ReuseEngine(Engine):
    def __init__(self, *args):
        super().__init__(*args)
        self.recipes = set()

    async def compose(self, layers):
        digest = hashlib.sha256(b'sandcrab-template-recipe-v1\0' + len(layers).to_bytes(4, 'little'))
        for layer in layers:
            digest.update(layer.encode('ascii'))
        identity = digest.hexdigest()
        self.recipes.add(identity)
        _, value = await self.call('POST', '/v1/templates/compose', {'layers': layers})
        if value.get('id') != identity or value.get('layers') != layers:
            raise RuntimeError('Recipe publication identity changed')
        return identity

    async def cleanup(self):
        failures = []
        # Recipes hold leaf references. Contain users before deleting recipes,
        # then let the existing engine reconcile runs, leaf trees and inventory.
        for identity in list(self.sessions):
            try:
                await self.close(identity)
            except Exception as error:
                failures.append(type(error).__name__)
        for identity in list(self.recipes):
            try:
                await self.call('DELETE', '/v1/templates/' + identity, allowed=(200, 404))
                self.recipes.remove(identity)
            except Exception as error:
                failures.append(type(error).__name__)
        result = await super().cleanup()
        failures += result['failures']
        return {'result': 'FAIL' if failures else 'PASS', 'failures': failures}


async def exercise(fixture, item, ledger, files, mode, count):
    def emit(event, value):
        ledger.write(json.dumps({'event': event, **value}, separators=(',', ':')) + '\n')
        ledger.flush()
        if event == 'template-import-created':
            item['importedBytes'] += value['archiveBytes']
    engine = ReuseEngine(fixture.socket, fixture.info['serverId'], emit)
    item.update(importedBytes=0, phases=[], startNs=[], compositionNs=[])
    source = fixture.root / 'source'
    expected, changed = corpus(source, files)
    workspace = fixture.root / 'workspace-source'
    workspace.mkdir()
    roots, sessions = [], []
    started = time.monotonic_ns()
    item['beforePreparation'] = sample(fixture)
    failure = None
    try:
        common = await engine.template(source) if mode == 'recipe' else None
        for index in range(count):
            identity_file = (workspace if common else source) / 'workspace-id'
            identity_file.write_text(str(index))
            identity_file.chmod(0o644)
            leaf = await engine.template(workspace if common else source)
            if common:
                composing = time.monotonic_ns()
                template = await engine.compose([common, leaf])
                item['compositionNs'].append(time.monotonic_ns() - composing)
            else:
                template = leaf
            session, elapsed = await engine.session(template=template)
            item['startNs'].append(elapsed)
            sessions.append(session)
            if not common or index == 0:
                root = fixture.socket.parent / 'templates/objects' / (common or leaf) / 'lower/data'
                if root.is_symlink() or not root.resolve(strict=True).is_relative_to(fixture.root):
                    raise RuntimeError('Unexpected fixture layer path')
                roots.append(root)
        item['preparationNs'] = time.monotonic_ns() - started
        await asyncio.sleep(SETTLE_SECONDS)
        item['afterPreparation'] = sample(fixture)
        _, catalog = await engine.call('GET', '/v1/templates')
        item['templatePool'] = catalog['pool']
        recipe_root = fixture.socket.parent / 'templates/recipes'
        item['recipeMetadataBytes'] = sum(path.stat().st_size for path in recipe_root.glob('*/record.json')) if recipe_root.exists() else 0
        rows = await asyncio.gather(*(engine.execute(session, 'cat workspace-id', kind='verify-workspace') for session in sessions))
        if any(row['outcome'] != 'OK' or row.get('fatal') or row.get('stdout') != str(index) for index, row in enumerate(rows)):
            raise RuntimeError('Workspace identity or setup execution failed')
        item['coldResidency'] = residency(roots, files, evict=True)
        if item['coldResidency']['residentPages']:
            raise RuntimeError('File-specific eviction did not establish cold pages')
        await asyncio.sleep(SETTLE_SECONDS)
        item['beforeReadCopyUp'] = upper_files(fixture, sessions)
        if item['beforeReadCopyUp']['files']:
            raise RuntimeError('Preparation copied immutable corpus data')
        for phase in ('cold-read', 'warm-read', 'write-heavy'):
            row = {'phase': phase, 'before': sample(fixture)}
            item['phases'].append(row)
            begin = time.monotonic_ns()
            commands = await asyncio.gather(*(engine.execute(session, writer() if phase == 'write-heavy' else reader('/workspace'),
                kind=phase, timeout_ms=60000) for session in sessions))
            row['wallNs'] = time.monotonic_ns() - begin
            # Hierarchical memory.stat batches per-CPU updates. Quiescence stays
            # outside measured command wall time and precedes the endpoint read.
            await asyncio.sleep(SETTLE_SECONDS)
            row['after'] = sample(fixture)
            row['latency'] = latency(commands)
            row['successfulPerSecond'] = row['latency']['successful'] * 1_000_000_000 / row['wallNs']
            row['commands'] = commands
            row['lowerResidency'] = residency(roots, files)
            row['copyUp'] = upper_files(fixture, sessions)
            row['applicationWriteBytes'] = files * count if phase == 'write-heavy' else 0
            wanted = changed if phase == 'write-heavy' else expected
            if any(command['outcome'] != 'OK' or command.get('fatal') or json.loads(command.get('stdout', '{}')) != wanted for command in commands):
                raise RuntimeError('A measured command failed independent complete-corpus readback')
            if phase != 'write-heavy' and row['copyUp']['files']:
                raise RuntimeError('Readers copied up immutable data')
            if phase == 'write-heavy' and row['copyUp']['files'] != files * count:
                raise RuntimeError('Write-heavy copy-up inventory differs from the commanded files')
            if row['after']['oomKills'] != row['before']['oomKills']:
                raise RuntimeError('OOM during the targeted comparison')
        # Read lower content independently after measurements; no workload report
        # can establish that it left other consumers' immutable data intact.
        for root in roots:
            digest = hashlib.sha256()
            for index in range(files):
                name = document_path(index)
                digest.update(name.encode() + b'\0' + (root / name).read_bytes())
            if digest.hexdigest() != expected['sha256']:
                raise RuntimeError('Shared immutable source changed')
        item['immutableReadback'] = 'PASS'
        item['status'] = 'PASS'
    except BaseException as error:
        failure = error
        raise
    finally:
        item['apiCleanup'] = await engine.cleanup()
        if item['apiCleanup']['result'] != 'PASS':
            item['status'] = 'FAIL'
            if failure is None:
                raise RuntimeError('Preparation comparison API cleanup unconfirmed')


class ReuseFixture(Fixture):
    io_accounting = True

    def configure(self, tools, memory, free):
        super().configure(tools, memory, free)
        self.config.write_text(self.config.read_text().replace('[storage]',
            'max_templates = 128\ntemplate_pool_bytes = 536870912\n[storage]', 1))
        self.receipt['configSha256'] = hashlib.sha256(self.config.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True, help='Recipe-capable candidate binary')
    parser.add_argument('--baseline-binary', type=Path, required=True, help='Unmodified pre-recipe binary')
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='New raw evidence directory')
    parser.add_argument('--smoke', action='store_true', help='One reader and four files per mode; protocol check only')
    args = parser.parse_args()
    for binary in (args.binary, args.baseline_binary):
        if not binary.is_file() or not binary.with_name('bwrap').is_file():
            parser.error('Each binary needs its verified bundled bwrap beside it')
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    counts, repetitions, files = ([1], 1, 4) if args.smoke else ([1, 10, 50], 2, 64)
    report = args.output / 'results.json'
    receipt = {'schema': 1, 'kind': 'preparation-reuse-smoke' if args.smoke else 'preparation-reuse',
        'started': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'result': 'RUNNING', 'cases': [],
        'parameters': {'readers': counts, 'repetitions': repetitions, 'files': files, 'bytesPerFile': FILE_BYTES,
                       'memoryMaxBytes': 1024**3, 'cpuQuotaPercent': 200, 'swapBytes': 0,
                       'kernelObservationSettleSeconds': SETTLE_SECONDS,
                       'cachePolicy': 'Only fixture files: fsync, POSIX_FADV_DONTNEED, root mincore verification'},
        'binaries': {name: {'bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                     for name, path in [('baseline', args.baseline_binary), ('candidate', args.binary)]},
        'sourceSha256Lf': {path.name: hashlib.sha256(path.read_bytes().replace(b'\r\n', b'\n')).hexdigest()
                           for path in Path(__file__).parent.glob('*.py')},
        'scope': 'Targeted environment composition, cold/warm file cache and copy-up comparison. Distinct workspace content shares common dependencies. Existing sharing of one identical template is not a new gain. No density or production claim.',
        'counterLimits': 'io.stat devices may include stacked storage; do not sum devices. Allocated blocks do not identify unique physical extents. File includes shmem.',
        'modelTokens': 0, 'containsProductionContent': False}
    save(report, receipt)
    def interrupt(signum, frame):
        raise KeyboardInterrupt('Preparation comparison interrupted')
    signal.signal(signal.SIGTERM, interrupt)
    try:
        for repetition in range(repetitions):
            for count in counts:
                for mode in (('monolithic', 'recipe') if repetition % 2 == 0 else ('recipe', 'monolithic')):
                    name = f'{repetition + 1}-{count}-{mode}'
                    item = {'name': name, 'mode': mode, 'readers': count, 'repetition': repetition + 1, 'status': 'RUNNING'}
                    receipt['cases'].append(item)
                    save(report, receipt)
                    fixture = None
                    try:
                        binary = args.binary if mode == 'recipe' else args.baseline_binary
                        fixture = ReuseFixture(binary.resolve(), args.tools.resolve(), args.output / (name + '-fixture.json'), 1024**3, smoke=True)
                        def tests():
                            with (args.output / (name + '-requests.jsonl')).open('x', buffering=1) as ledger:
                                asyncio.run(exercise(fixture, item, ledger, files, mode, count))
                                os.fsync(ledger.fileno())
                        fixture.tests = tests
                        # The existing controller retains primary and cleanup failures.
                        execute_fixture('preparation', fixture, None)
                    except BaseException as error:
                        item.update(status='FAIL', failureType=type(error).__name__)
                        raise
                    finally:
                        if fixture:
                            item['hostCleanup'] = fixture.receipt.get('cleanup', 'UNCONFIRMED')
                            item['fixture'] = fixture.receipt
                        save(report, receipt)
                    print(name + ': PASS', flush=True)
        receipt['result'] = 'PASS'
    except BaseException as error:
        receipt.update(result='FAIL', failureType=type(error).__name__)
        (args.output / 'diagnostic.txt').write_text(traceback.format_exc(), encoding='utf-8')
        raise
    finally:
        receipt['finished'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save(report, receipt)


if __name__ == '__main__':
    main()
