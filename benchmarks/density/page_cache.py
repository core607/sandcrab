#!/usr/bin/env python3
"""Compare file-cache residency for reflink copies and a shared read-only synthetic tree."""
import argparse
import asyncio
import ctypes
import datetime
import hashlib
import json
import mmap
import os
from pathlib import Path
import shlex
import signal
import subprocess
import traceback

from density import save
from engine import Engine
from host import Fixture
from metrics import Metrics
from workload import create, document, document_path, FILES

SEED = 20261102
COPIES = 10


def residency(roots, files, *, evict=False):
    """Observe only fixture data pages. Never read file contents or drop global caches."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mincore.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_ubyte)]
    libc.mincore.restype = ctypes.c_int
    page_size = os.sysconf('SC_PAGE_SIZE')
    result = {'files': 0, 'payloadBytes': 0, 'pages': 0, 'residentPages': 0, 'pageBytes': page_size}
    identities = set()
    for root in roots:
        for index in range(files):
            path = root / document_path(index)
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                stat = os.fstat(descriptor)
                if not stat.st_size:
                    raise RuntimeError('Expected a nonempty synthetic document')
                identity = (stat.st_dev, stat.st_ino)
                if identity in identities:
                    raise RuntimeError('A purported separate copy reuses an inode')
                identities.add(identity)
                if evict:
                    os.fsync(descriptor)
                    os.posix_fadvise(descriptor, 0, 0, os.POSIX_FADV_DONTNEED)
                count = (stat.st_size + page_size - 1) // page_size
                bits = (ctypes.c_ubyte * count)()
                with mmap.mmap(descriptor, stat.st_size, flags=mmap.MAP_PRIVATE,
                               prot=mmap.PROT_READ | mmap.PROT_WRITE) as mapping:
                    address = ctypes.addressof(ctypes.c_char.from_buffer(mapping))
                    if libc.mincore(address, stat.st_size, bits):
                        raise OSError(ctypes.get_errno(), 'Fixture page residency unavailable')
                result['files'] += 1
                result['payloadBytes'] += stat.st_size
                result['pages'] += count
                result['residentPages'] += sum(value & 1 for value in bits)
            finally:
                os.close(descriptor)
    result['residentBytes'] = result['residentPages'] * page_size
    result['distinctInodes'] = len(identities)
    return result


class CacheFixture(Fixture):
    def configure(self, tools, memory, free):
        self.shared = self.root / 'shared-corpus'
        self.shared.mkdir()
        self.shared_manifest = create(self.shared, SEED, self.file_count)
        for path in self.shared.rglob('*'):
            if path.is_symlink():
                raise RuntimeError('Unexpected synthetic-tree symlink')
            path.chmod(0o555 if path.is_dir() else 0o444)
        self.shared.chmod(0o555)
        self.extra_reads = [str(self.shared)]
        super().configure(tools, memory, free)


def reader(root):
    # Validate the bytes read as well as the API status. Each command reads every
    # document once and returns a compact independent checksum.
    program = f'''import hashlib,json,pathlib
root=pathlib.Path({str(root)!r})
digest=hashlib.sha256(); count=0; size=0
for path in sorted((root/'corpus').glob('group-*/document-*.md')):
 body=path.read_bytes(); relative=path.relative_to(root).as_posix()
 digest.update(relative.encode()+b'\\0'+body); count+=1; size+=len(body)
print(json.dumps({{'files':count,'bytes':size,'sha256':digest.hexdigest()}}))
'''
    return 'python3 -c ' + shlex.quote(program)


async def measure(fixture, receipt, report, ledger, files):
    def emit(phase, row):
        ledger.write(json.dumps({'event': phase, **row}, separators=(',', ':')) + '\n')
        ledger.flush()

    engine = Engine(fixture.socket, fixture.info['serverId'], emit)
    metrics = Metrics(fixture)
    receipt['cases'] = []
    expected = {'files': files, 'bytes': sum(len(document(SEED, index)) for index in range(files)),
                'sha256': fixture.shared_manifest['corpusSha256']}
    try:
        base, manifest = await engine.seed(SEED, files)
        if manifest != fixture.shared_manifest:
            raise RuntimeError('The reflink and shared corpora differ')
        receipt['corpus'] = manifest
        for name in ('reflink', 'shared-read-only'):
            item = {'name': name, 'readers': COPIES, 'status': 'STARTING'}
            receipt['cases'].append(item)
            save(report, receipt)
            sessions, roots = [], []
            for _ in range(COPIES):
                volume = await engine.volume(base) if name == 'reflink' else None
                session, _ = await engine.session(volume)
                sessions.append(session)
                if volume:
                    # This is fixture-only kernel inspection, not a content API.
                    # The current storage owner places data below this exact root.
                    path = fixture.data / 'volumes' / volume / 'data'
                    if path.is_symlink() or not path.resolve(strict=True).is_relative_to(fixture.root):
                        raise RuntimeError('Unexpected fixture volume path')
                    roots.append(path)
            if name == 'shared-read-only':
                roots = [fixture.shared]
                readonly = await engine.execute(sessions[0], 'python3 -c ' + shlex.quote(
                    f'import os; print(bool(os.statvfs({str(fixture.shared)!r}).f_flag & os.ST_RDONLY))'))
                if readonly['outcome'] != 'OK' or readonly.get('fatal') or readonly.get('stdout') != 'True\n':
                    raise RuntimeError('The shared tree is not mounted read-only in the sandbox')
                item['readOnlyMountVerified'] = True
            item['coldResidency'] = residency(roots, files, evict=True)
            if item['coldResidency']['residentPages']:
                raise RuntimeError('File-specific eviction did not produce a cold dataset')
            await asyncio.sleep(1)
            item['beforeRead'] = metrics.sample()
            target = '/workspace' if name == 'reflink' else str(fixture.shared)
            item['commands'] = await asyncio.gather(*(engine.execute(session, reader(target), kind='cache-read')
                                                      for session in sessions))
            for row in item['commands']:
                if row['outcome'] != 'OK' or row.get('fatal') or json.loads(row.get('stdout', '{}')) != expected:
                    raise RuntimeError('A page-cache reader did not verify the entire corpus')
            item['afterRead'] = metrics.sample()
            item['warmResidency'] = residency(roots, files)
            item['fileCacheDeltaBytes'] = item['afterRead']['memoryStat']['file'] - item['beforeRead']['memoryStat']['file']
            item['oomKills'] = item['afterRead']['oomKills'] - item['beforeRead']['oomKills']
            if item['oomKills'] or item['afterRead']['hostAvailableBytes'] < 256 * 1024**2:
                raise RuntimeError('OOM or host reserve failure during cache comparison')
            item['apiCleanup'] = await engine.cleanup(keep_volumes=(base,))
            if item['apiCleanup']['result'] != 'PASS':
                raise RuntimeError('Page-cache cohort cleanup unconfirmed')
            item['status'] = 'COMPLETED'
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
    args = parser.parse_args()
    report = args.report.resolve()
    ledger_path = report.with_suffix('.attempts.jsonl')
    if any(path.exists() for path in (report, ledger_path, report.with_name(report.name + '.pending'))):
        raise SystemExit('Preserve the previous receipt; select a new report path')
    report.parent.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).resolve().parents[2]
    git = ['git', '-c', 'safe.directory=' + str(source), '-C', str(source)]
    files = 400 if args.smoke else FILES
    receipt = {'schema': 1, 'kind': 'sandcrab-cache-smoke' if args.smoke else 'sandcrab-cache',
               'started': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'sourceCommit': subprocess.check_output([*git, 'rev-parse', 'HEAD'], text=True).strip(),
               'sourceDirty': bool(subprocess.check_output([*git, 'status', '--porcelain'], text=True).strip()),
               'sourceSha256': {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in Path(__file__).parent.glob('*.py')},
               'parameters': {'seed': SEED, 'files': files, 'readers': COPIES,
                              'cachePolicy': 'fsync + per-file POSIX_FADV_DONTNEED, verified with root mincore'},
               'scope': 'Synthetic fixture only. Page residency and hierarchical file-cache deltas; '
                        'not a template API, cold-start latency or density measurement.',
               'measurementStatus': 'STARTING', 'apiCleanup': 'NOT_RUN', 'hostCleanup': 'NOT_RUN',
               'modelTokens': 0, 'containsProductionContent': False}
    with report.open('x') as output:
        json.dump(receipt, output)
    def interrupted(signum, frame):
        raise KeyboardInterrupt('Page-cache measurement interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    fixture = None
    try:
        CacheFixture.file_count = files
        fixture = CacheFixture(args.binary.resolve(), args.tools.resolve(), report,
                               1024**3 if args.smoke else args.budget * 1_000_000_000, args.smoke)
        fixture.setup()
        receipt['fixture'] = fixture.receipt
        with ledger_path.open('x', buffering=1) as ledger:
            asyncio.run(measure(fixture, receipt, report, ledger, files))
            os.fsync(ledger.fileno())
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
