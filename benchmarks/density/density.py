#!/usr/bin/env python3
"""Independent public-API density experiment; a smoke run is never a capacity result."""
import argparse
import asyncio
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import traceback

from engine import Engine, NativeFailure
from host import Fixture
from metrics import Metrics
from protocol import load
from scoring import summarize
from workload import AgentWorkload, FILES


def save(path, value):
    temporary = path.with_name(path.name + '.pending')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def retain(row, start):
    return {**{key: value for key, value in row.items() if key not in ('stdout', 'stderr', 'startedAbsoluteNs')},
            'startedNs': row['startedAbsoluteNs'] - start,
            'outputObserved': 'stdout' in row,
            'stdoutBytes': len(row['stdout'].encode()) if 'stdout' in row else None,
            'stderrBytes': len(row['stderr'].encode()) if 'stderr' in row else None,
            'stdoutSha256': hashlib.sha256(row['stdout'].encode()).hexdigest() if 'stdout' in row else None,
            'stderrPreview': row.get('stderr', '')[:256], 'stderrTail': row.get('stderr', '')[-1024:]}


async def stage(engine, metrics, base, agents, repetition, settings, files, publish):
    result = {'agents': agents, 'repetition': repetition, 'status': 'SETTING_UP', 'attempts': [], 'samples': [],
              'coldStartNs': [], 'admissionFailure': None, 'apiCleanup': 'NOT_RUN'}
    publish(result)
    before = metrics.sample()
    sessions = []
    for _ in range(agents):
        try:
            volume = await engine.volume(base)
            session, cold = await engine.session(volume)
            sessions.append(session)
            result['coldStartNs'].append(cold)
            publish(None)
        except NativeFailure as error:
            if error.status != 429:
                raise
            result['admissionFailure'] = {'status': error.status, 'code': error.code,
                                          'kind': 'configured admission or request refusal; not host saturation'}
            break
    stop = asyncio.Event()
    started = time.monotonic_ns()
    duration_ns = settings['durationSeconds'] * 1_000_000_000
    result['status'] = 'RUNNING'
    monitor_errors = []

    async def monitor():
        while not stop.is_set():
            try:
                sample = metrics.sample(sum(state == 'running' for state in engine.executing.values()))
                sample['sinceStartNs'] = sample.pop('monotonicNs') - started
                result['samples'].append(sample)
                # The incremental ledger retains observations without serializing
                # and fsyncing every previous attempt inside the measured loop.
                engine.emit('kernel-sample', {'agents': agents, 'repetition': repetition, **sample})
                if sample['hostAvailableBytes'] < 256 * 1024**2:
                    raise RuntimeError('Host memory reserve fell below its guard')
                if sample['oomKills'] > before['oomKills']:
                    stop.set()
            except Exception as error:
                monitor_errors.append(type(error).__name__)
                stop.set()
            try:
                await asyncio.wait_for(stop.wait(), settings['sampleIntervalSeconds'])
            except asyncio.TimeoutError:
                pass

    async def agent(index, session):
        workload = AgentWorkload(settings['seed'] + repetition * 1_000_000, index, files)
        workload.think = settings['thinkSeconds']
        while not stop.is_set():
            command = workload.next()
            remaining = (duration_ns - (time.monotonic_ns() - started)) / 1_000_000_000
            if remaining <= 0:
                return
            try:
                await asyncio.wait_for(stop.wait(), min(command['thinkSeconds'], remaining))
                return
            except asyncio.TimeoutError:
                pass
            if time.monotonic_ns() - started >= duration_ns:
                return
            recorded = {}
            def on_start(row):
                recorded.update(retain(row, started))
                result['attempts'].append(recorded)
            row = await engine.execute(session, command['command'], kind=command['kind'], on_start=on_start,
                                       timeout_ms=settings['commandTimeoutSeconds'] * 1000)
            recorded.update(retain(row, started))
            if row.get('fatal'):
                stop.set()

    observer = asyncio.create_task(monitor())
    try:
        if len(sessions) == agents:
            await asyncio.gather(*(agent(index, session) for index, session in enumerate(sessions)))
    finally:
        stop.set()
        await observer
    after = metrics.sample()
    result['countersBeforeSetup'] = before
    result['countersAfterCommands'] = after
    result['monitorErrors'] = monitor_errors
    result['observedSeconds'] = (time.monotonic_ns() - started) / 1_000_000_000
    result['score'] = summarize(result['attempts'], settings['warmupSeconds'] * 1_000_000_000,
                                duration_ns, after['oomKills'] - before['oomKills'], len(sessions), agents)
    if monitor_errors or any(row.get('fatal') for row in result['attempts']):
        result['score']['verdict'] = 'FAIL'
        result['score']['reasons'].append('OBSERVATION_OR_CLEANUP_UNCONFIRMED')
    result['apiCleanup'] = await engine.cleanup(keep_volumes=(base,))
    if result['apiCleanup']['result'] != 'PASS':
        raise RuntimeError('Trial API cleanup was not confirmed')
    if monitor_errors:
        result['status'] = 'ERROR'
        publish(None)
        raise RuntimeError('Required kernel observations or host reserve were lost')
    result['status'] = 'COMPLETED'
    publish(None)
    return result


async def measure(fixture, receipt, settings, files, report, ledger):
    def emit(phase, row):
        observation = {key: value for key, value in row.items() if key not in ('stdout', 'stderr')}
        observation.update(event=phase, stderrTail=row.get('stderr', '')[-1024:])
        ledger.write(json.dumps(observation, separators=(',', ':')) + '\n')
        ledger.flush()
    engine = Engine(fixture.socket, fixture.info['serverId'], emit)
    metrics = Metrics(fixture)
    receipt['daemonIdle'] = metrics.sample()
    try:
        base, corpus = await engine.seed(settings['seed'], files)
        receipt['corpus'] = corpus
        # Check the workload inside the actual sandbox before treating a command
        # failure as evidence about capacity; reset only this synthetic repository.
        session, _ = await engine.session(base)
        workload, seen = AgentWorkload(settings['seed'], 0, files), set()
        for _ in range(100):
            command = workload.next()
            if command['kind'] in seen:
                continue
            row = await engine.execute(session, command['command'])
            if row['outcome'] != 'OK' or row.get('fatal'):
                raise RuntimeError('Native workload preflight failed: ' + command['kind'])
            seen.add(command['kind'])
            if len(seen) == 6:
                break
        if len(seen) != 6:
            raise RuntimeError('Workload preflight did not cover every command kind')
        row = await engine.execute(session, 'git -C small-repo reset --hard HEAD >/dev/null')
        if row['outcome'] != 'OK' or row.get('fatal'):
            raise RuntimeError('Synthetic preflight state was not restored')
        await engine.close(session)
        receipt['nativeWorkloadPreflight'] = sorted(seen)
        receipt['stages'] = []
        receipt['capacityLowerBound'] = None
        save(report, receipt)
        for agents in settings['stages']:
            passed = True
            for repetition in range(settings['repetitions']):
                def publish(value):
                    if value is not None:
                        receipt['stages'].append(value)
                    save(report, receipt)
                result = await stage(engine, metrics, base, agents, repetition, settings, files, publish)
                print(json.dumps({'agents': agents, 'repetition': repetition,
                                  'verdict': result['score']['verdict'], 'reasons': result['score']['reasons']}), flush=True)
                if result['score']['verdict'] != 'PASS':
                    passed = False
                    break
            if not passed:
                receipt['firstFailedStage'] = agents
                break
            receipt['capacityLowerBound'] = agents
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
    if report.exists() or ledger_path.exists() or report.with_name(report.name + '.pending').exists():
        raise SystemExit('Preserve the previous receipt; select a new report path')
    report.parent.mkdir(parents=True, exist_ok=True)
    settings = load()
    if args.smoke:
        settings.update(stages=[2], repetitions=1, durationSeconds=6, warmupSeconds=1, thinkSeconds=[.05, .1])
    budget, files = (1024**3, 400) if args.smoke else (args.budget * 1_000_000_000, FILES)
    sources = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob('*.py')}
    repository = Path(__file__).resolve().parents[2]
    git = ['git', '-c', 'safe.directory=' + str(repository), '-C', str(repository)]
    commit = subprocess.run([*git, 'rev-parse', 'HEAD'], check=True,
                            capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run([*git, 'status', '--porcelain', '--untracked-files=normal'],
                           check=True, capture_output=True, text=True).stdout.strip()
    receipt = {'kind': 'sandcrab-density-smoke' if args.smoke else 'sandcrab-density', 'schema': 1,
               'started': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'settings': settings,
               'sourceSha256': sources, 'sourceCommit': commit, 'sourceDirty': bool(dirty),
               'protocolSha256': hashlib.sha256(Path(__file__).with_name('protocol.json').read_bytes()).hexdigest(),
               'measurementStatus': 'STARTING', 'apiCleanup': 'NOT_RUN',
               'hostCleanup': 'NOT_RUN', 'modelTokens': 0, 'containsProductionContent': False}
    if args.smoke:
        receipt['scope'] = 'Small native smoke only; no canonical footprint, readiness or density result'
    with report.open('x') as stream:
        json.dump(receipt, stream)
    def interrupted(signum, frame):
        raise KeyboardInterrupt('Benchmark interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    fixture = None
    try:
        fixture = Fixture(args.binary.resolve(), args.tools.resolve(), report, budget, args.smoke)
        fixture.setup()
        receipt['fixture'] = fixture.receipt
        with ledger_path.open('x', buffering=1) as ledger:
            asyncio.run(measure(fixture, receipt, settings, files, report, ledger))
            os.fsync(ledger.fileno())
    except BaseException as error:
        receipt['measurementStatus'] = 'ERROR'
        receipt['errorType'] = type(error).__name__
        report.with_suffix('.diagnostic.txt').write_text(traceback.format_exc())
        if fixture is not None:
            try:
                journal = subprocess.run(['journalctl', '--no-pager', '-n', '100', '-u', fixture.unit],
                                         capture_output=True, text=True, timeout=10)
                report.with_suffix('.journal.txt').write_text(journal.stdout[-65536:] + journal.stderr[-4096:])
            except Exception:
                receipt['journalCollection'] = 'UNAVAILABLE'
        raise
    finally:
        cleanup_error = None
        if fixture is not None:
            try:
                fixture.cleanup()
                receipt['hostCleanup'] = 'PASS'
            except BaseException as error:
                receipt['hostCleanup'] = 'UNCONFIRMED'
                receipt['measurementStatus'] = 'ERROR'
                cleanup_error = error
            finally:
                receipt['fixture'] = fixture.receipt
        receipt['finished'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save(report, receipt)
        if cleanup_error is not None:
            raise RuntimeError('Fixture containment/cleanup unconfirmed; preserve its resources') from cleanup_error
    if receipt['measurementStatus'] != 'COMPLETED':
        raise SystemExit(1)
    if args.smoke and any(row['score']['verdict'] != 'PASS' for row in receipt.get('stages', [])):
        raise SystemExit('Smoke failed; no capacity claim')


if __name__ == '__main__':
    main()
