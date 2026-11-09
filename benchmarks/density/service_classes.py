#!/usr/bin/env python3
"""Test operator-owned CPU weights and caller startup bounds before adding runtime controls."""
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
import time
import traceback

from density import save
from engine import Engine
from host import Fixture, fields
from metrics import Metrics
from sandcrab_conformance.runner import execute_fixture


def build_program(seconds):
    source = '\n'.join(f'def function_{index}(value): return value * {index}' for index in range(256))
    return f'''import hashlib,json,time
source={source!r}; buckets=[0]*{seconds}; started=time.monotonic_ns(); deadline=started+{seconds}*1000000000
while (now:=time.monotonic_ns()) < deadline:
 compile(source,'synthetic-build.py','exec'); buckets[min(len(buckets)-1,(now-started)//1000000000)]+=1
print(json.dumps({{'compiled':sum(buckets),'perSecond':buckets,'sourceSha256':hashlib.sha256(source.encode()).hexdigest(),'startedNs':started,'finishedNs':time.monotonic_ns()}}))
'''


def quantiles(values):
    ordered = sorted(values)
    return {f'p{percent}Ns': ordered[math.ceil(len(ordered) * percent / 100) - 1] for percent in (50, 95, 99)}


def snapshot(fixture):
    result = Metrics(fixture).sample()
    result['cpuStat'] = fields(fixture.pool_group / 'cpu.stat')
    result['cpuPressure'] = (fixture.pool_group / 'cpu.pressure').read_text()
    return result


def group(fixture, identity):
    path = fixture.workloads_group / ('session-' + identity)
    if path.is_symlink() or path.resolve(strict=True).parent != fixture.workloads_group.resolve(strict=True):
        raise RuntimeError('Unexpected fixture session cgroup')
    return path


def weight(fixture, identity, value):
    if value not in (10, 100):
        raise ValueError('Use the fixed experimental weights')
    control = group(fixture, identity) / 'cpu.weight'
    if control.is_symlink() or control.stat().st_uid != 0:
        raise RuntimeError('Unprotected fixture CPU controller')
    control.write_text(str(value))
    if int(control.read_text()) != value:
        raise RuntimeError('CPU weight readback differs')


async def measure(fixture, row, ledger, *, seconds, commands, starters, weighted, parallel, executing):
    def emit(event, value):
        ledger.write(json.dumps({'event': event, **value}, separators=(',', ':')) + '\n')
        ledger.flush()
    engine = Engine(fixture.socket, fixture.info['serverId'], emit)
    background_tasks, failure = [], None
    try:
        foreground, _ = await engine.session()
        background = [(await engine.session())[0] for _ in range(4)]
        for identity in background:
            weight(fixture, identity, 10 if weighted else 100)
        weight(fixture, foreground, 100)
        row['weights'] = {'foreground': 100, 'background': 10 if weighted else 100}
        row['before'] = snapshot(fixture)
        row['backgroundBefore'] = [fields(group(fixture, identity) / 'cpu.stat') for identity in background]
        started_ids = []
        execution_gate = asyncio.Semaphore(executing)
        row['backgroundCallerQueueNs'] = []
        async def compile_background(identity):
            submitted = time.monotonic_ns()
            async with execution_gate:
                row['backgroundCallerQueueNs'].append(time.monotonic_ns() - submitted)
                return await engine.execute(identity, 'python3 -c ' + shlex.quote(build_program(seconds)),
                    timeout_ms=(seconds + 15) * 1000, kind='background-compile', on_start=lambda value: started_ids.append(value['id']))
        background_tasks = [asyncio.create_task(compile_background(identity)) for identity in background]
        ready_deadline = time.monotonic() + 5
        while len(started_ids) < min(4, executing) or any(engine.executing.get(identity) != 'running' for identity in started_ids):
            if time.monotonic() >= ready_deadline or any(task.done() for task in background_tasks):
                raise RuntimeError('Background compilation did not reach the running state')
            await asyncio.sleep(.01)
        semaphore = asyncio.Semaphore(parallel)
        startup_begin = time.monotonic_ns()
        async def start(index):
            submitted = time.monotonic_ns()
            async with semaphore:
                admitted = time.monotonic_ns()
                _, elapsed = await engine.session()
                return {'index': index, 'callerQueueNs': admitted - submitted, 'apiStartNs': elapsed,
                        'totalNs': time.monotonic_ns() - submitted, 'finishedNs': time.monotonic_ns()}
        startup_tasks = [asyncio.create_task(start(index)) for index in range(starters)]
        foreground_rows = []
        row['foreground'] = foreground_rows
        foreground_begin = time.monotonic_ns()
        command = "python3 -c 'print(sum(i*i for i in range(50000)))'"
        expected = str(sum(i * i for i in range(50000))) + '\n'
        for _ in range(commands):
            result = await engine.execute(foreground, command, kind='interactive')
            foreground_rows.append(result)
            if result['outcome'] != 'OK' or result.get('fatal') or result.get('stdout') != expected:
                raise RuntimeError('Interactive command failed independent output validation')
            await asyncio.sleep(.025)
        foreground_wall = time.monotonic_ns() - foreground_begin
        row['startup'] = await asyncio.gather(*startup_tasks)
        row['startupWallNs'] = max(item['finishedNs'] for item in row['startup']) - startup_begin
        row['foregroundSummary'] = {**quantiles([item['elapsedNs'] for item in foreground_rows]),
            'attempts': len(foreground_rows), 'successful': len(foreground_rows), 'wallNs': foreground_wall,
            'successfulPerSecond': len(foreground_rows) * 1_000_000_000 / foreground_wall}
        row['background'] = await asyncio.gather(*background_tasks)
        row['backgroundAfter'] = [fields(group(fixture, identity) / 'cpu.stat') for identity in background]
        observations = []
        expected_source = '\n'.join(f'def function_{index}(value): return value * {index}' for index in range(256))
        for result in row['background']:
            if result['outcome'] != 'OK' or result.get('fatal'):
                raise RuntimeError('A background compilation failed')
            value = json.loads(result['stdout'])
            if value['sourceSha256'] != hashlib.sha256(expected_source.encode()).hexdigest() or value['compiled'] != sum(value['perSecond']):
                raise RuntimeError('Background compilation input or progress changed')
            observations.append(value)
        row['backgroundProgress'] = observations
        row['backgroundSummary'] = {'compilations': sum(item['compiled'] for item in observations),
            'zeroProgressSeconds': sum(count == 0 for item in observations for count in item['perSecond']),
            'perSecond': sum(item['compiled'] for item in observations) * 1_000_000_000 /
                (max(item['finishedNs'] for item in observations) - min(item['startedNs'] for item in observations)),
            'maximumCallerQueueNs': max(row['backgroundCallerQueueNs'])}
        overlap_start = max(item['startedNs'] for item in observations)
        overlap_end = min(item['finishedNs'] for item in observations)
        row['foregroundOverlappingAllBackgrounds'] = sum(overlap_start <= item['createdAbsoluteNs']
            and item['createdAbsoluteNs'] + item['elapsedNs'] <= overlap_end for item in foreground_rows)
        row['foregroundWithBackgroundWork'] = sum(any(background['startedNs'] <= item['createdAbsoluteNs']
            and item['createdAbsoluteNs'] + item['elapsedNs'] <= background['finishedNs'] for background in observations)
            for item in foreground_rows)
        row['after'] = snapshot(fixture)
        if row['after']['oomKills'] != row['before']['oomKills']:
            raise RuntimeError('OOM during service-class comparison')
        row['status'] = 'PASS'
    except BaseException as error:
        failure = error
        row.update(status='FAIL', failureType=type(error).__name__)
        raise
    finally:
        # Join all one-shot HTTP operations before their owned objects are released.
        await asyncio.gather(*background_tasks, return_exceptions=True)
        if 'startup_tasks' in locals():
            await asyncio.gather(*startup_tasks, return_exceptions=True)
        row['apiCleanup'] = await engine.cleanup()
        if row['apiCleanup']['result'] != 'PASS':
            row['status'] = 'FAIL'
            if failure is None:
                raise RuntimeError('Service-class comparison cleanup unconfirmed')


class ClassFixture(Fixture):
    def configure(self, tools, memory, free):
        super().configure(tools, memory, free)
        self.config.write_text(self.config.read_text().replace('max_sandboxes = 512', 'max_sandboxes = 16'))
        self.receipt.update(configuredSandboxCeiling=16,
            configSha256=hashlib.sha256(self.config.read_bytes()).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--smoke', action='store_true')
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    settings = {'seconds': 2 if args.smoke else 20, 'commands': 4 if args.smoke else 60, 'starters': 2 if args.smoke else 8}
    modes = [('default', False, settings['starters'], 4), ('weights', True, settings['starters'], 4),
             ('execution-bound', False, settings['starters'], 2)]
    if not args.smoke:
        modes += [('startup-bound', False, 2, 4), ('weights-and-startup-bound', True, 2, 4)]
    receipt = {'kind': 'service-class-smoke' if args.smoke else 'service-class-comparison', 'result': 'RUNNING', 'cases': [],
        'started': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'parameters': settings,
        'scope': 'Synthetic interactive arithmetic with four CPU compilation loops and a startup burst. Operator changes only owned fixture cpu.weight; startup and background execution bounds are caller-side. No runtime control or topology isolation is implemented.',
        'decisionRule': 'A candidate needs >=20% lower interactive p95 in both reversed-order repetitions, all interactive successes, >=80% background compilation throughput, zero full seconds without active background progress, background caller wait <=2 seconds and >=80% foreground overlap with background work before considering a runtime control.',
        'binarySha256': hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        'sourceSha256Lf': {path.name: hashlib.sha256(path.read_bytes().replace(b'\r\n', b'\n')).hexdigest() for path in Path(__file__).parent.glob('*.py')},
        'modelCalls': 0, 'productionContent': False}
    report = args.output / 'results.json'
    save(report, receipt)
    def interrupt(signum, frame):
        raise KeyboardInterrupt('Service-class comparison interrupted')
    signal.signal(signal.SIGTERM, interrupt)
    try:
        for repetition in range(1 if args.smoke else 2):
            for name, weighted, parallel, executing in (modes if repetition == 0 else list(reversed(modes))):
                identity = f'{repetition + 1}-{name}'
                row = {'name': identity, 'mode': name, 'repetition': repetition + 1, 'startupParallelism': parallel,
                       'backgroundExecutionBound': executing, 'status': 'RUNNING'}
                receipt['cases'].append(row)
                save(report, receipt)
                fixture = None
                try:
                    fixture = ClassFixture(args.binary.resolve(), args.tools.resolve(), args.output / (identity + '-fixture.json'), 1024**3, smoke=True)
                    def tests():
                        with (args.output / (identity + '-requests.jsonl')).open('x', buffering=1) as ledger:
                            asyncio.run(measure(fixture, row, ledger, **settings, weighted=weighted, parallel=parallel, executing=executing))
                            os.fsync(ledger.fileno())
                    fixture.tests = tests
                    execute_fixture('service-classes', fixture, None)
                except BaseException as error:
                    row.update(status='FAIL', failureType=type(error).__name__)
                    raise
                finally:
                    if fixture:
                        row['hostCleanup'] = fixture.receipt.get('cleanup', 'UNCONFIRMED')
                        row['fixture'] = fixture.receipt
                    save(report, receipt)
                print(identity + ': PASS', flush=True)
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
