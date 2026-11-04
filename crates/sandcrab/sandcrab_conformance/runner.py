"""One fixture lifecycle and contributor entrypoint for native acceptance."""
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import traceback
from types import SimpleNamespace


SUITES = {
    'native': ('native', 'Probe'),
    'tcp': ('tcp', 'TcpProbe'),
    'resources': ('resources', 'ResourcesProbe'),
    'volumes': ('volume', 'VolumeProbe'),
    'plain-storage': ('plain_storage', 'PlainStorageProbe'),
    'files': ('file', 'FileProbe'),
    'templates': ('template', 'TemplateProbe'),
    'contexts': ('contexts', 'ContextsProbe'),
    'overlays': ('overlay', 'OverlayProbe'),
    'rootfs': ('rootfs', 'RootfsProbe'),
    'diff': ('diff', 'DiffProbe'),
    'egress': ('egress', 'EgressProbe'),
    'queue': ('queue', 'QueueProbe'),
    'retention': ('retention', 'RetentionProbe'),
    'streaming': ('streaming_file', 'StreamingProbe'),
    'events': ('events', 'EventProbe'),
    'host-calls': ('host_calls', 'HostCallsProbe'),
    'delegation': ('delegation', 'DirectProbe'),
    'sdk': ('opensandbox', 'SdkProbe'),
}
ENTRY = Path(__file__).resolve().parents[1] / 'conformance.py'
SOURCE = (ENTRY.parent / '../../..').resolve()


def create_fixture(name, args, report):
    module_name, class_name = SUITES[name]
    module = importlib.import_module('.' + module_name, __package__)
    constructor = getattr(module, class_name)
    positional = [args.binary, args.tools, report]
    if name == 'delegation':
        positional.append(args.parent)
    elif name == 'host-calls':
        positional.append(args.examples / 'sandcrab-host-calls.py')
    elif name == 'sdk':
        positional.extend([args.python, args.sdk_clients / 'python_client.py', args.java, args.jvm_libs])
    probe = constructor(*positional)
    probe.receipt['suite'] = name
    probe.receipt['suiteSha256'] = hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
    if name == 'native':
        probe.inherited_fd_probe = True
    if name in ('egress', 'queue') and args.python:
        probe.sdk_python = args.python
        probe.sdk_client = args.sdk_clients / ('network_client.py' if name == 'egress' else 'queue_client.py')
    if name == 'rootfs' and args.python:
        probe.sdk = SimpleNamespace(python=args.python, python_client=args.sdk_clients / 'rootfs_client.py',
                                    java=args.java, jvm_libs=args.jvm_libs)
        probe.config.write_text(probe.config.read_text().replace('[service]', '[service]\nopensandbox = true', 1))
    return probe


def exercise(name, probe, examples):
    probe.tests()
    if name == 'native':
        probe.session_tests()
        probe.example(examples / 'sandcrab-build-test.sh')
        probe.session_cleanup_failure()
        probe.startup_cancellation()
        probe.startup_cancellation(session=True)
        probe.failed_exec()
        probe.rejected_clone()


def diagnostics(probe, failure):
    details = ''.join(traceback.format_exception(failure))
    if isinstance(failure, subprocess.CalledProcessError):
        for stream in (failure.stdout, failure.stderr):
            details += '\n' + (stream.decode('utf-8', 'replace') if isinstance(stream, bytes) else (stream or ''))
    if getattr(probe, 'unit', None):
        try:
            result = subprocess.run(['journalctl', '-u', probe.unit, '--no-pager', '-n', '60'],
                                    capture_output=True, text=True, timeout=10)
            details += '\n' + result.stdout
        except (OSError, subprocess.TimeoutExpired) as error:
            details += '\nJournal unavailable: ' + type(error).__name__
    data = getattr(probe, 'data', None)
    if data and os.path.ismount(data):
        for kind in ('-b', '-i'):
            try:
                result = subprocess.run(['xfs_quota', '-x', '-c', 'quota -p ' + kind + ' -N -v 1', str(data)],
                                        capture_output=True, text=True, timeout=10)
                details += '\n' + result.stdout
            except (OSError, subprocess.TimeoutExpired):
                pass
    return details[-131072:]


def execute_fixture(name, probe, examples):
    """A successful test body still fails when cleanup cannot confirm release."""
    failure = None
    try:
        probe.setup()
        exercise(name, probe, examples)
        probe.receipt['result'] = 'PASS'
    except BaseException as error:
        failure = error
        probe.receipt.update(result='FAIL', failureType=type(error).__name__)
        probe.report.with_suffix('.diagnostic.txt').write_text(diagnostics(probe, error), encoding='utf-8')
    finally:
        try:
            probe.cleanup()
            if probe.receipt.get('cleanup') != 'PASS':
                raise RuntimeError('Fixture did not confirm cleanup: ' + name)
        except BaseException as error:
            probe.receipt.update(result='FAIL', cleanup='FAIL', cleanupFailureType=type(error).__name__)
            with probe.report.with_suffix('.diagnostic.txt').open('a', encoding='utf-8') as output:
                output.write('\nCleanup failure:\n' + diagnostics(probe, error))
            if failure is None:
                failure = error
        finally:
            probe.save()
    if failure is not None:
        raise failure


def interrupt(signum, frame):
    raise KeyboardInterrupt('Conformance interrupted')


def validate(args, suites):
    if not hasattr(os, 'geteuid') or os.geteuid() != 0:
        raise RuntimeError('Conformance fixtures require a disposable root Linux host')
    args.binary = args.binary.resolve(strict=True)
    args.tools = args.tools.resolve(strict=True)
    if not args.binary.is_file() or not args.binary.with_name('bwrap').is_file() or not args.tools.is_dir():
        raise RuntimeError('Provide the built binary with its bundled bwrap and prepared workload tools')
    for name, filename in [('native', 'sandcrab-build-test.sh'), ('host-calls', 'sandcrab-host-calls.py')]:
        if name in suites and not (args.examples / filename).is_file():
            raise RuntimeError('Missing conformance example: ' + str(args.examples / filename))
    if 'delegation' in suites:
        args.parent = args.parent.resolve(strict=True)
    if 'sdk' in suites or ('rootfs' in suites and args.python):
        if not all((args.python, args.java, args.jvm_libs)):
            raise RuntimeError('SDK coverage requires --python, --java and --jvm-libs')
    if args.python:
        # Resolving a virtualenv interpreter selects the wrong site-packages.
        args.python = args.python.absolute()
        if not args.python.is_file():
            raise RuntimeError('SDK Python interpreter is missing')
        for name, filename in [('sdk', 'python_client.py'), ('egress', 'network_client.py'),
                               ('queue', 'queue_client.py'), ('rootfs', 'rootfs_client.py')]:
            if name in suites and not (args.sdk_clients / filename).is_file():
                raise RuntimeError('Missing SDK client: ' + str(args.sdk_clients / filename))
    if args.java:
        if not args.jvm_libs:
            raise RuntimeError('--java requires --jvm-libs')
        args.java = args.java.absolute()
        args.jvm_libs = args.jvm_libs.resolve(strict=True)
        if not args.java.is_file() or not args.jvm_libs.is_dir():
            raise RuntimeError('Provide the SDK Java executable and its JAR directory')
    if args.initialize_container and (suites != ['delegation'] or os.getpid() != 1):
        raise RuntimeError('--initialize-container requires only delegation and PID 1')


def single(name, args, report):
    if report.exists():
        raise RuntimeError('Preserve earlier receipts: ' + str(report))
    if args.initialize_container:
        if args.parent != Path('/sys/fs/cgroup') or Path('/proc/self/cgroup').read_text().strip() != '0::/':
            raise RuntimeError('Direct container probe needs its private cgroup root')
        controller = args.parent / 'sandcrab-probe-controller'
        controller.mkdir()
        (controller / 'cgroup.procs').write_text('1')
        (args.parent / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
    probe = create_fixture(name, args, report)
    execute_fixture(name, probe, args.examples)


def child_arguments(name, args, report):
    result = [sys.executable, str(ENTRY), '--case', name, '--report', str(report),
              '--binary', str(args.binary), '--tools', str(args.tools), '--parent', str(args.parent),
              '--examples', str(args.examples), '--sdk-clients', str(args.sdk_clients)]
    for name in ('python', 'java', 'jvm_libs'):
        value = getattr(args, name)
        if value:
            result += ['--' + name.replace('_', '-'), str(value)]
    return result


def run_case(name, args, report):
    if args.initialize_container:
        single(name, args, report)
    else:
        # Egress changes the controller's network namespace; isolate every suite.
        with (args.output / (name + '.log')).open('x', encoding='utf-8') as log:
            process = subprocess.Popen(child_arguments(name, args, report), stdout=log, stderr=subprocess.STDOUT)
            try:
                if process.wait(timeout=360) != 0:
                    raise RuntimeError('Conformance suite failed: ' + name)
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=90)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)


def run_suites(args, suites):
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    summary = {'result': 'RUNNING', 'suites': []}
    def save():
        temporary = args.output / 'summary.pending'
        temporary.write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
        temporary.replace(args.output / 'summary.json')
    save()
    try:
        validate(args, suites)
        summary['binarySha256'] = hashlib.sha256(args.binary.read_bytes()).hexdigest()
        for name in suites:
            report = args.output / (name + '.json')
            started = time.monotonic()
            row = {'name': name, 'result': 'RUNNING'}
            summary['suites'].append(row)
            save()
            receipt = {}
            try:
                run_case(name, args, report)
            finally:
                row.update(result='FAIL', seconds=round(time.monotonic() - started, 3))
                try:
                    receipt = json.loads(report.read_text(encoding='utf-8'))
                except (ValueError, OSError) as error:
                    row['receiptError'] = type(error).__name__
                if isinstance(receipt, dict):
                    row.update(cleanup=receipt.get('cleanup', 'UNCONFIRMED'), checks=len(receipt.get('checks', [])))
            if not isinstance(receipt, dict) or receipt.get('result') != 'PASS' or row['cleanup'] != 'PASS':
                raise RuntimeError('Conformance result or cleanup unconfirmed: ' + name)
            row['result'] = 'PASS'
            print(name + ': PASS', flush=True)
            save()
        summary['result'] = 'PASS'
    except BaseException as error:
        summary.update(result='FAIL', failureType=type(error).__name__, failure=str(error))
        raise
    finally:
        save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--list', action='store_true', help='List selectable suites without starting fixtures')
    parser.add_argument('--suite', nargs='+', choices=['all', *SUITES], default=['all'])
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--tools', type=Path)
    parser.add_argument('--output', type=Path, help='New directory for all raw receipts and logs')
    parser.add_argument('--python', type=Path, help='Published Python SDK virtualenv interpreter')
    parser.add_argument('--java', type=Path)
    parser.add_argument('--jvm-libs', type=Path)
    parser.add_argument('--sdk-clients', type=Path, default=SOURCE / 'evals/sdk')
    parser.add_argument('--examples', type=Path, default=SOURCE / 'examples')
    parser.add_argument('--parent', type=Path, default=Path('/sys/fs/cgroup'))
    parser.add_argument('--initialize-container', action='store_true')
    parser.add_argument('--case', choices=SUITES, help=argparse.SUPPRESS)
    parser.add_argument('--report', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.list:
        print('\n'.join(SUITES))
        return
    if not args.binary or not args.tools:
        parser.error('--binary and --tools are required')
    suites = [args.case] if args.case else (list(SUITES) if args.suite == ['all'] else args.suite)
    if 'all' in suites or len(suites) != len(set(suites)):
        parser.error('Select all or distinct named suites')
    signal.signal(signal.SIGTERM, interrupt)
    if args.case:
        if not args.report or args.output:
            parser.error('A child case requires only --report')
        validate(args, suites)
        single(args.case, args, args.report)
    else:
        if not args.output or args.report:
            parser.error('--output is required')
        run_suites(args, suites)
