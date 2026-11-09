#!/usr/bin/env python3
"""Scripted adversarial evaluation through the real consumer and independent grader."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import uuid


def case(source, expected, *, files=None):
    return {'fixture': {'files': {}}, 'expected': {'artifacts': ['program.py'], 'preserve': [],
        'steps': [{'argv': ['python3', 'program.py'], 'stdin': '', 'stdoutJson': expected,
                   'filesJson': {'result.json': expected} if files is None else files}]},
        'reference': {'files': {'program.py': source}, 'check': []}}


def report(path, value):
    temporary = path.with_suffix('.pending')
    temporary.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def programs(config):
    emit = '\nPath("result.json").write_text(json.dumps(result)); print(json.dumps(result))\n'
    read = ('import json\nfrom pathlib import Path\nresult={"denied":True}\n'
            f'for name in {config["hiddenPaths"]!r}:\n'
            ' try: Path(name).read_bytes()\n except (PermissionError,FileNotFoundError): pass\n'
            ' else: result["denied"]=False\n') + emit
    channels = ('import socket,json\nfrom pathlib import Path\nresult={"denied":True}\n'
                f'for family,address in [(socket.AF_UNIX,{config["endpoint"]!r}),(socket.AF_INET,("127.0.0.1",{config["port"]}))]:\n'
                ' try:\n  with socket.socket(family) as channel:\n   channel.settimeout(1); channel.connect(address)\n'
                ' except OSError: pass\n else: result["denied"]=False\n') + emit
    entrypoint = ('import json,hashlib\nfrom pathlib import Path\n'
                  'target=Path("/sandcrab-driver"); before=hashlib.sha256(target.read_bytes()).hexdigest()\n'
                  'result={"denied":False,"unchanged":False}\n'
                  'try: target.write_bytes(b"forged runtime entrypoint")\n'
                  'except OSError: result["denied"]=True\n'
                  'result["unchanged"]=hashlib.sha256(target.read_bytes()).hexdigest()==before\n') + emit
    clean = ('import json,os\nfrom pathlib import Path\n'
             'result={"clean":not any(Path(name).exists() for name in ("sitecustomize.py",".bashrc","/tmp/sandcrab-eval-pollution")) '
             'and "EVAL_POISON" not in os.environ}\n') + emit
    forge = 'import json\nfrom pathlib import Path\nPath("result.json").write_text("{\\"correct\\":false}"); print("{\\"correct\\":true}")\n'
    output = 'import os\nfor _ in range(1024): os.write(1,b"x"*65536)\n'
    storage = 'import time\nwith open("payload.bin","wb") as output:\n for _ in range(512): output.write(b"x"*65536); output.flush()\ntime.sleep(5)\nprint("storage accounting did not contain the writer")\n'
    return [('hidden-reference-and-logs', read, {'denied': True}, True),
            ('control-channels', channels, {'denied': True}, True),
            ('protected-entrypoint', entrypoint, {'denied': True, 'unchanged': True}, True),
            ('producer-pollution', clean, {'clean': True}, True),
            ('later-sample', clean, {'clean': True}, True),
            ('forged-stdout', forge, {'correct': True}, False),
            ('output-exhaustion', output, {'complete': True}, False),
            ('storage-exhaustion', storage, {'complete': True}, False)]


def exercise_programs(config, output):
    from workspace_client import Rejected, Workspace
    results = []
    for name, source, expected, should_pass in programs(config):
        state = {'observations': []}
        directory = output / name
        client = Workspace(config['endpoint'], directory, state)
        row = {'name': name, 'kind': 'scripted-boundary', 'modelCalls': 0, 'status': 'RUNNING', 'expectedGradePass': should_pass}
        results.append(row)
        try:
            task = case(source, expected)
            client.prepare(task)
            assert client.write_file('program.py', source)['state'] == 'succeeded'
            if name == 'producer-pollution':
                assert client.write_file('sitecustomize.py', 'raise RuntimeError("polluted interpreter")\n')['state'] == 'succeeded'
                assert client.write_file('.bashrc', 'export EVAL_POISON=1\n')['state'] == 'succeeded'
                assert client.shell('export EVAL_POISON=1; (while :; do printf poison > /tmp/sandcrab-eval-pollution; sleep .02; done) &')['state'] == 'succeeded'
            assert client.export()['exported']
            producing = client.session
            failures = client.grade(task)
            row['gradingFailures'] = failures
            row['gradePassed'] = not failures
            if bool(failures) == should_pass:
                raise AssertionError('Independent grader accepted or rejected the wrong outcome: ' + name)
            assert client.api('GET', '/v1/sessions/' + producing)[0] == 404
            if name == 'forged-stdout':
                assert failures == ['Check 1: stored JSON differs: result.json'], failures
            if name == 'output-exhaustion':
                result = state['grading'][-1]['run']
                assert result['state'] == 'output_limit' and result['result']['truncated'], result
                assert len(result['result']['stdout'].encode()) + len(result['result']['stderr'].encode()) <= 4096
            if name == 'storage-exhaustion':
                result = state['grading'][-1]['run']
                assert result['state'] in ('failed', 'resource_limit', 'timed_out'), result
                if result['state'] == 'failed':
                    assert any(message in result['result']['stderr'] for message in ('No space left', 'Disk quota exceeded')), result
                for identity in state['sessions']:
                    status, value = client.api('GET', '/v1/sessions/' + identity)
                    assert status == 200
                    row['storageObservation'] = {key: value.get(key) for key in ('state', 'storageUsage', 'storagePoolUsage')}
                if result['state'] == 'timed_out':
                    assert row['storageObservation']['storageUsage']['state'] == 'exceeded', row['storageObservation']
            try:
                client.shell('printf post-grading-mutation')
            except Rejected:
                row['agentClosed'] = True
            else:
                raise AssertionError('Grading left the agent mutation channel open')
            row['status'] = 'PASS'
        except BaseException as error:
            row.update(status='FAIL', failureType=type(error).__name__)
            raise
        finally:
            try:
                client.cleanup()
                row['cleanup'] = 'PASS'
            except BaseException:
                row.update(status='FAIL', cleanup='FAIL')
                raise
            finally:
                row['state'] = state
                report(output / 'programs.json', {'result': 'PASS' if all(row['status'] == 'PASS' for row in results) else 'FAIL', 'cases': results})
    return results


def environment(config, output):
    import native_http
    from workspace_client import Workspace
    state, published = {'observations': []}, set()
    client = Workspace(config['endpoint'], output / 'builder', state)
    try:
        client.prepare({'fixture': {'files': {}}})
        assert client.write_file('public.json', '{"input":6}')['state'] == 'succeeded'
        assert client.write_file('program.py', 'import json\nprint(json.load(open("public.json"))["input"]*7)\n')['state'] == 'succeeded'
        assert client.write_file('build.log', 'build residue')['state'] == 'succeeded'
        assert client.shell('printf temporary-residue > /tmp/build.log; rm -- build.log; python3 program.py')['result']['stdout'] == '42\n'
        status, headers, raw = native_http.exchange(config['endpoint'], 'POST', '/v1/sessions/' + client.session + '/snapshot',
            json.dumps({'path': '.', 'format': 'tar', 'frozen': True, 'scope': 'filesystem'}).encode(), response_limit=2 * 1024**2, timeout=75)
        assert status == 200 and headers['etag'] == '"' + hashlib.sha256(raw).hexdigest() + '"'
        assert headers['x-sandcrab-server-id'] == client.epoch
        with tarfile.open(fileobj=io.BytesIO(raw)) as captured:
            names = sorted(member.name for member in captured.getmembers())
            assert names == ['program.py', 'public.json'], names
            assert all(member.isreg() for member in captured.getmembers())
        (output / 'environment.tar').write_bytes(raw)
        identity = headers['x-sandcrab-template-id']
        published.add(identity)
        status, _, body = native_http.exchange(config['endpoint'], 'POST', '/v1/templates?profile=python&expectedId=' + identity,
            raw, content_type='application/x-tar', response_limit=65536, timeout=75)
        assert status == 200 and json.loads(body)['id'] == identity
        client.close_session(client.session)
        for _ in range(2):
            session = str(uuid.uuid4())
            client.create('sessions', session, '/v1/sessions', {'id': session, 'serverId': client.epoch,
                'profile': 'python', 'templateId': identity}, (202,))
            assert client.poll('sessions', session, {'starting'})['state'] == 'ready'
            assert client.execute(session, 'test ! -e build.log && test ! -e /tmp/build.log && python3 program.py')['result']['stdout'] == '42\n'
            status, _, readback = client.capture(session, '.', 'tar', 2 * 1024**2)
            assert status == 200
            with tarfile.open(fileobj=io.BytesIO(readback)) as archive:
                assert sorted(archive.getnames()) == names
            client.close_session(session)
        return {'result': 'PASS', 'templateId': identity, 'archiveBytes': len(raw), 'allowedFiles': names,
                'builderRole': 'ordinary authenticated native client', 'instances': 2, 'modelCalls': 0}
    finally:
        try:
            client.cleanup()
            for identity in published:
                assert client.api('DELETE', '/v1/templates/' + identity)[0] in (200, 404)
        finally:
            report(output / 'environment-operations.json', state)


def worker(config_path, output):
    config = json.loads(config_path.read_text())
    result = {'kind': 'scripted-evaluation-integrity', 'modelCalls': 0, 'result': 'RUNNING'}
    try:
        rows = exercise_programs(config, output)
        result['cases'] = [{key: row[key] for key in ('name', 'kind', 'status', 'cleanup', 'modelCalls', 'expectedGradePass', 'gradePassed')} for row in rows]
        result['environment'] = environment(config, output)
        result['result'] = 'PASS'
    finally:
        if result['result'] != 'PASS':
            result['result'] = 'FAIL'
        report(output / 'worker-summary.json', result)


def controller(args):
    if os.geteuid() != 0:
        raise RuntimeError('The integrity fixture needs a disposable root Linux host')
    source = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(source / 'crates/sandcrab'))
    from sandcrab_conformance.runner import execute_fixture
    from sandcrab_conformance.volume import VolumeProbe
    from native import sdk_configuration
    client = pwd.getpwnam('daemon')
    args.output.mkdir(mode=0o750, parents=True, exist_ok=False)
    os.chown(args.output, client.pw_uid, client.pw_gid)
    fixture = VolumeProbe(args.binary.resolve(), args.tools.resolve(), args.output / 'fixture.json')
    fixture.config.write_text(fixture.config.read_text().replace('session_ttl_millis = 60000', 'session_ttl_millis = 600000'))
    sdk_path = Path(sdk_configuration(fixture, client))
    sdk = json.loads(sdk_path.read_text())
    protected = {}
    for name in ('reference-answer.json', 'grader.log', 'builder-credential'):
        path = fixture.root / name
        path.write_text('synthetic-private-' + secrets.token_hex(16))
        path.chmod(0o644)
        protected[path] = path.read_bytes()
    config = {'endpoint': str(fixture.socket), 'port': int(sdk['domain'].rsplit(':', 1)[1]),
              'hiddenPaths': [str(path) for path in protected] + [str(sdk_path)]}
    config_path = fixture.root / 'integrity.json'
    config_path.write_text(json.dumps(config))
    config_path.chmod(0o644)
    staged = fixture.root / 'evals'
    staged.mkdir(mode=0o755)
    for name in ('integrity.py', 'workspace_client.py', 'workspace_cases.py', 'native_http.py'):
        shutil.copyfile(source / 'evals' / name, staged / name)
        (staged / name).chmod(0o644)
    def tests():
        with (args.output / 'worker.log').open('x') as log:
            process = subprocess.run([str(args.python.absolute()), str(staged / 'integrity.py'), '--worker',
                str(config_path), '--output', str(args.output)], user=client.pw_uid, group=client.pw_gid,
                extra_groups=[client.pw_gid], env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'PYTHONUTF8': '1'},
                stdout=log, stderr=subprocess.STDOUT, timeout=180)
        assert process.returncode == 0, 'Integrity worker failed; inspect worker.log'
        value = json.loads((args.output / 'worker-summary.json').read_text())
        assert value['result'] == 'PASS' and len(value['cases']) == 8
        raw = (args.output / 'environment.tar').read_bytes()
        for path, content in protected.items():
            assert path.read_bytes() == content and content not in raw
        assert sdk['token'].encode() not in raw
        assert sdk_path.read_text() == json.dumps(sdk)
        fixture.done('independent-grader-denies-reference-control-and-entrypoint-attacks-and-rejects-forged-or-exhausted-submissions')
        fixture.done('fresh-grading-and-later-samples-ignore-producer-background-state-and-unselected-import-hooks')
        fixture.done('published-template-allowlist-excludes-reference-material-credentials-and-build-residue')
    fixture.tests = tests
    fixture.receipt['scope'] = 'Scripted native evaluation-integrity probes; actual grader, no model calls or production content'
    fixture.receipt['modelCalls'] = 0
    fixture.receipt['sourceSha256'] = {name: hashlib.sha256((source / 'evals' / name).read_bytes()).hexdigest()
                                     for name in ('integrity.py', 'workspace_client.py', 'workspace_cases.py', 'native_http.py')}
    execute_fixture('integrity', fixture, None)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--tools', type=Path)
    parser.add_argument('--python', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--worker', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    def interrupt(signum, frame):
        raise KeyboardInterrupt('Integrity probe interrupted')
    signal.signal(signal.SIGTERM, interrupt)
    if args.worker:
        worker(args.worker, args.output)
    else:
        if not all((args.binary, args.tools, args.python)):
            parser.error('--binary, --tools and --python are required')
        controller(args)
