#!/usr/bin/env python3
"""Disposable SDK endpoint with ordinary published clients and kernel-side checks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import secrets
import shutil
import signal
import socket
import subprocess
import time

import native_probe
from native_probe import call, http
import opensandbox_contract_probe
import opensandbox_contexts_probe
from resources_probe import ResourcesProbe


class SdkProbe(ResourcesProbe):
    def __init__(self, binary, tools, report, python, client, java=None, jvm_libs=None):
        super().__init__(binary, tools, report)
        self.python = python
        self.client = self.root / 'python-client.py'
        shutil.copyfile(client, self.client)
        self.client.chmod(0o644)
        self.java, self.jvm_libs = java, None
        if jvm_libs:
            self.jvm_libs = self.root / 'jvm-lib'
            shutil.copytree(jvm_libs, self.jvm_libs)
            self.jvm_libs.chmod(0o755)
            for item in self.jvm_libs.iterdir():
                assert item.is_file() and item.suffix == '.jar'
                item.chmod(0o644)
            self.receipt['jvmArtifactsSha256'] = {
                item.name: hashlib.sha256(item.read_bytes()).hexdigest() for item in sorted(self.jvm_libs.iterdir())}
            for name, digest in [('sandbox-1.1.0.jar', 'cb96348a273124a899586e23abe9b5aeafcc98b1d6055532a62ecc8a2a22a392'),
                                 ('sandbox-api-1.1.0.jar', '4cc5236a3c69d4328a8e80754fe0ccf47bddea10a0eaecd5dd01ba299bb87e45')]:
                assert hashlib.sha256((self.jvm_libs / name).read_bytes()).hexdigest() == digest
        self.token = secrets.token_hex(32)
        server, self.key = self.root / 'server.token', self.root / 'client.token'
        for path in [server, self.key]:
            path.write_text(self.token + '\n')
            path.chmod(0o600)
        os.chown(self.key, *native_probe.CLIENT)
        with socket.socket() as free:
            free.bind(('127.0.0.1', 0))
            self.port = free.getsockname()[1]
        self.endpoint = f'127.0.0.1:{self.port}'
        config = self.config.read_text().replace('[service]', '[service]\nopensandbox = true', 1)
        config = config.replace('session_ttl_millis = 60000', 'session_ttl_millis = 180000')
        config = config.replace('output_limit_bytes = 4096', 'output_limit_bytes = 65536')
        config = config.replace('[profiles.python]', '[profiles.python]\ntransfer_bytes = 1048576')
        self.config.write_text(config + f'\n[tcp]\nlisten = "{self.endpoint}"\ntoken_file = {json.dumps(str(server))}\n')
        helpers = self.root / 'context-cleanup-fault'
        helpers.mkdir(mode=0o755)
        self.context_cleanup_fault = helpers / 'fail-id'
        (helpers / 'umount').write_text(f'''#!/usr/bin/python3
import os, sys
from pathlib import Path
flag = Path({str(self.context_cleanup_fault)!r})
if flag.exists() and Path(sys.argv[-1]).name == flag.read_text():
    raise SystemExit(79)
os.execv('/usr/bin/umount', ['umount', *sys.argv[1:]])
''')
        (helpers / 'umount').chmod(0o755)
        self.upload_reply_fault = helpers / 'drop-upload-record'
        # Lose bookkeeping after the real helper publishes, so ENOENT cannot be
        # mistaken for an acknowledged missing-parent refusal.
        (helpers / 'systemd-run').write_text(f'''#!/usr/bin/python3
import json, os, subprocess, sys
from pathlib import Path
flag = Path({str(self.upload_reply_fault)!r})
record = None
if flag.exists() and '__file' in sys.argv:
    candidate = Path(sys.argv[sys.argv.index('__file') + 1])
    if candidate.parent == Path({str(self.socket.parent / 'file-ops')!r}) and json.loads(candidate.read_text())['action'] == 'sdk-publish':
        record = candidate
if record is None:
    os.execv('/usr/bin/systemd-run', ['systemd-run', *sys.argv[1:]])
result = subprocess.run(['/usr/bin/systemd-run', *sys.argv[1:]])
if result.returncode == 0:
    record.unlink()
    flag.unlink()
raise SystemExit(result.returncode)
''')
        (helpers / 'systemd-run').chmod(0o755)
        self.launch_path = str(helpers) + ':/usr/bin:/bin'
        self.receipt.update(scope='Published OpenSandbox SDK clients through actual native TCP and sandbox units; no model or production cutover',
                            specification={'repository': 'https://github.com/opensandbox-group/OpenSandbox',
                                           'commit': 'b1a29cf93a823a95913f7943010febb3f29de05c',
                                           'files': ['specs/sandbox-lifecycle.yml', 'specs/execd-api.yaml']},
                            opensandboxProbeSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                            contractProbeSha256=hashlib.sha256(Path(opensandbox_contract_probe.__file__).read_bytes()).hexdigest(),
                            contextsProbeSha256=hashlib.sha256(Path(opensandbox_contexts_probe.__file__).read_bytes()).hexdigest(),
                            pythonClientSha256=hashlib.sha256(client.read_bytes()).hexdigest())

    def client_flow(self, command, label):
        process = subprocess.Popen(command,
                                   user=native_probe.CLIENT[0], group=native_probe.CLIENT[1],
                                   extra_groups=[native_probe.CLIENT[1]], env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'},
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                assert selector.select(40), 'SDK did not create its sandbox'
                first = process.stdout.readline(4096)
            if not first:
                _, error = process.communicate(timeout=5)
                raise AssertionError('SDK creation failed: ' + error.decode(errors='replace'))
            created = json.loads(first)['created']
            self.limits(created, session=True)
            self.done(label + '-selected-resource-caps-reach-the-actual-kernel-cgroup')
            out, error = process.communicate(input=b'continue\n', timeout=90)
            assert process.returncode == 0, error.decode(errors='replace')
            client = json.loads(out)
            assert client['result'] == 'PASS' and client['sdkVersion'] == '1.1.0'
            self.receipt[label] = client
            for identity in client['sandboxIds'] + client['contextIds']:
                assert http(self.socket, 'GET', '/v1/sessions/' + identity)[0] == 404
            assert not list((self.socket.parent / 'jobs').iterdir()), 'SDK-owned shell workspace was not released'
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if all(http(self.socket, 'GET', '/v1/runs/' + identity)[0] == 404 for identity in client['commandIds']):
                    break
                time.sleep(.02)
            else:
                raise AssertionError('SDK-owned native run records were not released')
            self.done(label + '-published-sdk-flow-and-native-record-cleanup')
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=10)

    def tests(self):
        self.client_flow([str(self.python), str(self.client), '--endpoint', self.endpoint,
                          '--token-file', str(self.key), '--barrier'], 'python')
        if self.jvm_libs:
            self.client_flow([str(self.java), '-Xms16m', '-Xmx128m', '-XX:ActiveProcessorCount=1',
                              '-cp', str(self.jvm_libs / '*'), 'example.sandcrab.SdkConformance',
                              self.endpoint, str(self.key), 'barrier'], 'kotlin')
        opensandbox_contract_probe.Contract(self).tests()
        opensandbox_contexts_probe.Contexts(self).tests()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--python', type=Path, required=True)
    parser.add_argument('--python-client', type=Path, default=Path(__file__).resolve().parents[3] / 'evals/sdk/python_client.py')
    parser.add_argument('--java', type=Path)
    parser.add_argument('--jvm-libs', type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0 and not args.report.exists()
    assert bool(args.java) == bool(args.jvm_libs)
    probe = SdkProbe(args.binary.resolve(), args.tools.resolve(), args.report.resolve(), args.python.absolute(),
                     args.python_client.resolve(), args.java, args.jvm_libs)
    try:
        probe.setup()
        probe.tests()
        probe.receipt['result'] = 'PASS'
    except BaseException as error:
        probe.receipt.update(result='FAIL', failureType=type(error).__name__)
        args.report.with_suffix('.diagnostic.txt').write_text(str(error))
        raise
    finally:
        try:
            probe.cleanup()
        finally:
            probe.save()


if __name__ == '__main__':
    main()
