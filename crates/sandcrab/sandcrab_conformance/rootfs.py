#!/usr/bin/env python3
"""Template-owned programs, protected rootfs anchors and native file operations."""
import base64
import hashlib
from http.client import HTTPResponse
import io
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tarfile
import time

from . import native as native_probe
from .native import call, connect, http
from .file import archive, binary_http
from .overlay import OverlayProbe
from .host_calls import Calls
from .streaming_file import header


class RootfsProbe(OverlayProbe):
    def __init__(self, binary, tools, report):
        super().__init__(binary, tools, report)
        self.config.write_text(self.config.read_text().replace('template_pool_bytes = 1048576', 'template_pool_bytes = 33554432')
            .replace('transfer_bytes = 1048576', 'transfer_bytes = 16777216')
            .replace('network = "none"', 'network = "none"\nhost_calls = true'))
        config = self.config.read_text()
        capture_profile = config.split('[profiles.python]', 1)[1].split('\n[', 1)[0]
        capture_profile = capture_profile.replace('transfer_bytes = 16777216', 'transfer_bytes = 1048576')
        self.config.write_text(config + '\n[profiles.capture]\n' + capture_profile)
        self.receipt['scope'] = 'Native template rootfs and file authority; minimal synthetic environment, no density measurement'
        self.receipt['probeSha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    def image(self):
        files = {}
        for program in ['/bin/bash', '/bin/mv', '/bin/cat', '/usr/bin/env']:
            sources = [program, *re.findall(r'(/[^\s()]+)', call('ldd', program).stdout)]
            for source in sources:
                files[source.lstrip('/')] = Path(source).read_bytes()
        entries = [(name, tarfile.REGTYPE, data, 0o755) for name, data in sorted(files.items())]
        entries += [('workspace/seed', tarfile.REGTYPE, b'seeded workspace', 0o644),
                    ('opt/base', tarfile.REGTYPE, b'template environment', 0o644)]
        return archive(entries)

    def tests(self):
        tree = self.put(self.image())
        cli = call('runuser', '-u', 'daemon', '--', str(self.binary), 'session', 'open',
                   '--socket', str(self.socket), '--profile', 'python', '--template', tree['id'], '--rootfs')
        parent = json.loads(cli.stdout)
        assert parent['state'] == 'ready' and parent['rootfs'] is True, parent
        assert self.execute(parent, 'cat /opt/base; printf ":"; cat seed') == 'template environment:seeded workspace'
        assert self.execute(parent, 'if command -v python3; then exit 19; fi; printf template-only') == 'template-only'
        assert self.execute(parent, 'printf "%s" "$EUID"') == str(self.uid)
        security = self.execute(parent, '''while IFS=: read -r key value; do case "$key" in CapEff|NoNewPrivs) printf '%s:%s\n' "$key" "$value";; esac; done < /proc/self/status''')
        values = dict(line.split(':', 1) for line in security.splitlines())
        assert int(values['CapEff'], 16) == 0 and int(values['NoNewPrivs']) == 1
        base = self.socket.parent / 'templates/objects' / tree['id'] / 'lower/data'
        assert base.stat().st_uid == self.uid
        self.done('rootfs-cli-executes-template-programs-without-host-profile-mounts-or-privileges')

        request, _ = self.session_exec(parent, 'printf rootfs-request | sandcrab call -', wait=False)
        with Calls(self.socket, request) as events:
            pending = events.until('call')
            assert base64.b64decode(pending['base64']) == b'rootfs-request'
            status, value = http(self.socket, 'POST', f'/v1/runs/{request["id"]}/calls/{pending["id"]}/reply',
                                 {'base64': base64.b64encode(b'rootfs-response').decode()})
            assert status == 200, value
            result = self.wait(request)
            assert result['state'] == 'succeeded' and result['result']['stdout'] == 'rootfs-response', result
        self.forget(request)
        assert self.execute(parent, 'test ! -w /sandcrab-driver && test ! -w /sandcrab/sandcrab && test ! -w /sandcrab && printf protected') == 'protected'
        self.done('rootfs-host-calls-use-the-fixed-protected-runtime-bindings')

        self.execute(parent, 'mv /opt/base /workspace/moved; printf changed > moved')
        child = self.child(parent)
        assert http(self.socket, 'GET', '/v1/sessions/'+child['id'])[1]['rootfs'] is True
        assert self.execute(child, 'cat moved; test ! -e /opt/base') == 'changed'
        independent = self.session_open(templateId=tree['id'], rootfs=True)
        assert self.execute(independent, 'cat /opt/base; test ! -e moved') == 'template environment'
        assert (base / 'opt/base').read_bytes() == b'template environment'
        assert self.execute(parent, 'if mv /workspace /replaced 2>/dev/null; then exit 42; fi; printf protected') == 'protected'
        assert self.execute(parent, 'test ! -e /replaced && test -d /workspace && printf safe') == 'safe'
        self.done('rootfs-contexts-share-one-view-and-protected-workspace-anchors-prevent-replacement')

        content = b'atomic rootfs upload'
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(15)
            connect(stream, self.socket)
            stream.sendall((f'PUT /v1/sessions/{parent["id"]}/files?path=uploaded HTTP/1.1\r\nHost: local\r\n'
                            f'Content-Length: {len(content)}\r\nExpect: 100-continue\r\n\r\n').encode())
            assert header(stream) == b'HTTP/1.1 100 Continue\r\n\r\n'
            wrapper = self.daemon_path(self.socket.parent / 'workspaces' / parent['id'])
            assert len(list(wrapper.glob('.transfer-*'))) == 1
            assert self.execute(child, 'for path in /.transfer-*; do test ! -e "$path" || exit 43; done; printf private') == 'private'
            stream.sendall(content)
            response = HTTPResponse(stream)
            response.begin()
            raw = response.read()
            assert response.status == 200, raw
        assert self.execute(child, 'cat uploaded') == 'atomic rootfs upload'
        status, _, raw = binary_http(self.socket, 'POST', f'/v1/sessions/{parent["id"]}/snapshot',
                                    json.dumps({'path': '.', 'format': 'tar'}).encode())
        assert status == 200, raw
        with tarfile.open(fileobj=io.BytesIO(raw)) as snapshot:
            assert snapshot.extractfile('seed').read() == b'seeded workspace'
            assert snapshot.extractfile('uploaded').read() == b'atomic rootfs upload'
            assert snapshot.extractfile('moved').read() == b'changed'
        assert http(self.socket, 'DELETE', '/v1/templates/'+tree['id'])[0] == 409
        self.session_close(parent)
        self.session_wait(child, terminal=True)
        self.session_forget(child)
        self.session_forget(parent)
        self.session_close(independent)
        self.session_forget(independent)
        self.done('rootfs-file-helpers-publish-atomically-outside-the-guest-root-and-snapshot-the-workspace')

        from .checkpoint import check
        check(self, tree)

        if getattr(self, 'sdk', None):
            self.sdk_template(tree)

        interrupted = self.session_open(templateId=tree['id'], rootfs=True)
        self.execute(interrupted, 'printf disposable > /opt/base')
        call('systemctl', 'kill', '--kill-who=all', '--signal=SIGKILL', self.unit)
        self.restart()
        for name in ['workspaces', 'workspace-overlays']:
            assert sorted(path.name for path in (self.socket.parent / name).iterdir()) == ['owner.json']
        assert (base / 'opt/base').read_bytes() == b'template environment'
        assert base.stat().st_uid == self.uid
        assert http(self.socket, 'DELETE', '/v1/templates/'+tree['id'])[0] == 200
        self.done('rootfs-restart-reclaims-writable-layers-and-preserves-template-content-and-identity')

        for entry in [('workspace', tarfile.SYMTYPE, str(self.secret.parent), 0o777),
                      ('workspace', tarfile.REGTYPE, b'wrong node', 0o644),
                      ('sandcrab-driver', tarfile.REGTYPE, b'unwanted copy-up', 0o644)]:
            invalid = self.put(archive([entry]))
            rejected = self.session_open(templateId=invalid['id'], rootfs=True, wait=False)
            value = self.session_wait(rejected, terminal=True)
            assert value['state'] == 'failed' and value['code'] == 'ROOTFS_UNAVAILABLE', value
            self.session_forget(rejected)
            assert self.secret.read_text() == 'host-sentinel-is-not-mounted\n'
            assert http(self.socket, 'DELETE', '/v1/templates/'+invalid['id'])[0] == 200
        self.done('rootfs-refuses-unsafe-reserved-paths-before-launch-and-releases-template-pins')

    def sdk_template(self, tree, base_id=None):
        args = self.sdk
        source = self.root / 'rootfs-client.py'
        shutil.copyfile(args.python_client, source)
        source.chmod(0o644)
        token = self.root / 'sdk-client.token'
        token.write_text((self.root / 'token').read_text())
        token.chmod(0o600)
        os.chown(token, *native_probe.CLIENT)
        libraries = self.root / 'sdk-lib'
        shutil.copytree(args.jvm_libs, libraries)
        libraries.chmod(0o755)
        for path in libraries.iterdir():
            assert path.is_file() and path.suffix == '.jar'
            path.chmod(0o644)
        for name, expected in [('sandbox-1.1.0.jar', 'cb96348a273124a899586e23abe9b5aeafcc98b1d6055532a62ecc8a2a22a392'),
                               ('sandbox-api-1.1.0.jar', '4cc5236a3c69d4328a8e80754fe0ccf47bddea10a0eaecd5dd01ba299bb87e45')]:
            assert hashlib.sha256((libraries / name).read_bytes()).hexdigest() == expected
        endpoint, image = f'127.0.0.1:{self.port}', 'python@sha256:'+tree['id']
        clients = [
            ('python', [str(args.python), str(source), '--endpoint', endpoint, '--token-file', str(token), '--image', image]),
            ('kotlin', [str(args.java), '-Xms16m', '-Xmx128m', '-XX:ActiveProcessorCount=1', '-cp', str(libraries / '*'),
                        'example.sandcrab.SdkRootfs', endpoint, str(token), image]),
        ]
        for label, command in clients:
            result = subprocess.run(command, user=native_probe.CLIENT[0], group=native_probe.CLIENT[1],
                extra_groups=[native_probe.CLIENT[1]], env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'},
                text=True, capture_output=True, timeout=90)
            assert result.returncode == 0, result.stderr
            receipt = json.loads(result.stdout)
            assert receipt['result'] == 'PASS' and receipt['sdkVersion'] == '1.1.0', receipt
            assert http(self.socket, 'GET', '/v1/sessions/'+receipt['sandboxId'])[0] == 404
            deadline = time.monotonic()+5
            while not all(http(self.socket, 'GET', '/v1/runs/'+identity)[0] == 404 for identity in receipt['commandIds']):
                assert time.monotonic() < deadline
                time.sleep(.02)
            assert not list((self.socket.parent / 'jobs').iterdir())
            assert (self.socket.parent / 'templates/objects' / (base_id or tree['id']) / 'lower/data/opt/base').read_bytes() == b'template environment'
            self.receipt[label+'Sdk'] = receipt
            self.done(label+'-published-sdk-creates-a-template-rootfs-and-cleans-its-native-records')
        source = self.root / 'environment-client.py'
        shutil.copyfile(args.environment_client, source)
        source.chmod(0o644)
        artifacts = self.root / 'environment-client'
        artifacts.mkdir(mode=0o700)
        os.chown(artifacts, *native_probe.CLIENT)
        result = subprocess.run([str(args.python), str(source), '--endpoint', endpoint,
            '--token-file', str(token), '--base-image', image, '--archive', str(artifacts / 'prepared.tar'),
            '--receipt', str(artifacts / 'prepared.json')],
            user=native_probe.CLIENT[0], group=native_probe.CLIENT[1], extra_groups=[native_probe.CLIENT[1]],
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, text=True, capture_output=True, timeout=150)
        assert result.returncode == 0, result.stderr
        receipt = json.loads(result.stdout)
        assert receipt['result'] == 'PASS' and len(receipt['instanceIds']) == 2, receipt
        assert len(set([receipt['builderId'], *receipt['instanceIds']])) == 3
        for identity in [receipt['builderId'], *receipt['instanceIds']]:
            assert http(self.socket, 'GET', '/v1/sessions/' + identity)[0] == 404
        assert http(self.socket, 'GET', '/v1/templates/' + receipt['templateId'])[0] == 200
        assert http(self.socket, 'DELETE', '/v1/templates/' + receipt['templateId'])[0] == 200
        assert not list((self.socket.parent / 'jobs').iterdir())
        self.receipt['environmentPublication'] = receipt
        self.done('published-python-sdk-prepares-validates-publishes-and-reuses-independent-environments')
