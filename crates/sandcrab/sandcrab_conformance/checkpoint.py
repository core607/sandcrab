"""A filesystem capture must quiesce writers, preserve the tree and remain bounded."""
import hashlib
import io
import json
import os
import socket
import tarfile
import threading
import time

from . import native
from .native import call, connect, http
from .file import binary_http


def captured(probe, session, destination):
    result = call('runuser', '-u', 'daemon', '--', str(probe.binary), 'template', 'capture',
                  '--socket', str(probe.socket), session['id'], str(destination), timeout=75)
    receipt = json.loads(result.stdout)
    content = destination.read_bytes()
    assert receipt['bytes'] == len(content)
    assert receipt['sha256'] == hashlib.sha256(content).hexdigest()
    assert destination.stat().st_mode & 0o777 == 0o600
    assert len(receipt['template']['id']) == 64
    assert receipt['template']['profile'] == 'python'
    return content, receipt


def check(probe, rootfs):
    folder = probe.root / 'checkpoint-client'
    folder.mkdir(mode=0o700)
    os.chown(folder, *native.CLIENT)
    failed_downloads(probe, folder)
    session = probe.session_open()
    probe.execute(session, """python3 -c 'from pathlib import Path
for n in range(800): Path("entry-"+str(n)).write_bytes(b"fixture")
Path("executable").write_text("#!/bin/sh\\necho prepared\\n")'
chmod 0751 executable
ln executable hardlink
ln -s executable link
printf removed > deleted
rm deleted
export CHECKPOINT_VARIABLE=private-shell
mkdir working
cd working
""")
    group = probe.workloads_group / ('session-' + session['id'])
    child = probe.child(session)
    writer, _ = probe.session_exec(child, "python3 -c 'from pathlib import Path; import time\nfor n in range(500):\n Path(\"writer-next\").write_text(str(n)); Path(\"writer-next\").replace(\"writer\"); time.sleep(.01)'", wait=False)
    assert http(probe.socket, 'GET', '/v1/runs/' + writer['id'])[1]['state'] in ('queued', 'running')
    observed, ended = [], threading.Event()

    def observe():
        while not ended.wait(.001):
            if 'frozen 1' in (group / 'cgroup.events').read_text().splitlines():
                observed.append(True)
                return

    observer = threading.Thread(target=observe)
    observer.start()
    try:
        content, receipt = captured(probe, session, folder / 'workspace.tar')
    finally:
        ended.set()
        observer.join(timeout=5)
    assert observed, 'Capture never confirmed a frozen session cgroup'
    assert (group / 'cgroup.freeze').read_text().strip() == '0'
    assert http(probe.socket, 'POST', '/v1/runs/' + writer['id'] + '/cancel', {})[0] == 200
    probe.wait(writer)
    probe.forget(writer)
    probe.session_close(child)
    probe.session_forget(child)
    with tarfile.open(fileobj=io.BytesIO(content)) as archive:
        assert archive.getmember('executable').mode == 0o751
        assert archive.getmember('hardlink').islnk()
        assert archive.getmember('link').issym()
        assert 'deleted' not in archive.getnames()
        assert archive.extractfile('executable').read() == b'#!/bin/sh\necho prepared\n'
    assert receipt['template']['rootfs'] is False
    tree = published(probe, content, receipt, lost_reply=True)
    fresh = probe.session_open(templateId=tree['id'])
    assert probe.execute(fresh, 'test -z "${CHECKPOINT_VARIABLE+x}"; test ! -e deleted; ./executable; pwd') == 'prepared\n/workspace\n'
    probe.execute(fresh, 'printf changed > executable')
    assert probe.execute(session, 'cat /workspace/executable') == '#!/bin/sh\necho prepared\n'
    probe.session_close(fresh)
    probe.session_forget(fresh)
    assert http(probe.socket, 'DELETE', '/v1/templates/' + tree['id'])[0] == 200
    probe.done('filesystem-capture-freezes-then-thaws-and-preserves-links-modes-deletion-without-shell-state')

    route = f'/v1/sessions/{session["id"]}/snapshot'
    for options in ({'scope': 'filesystem'}, {'scope': 'filesystem', 'frozen': True, 'path': 'working'},
                    {'scope': 'host', 'frozen': True}):
        plan = {'path': '.', 'format': 'tar', **options}
        assert binary_http(probe.socket, 'POST', route, json.dumps(plan).encode())[0] == 400
    probe.session_close(session)
    probe.session_forget(session)
    session = probe.session_open(profile='capture')
    group = probe.workloads_group / ('session-' + session['id'])
    route = f'/v1/sessions/{session["id"]}/snapshot'
    probe.execute(session, "python3 -c 'from pathlib import Path; f=Path(\"oversized\").open(\"wb\"); f.truncate(1048577); f.close()'")
    status, _, data = binary_http(probe.socket, 'POST', route,
        json.dumps({'path': '.', 'format': 'tar', 'scope': 'filesystem', 'frozen': True}).encode())
    assert status == 413 and json.loads(data)['error']['code'] == 'FILE_LIMIT', (status, data)
    assert (group / 'cgroup.freeze').read_text().strip() == '0'
    assert probe.execute(session, 'printf thawed') == 'thawed'
    probe.session_close(session)
    probe.session_forget(session)
    probe.done('filesystem-capture-refuses-invalid-authority-and-thaws-after-size-failure')

    session = probe.session_open(templateId=rootfs['id'], rootfs=True)
    probe.execute(session, 'mv /opt/base /workspace/moved; printf prepared > /workspace/moved')
    content, receipt = captured(probe, session, folder / 'rootfs.tar')
    with tarfile.open(fileobj=io.BytesIO(content)) as archive:
        assert archive.extractfile('workspace/moved').read() == b'prepared'
        assert 'opt/base' not in archive.getnames()
        assert archive.getmember('bin/bash').isfile()
        assert archive.getmember('sandcrab-driver').size == 0
        assert not any(name.startswith(('proc/', 'dev/', 'tmp/')) for name in archive.getnames())
        assert probe.secret.name not in archive.getnames()
    assert receipt['template']['rootfs'] is True
    tree = published(probe, content, receipt, lost_reply=False)
    fresh = probe.session_open(templateId=tree['id'], rootfs=True)
    assert probe.execute(fresh, 'cat /workspace/moved; test ! -e /opt/base; test -z "${CHECKPOINT_VARIABLE+x}"') == 'prepared'
    probe.session_close(fresh)
    probe.session_forget(fresh)
    probe.session_close(session)
    probe.session_forget(session)
    assert http(probe.socket, 'DELETE', '/v1/templates/' + tree['id'])[0] == 200
    probe.done('rootfs-capture-reimports-the-complete-merged-tree-without-runtime-bindings')


def failed_downloads(probe, folder):
    """The real CLI must reject changed identity and partial bytes without retrying."""
    identity = '00000000-0000-0000-0000-000000000001'
    epoch = '00000000-0000-0000-0000-000000000002'
    payload = b'bytes'
    for failure in ('epoch', 'truncated', 'digest', 'existing'):
        endpoint = probe.root / ('checkpoint-' + failure + '.sock')
        destination = folder / (failure + '.tar')
        if failure == 'existing':
            destination.write_bytes(b'keep existing')
        errors, requests = [], []
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(endpoint))
            os.chown(endpoint, 0, native.CLIENT[1])
            endpoint.chmod(0o660)
            listener.listen()
            listener.settimeout(10)

            def serve():
                try:
                    for index in range(2):
                        stream, _ = listener.accept()
                        with stream, stream.makefile('rb') as reader:
                            stream.settimeout(10)
                            method, path, _ = reader.readline(8193).decode().split()
                            headers = {}
                            for _ in range(33):
                                line = reader.readline(8193)
                                if line == b'\r\n':
                                    break
                                key, value = line.decode().split(':', 1)
                                headers[key.lower()] = value.strip()
                            length = int(headers.get('content-length', '0'))
                            assert 0 <= length <= 1024
                            body = reader.read(length)
                            requests.append((method, path))
                            if index == 0:
                                assert method == 'GET' and path == '/v1/sessions/' + identity
                                data = json.dumps({'serverId': epoch}).encode()
                                extra = ''
                            else:
                                assert method == 'POST' and path == '/v1/sessions/' + identity + '/snapshot'
                                assert json.loads(body) == {'path': '.', 'format': 'tar', 'scope': 'filesystem', 'frozen': True}
                                data = payload
                                digest = '0' * 64 if failure == 'digest' else hashlib.sha256(data).hexdigest()
                                observed_epoch = identity if failure == 'epoch' else epoch
                                extra = f'ETag: "{digest}"\r\nX-Sandcrab-Server-Id: {observed_epoch}\r\n'
                                extra += 'X-Sandcrab-Template-Id: ' + 'a' * 64 + '\r\nX-Sandcrab-Profile: python\r\nX-Sandcrab-Rootfs: false\r\n'
                            head = f'HTTP/1.1 200 OK\r\nContent-Length: {len(data)}\r\nConnection: close\r\n{extra}\r\n'
                            stream.sendall(head.encode() + (data[:-1] if index == 1 and failure == 'truncated' else data))
                except BaseException as error:
                    errors.append(error)

            server = threading.Thread(target=serve)
            server.start()
            result = call('runuser', '-u', 'daemon', '--', str(probe.binary), 'template', 'capture',
                          '--socket', str(endpoint), identity, str(destination), check=False, timeout=30)
            server.join(timeout=15)
            assert not server.is_alive() and not errors, errors
            assert result.returncode != 0 and len(requests) == 2, result.stdout
        assert not list(folder.glob('.sandcrab-*.part'))
        if failure == 'existing':
            assert destination.read_bytes() == b'keep existing'
        else:
            assert not destination.exists()
    probe.done('capture-cli-refuses-epoch-change-partial-digest-and-replacement-without-retry')


def published(probe, content, receipt, lost_reply):
    expected = receipt['template']['id']
    route = '/v1/templates?profile=python&expectedId=' + expected
    for query in ('profile=python&expectedId=' + '0' * 64, 'profile=other&expectedId=' + expected):
        status, _, data = binary_http(probe.socket, 'POST', '/v1/templates?' + query, content)
        assert status == 409 and json.loads(data)['error']['code'] == 'TEMPLATE_ID_MISMATCH', (status, data)
        assert http(probe.socket, 'GET', '/v1/templates/' + expected)[0] == 404
        probe.no_stages()
    if lost_reply:
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(30)
            connect(stream, probe.socket)
            stream.sendall((f'POST {route} HTTP/1.1\r\nHost: sandcrab\r\nContent-Length: {len(content)}\r\nConnection: close\r\n\r\n').encode() + content)
            stream.shutdown(socket.SHUT_WR)
            # Discard the reply after the one publication request.
        deadline = time.monotonic() + 30
        while http(probe.socket, 'GET', '/v1/templates/' + expected)[0] != 200:
            assert time.monotonic() < deadline, 'Lost-response import did not become visible'
            time.sleep(.05)
        result = call('runuser', '-u', 'daemon', '--', str(probe.binary), 'template', 'get',
                      '--socket', str(probe.socket), expected)
    else:
        result = call('runuser', '-u', 'daemon', '--', str(probe.binary), 'template', 'import',
                      '--socket', str(probe.socket), '--profile', 'python', '--expected-id', expected,
                      receipt['destination'], timeout=75)
    tree = json.loads(result.stdout)
    assert tree['id'] == expected
    assert probe.put(content) == tree
    probe.done('predicted-template-identity-guards-publication-and-reconciles-' + ('lost-reply' if lost_reply else 'rootfs'))
    return tree
