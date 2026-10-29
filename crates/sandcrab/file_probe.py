#!/usr/bin/env python3
"""Native file transfer acceptance; fixture data and every attempt remain independently inspectable."""
import argparse
import hashlib
from http.client import HTTPResponse
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tarfile
import threading
import time
import uuid

import native_probe
from native_probe import call, connect, http
from volume_probe import VolumeProbe


def binary_http(endpoint, method, path, body):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(75)
        connect(stream, endpoint)
        stream.sendall(f'{method} {path} HTTP/1.1\r\nHost: sandcrab\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode() + body)
        response = HTTPResponse(stream)
        response.begin()
        data = response.read(16 * 1024 * 1024 + 1)
        assert len(data) <= 16 * 1024 * 1024
        return response.status, dict(response.getheaders()), data


def archive(entries):
    target = io.BytesIO()
    with tarfile.open(fileobj=target, mode='w', format=tarfile.PAX_FORMAT) as output:
        for name, kind, content, mode in entries:
            info = tarfile.TarInfo(name)
            info.type, info.mode = kind, mode
            if kind == tarfile.REGTYPE:
                info.size = len(content)
                output.addfile(info, io.BytesIO(content))
            else:
                if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                    info.linkname = content
                output.addfile(info)
    return target.getvalue()


class FileProbe(VolumeProbe):
    def __init__(self, binary, tools, report):
        super().__init__(binary, tools, report)
        self.config.write_text(self.config.read_text().replace('[profiles.python]',
            'max_file_records = 6\nmax_file_transfers = 1\n[profiles.python]', 1))
        self.receipt['scope'] = 'Native raw/tar upload, snapshot, quota, cancellation and crash recovery; synthetic files, no model or production cutover'
        self.receipt['fileProbeSha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    def plan(self, session, path, content, **options):
        request = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId'], 'sessionId': session['id'],
                   'path': path, 'format': 'raw', 'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest(), **options}
        status, value = http(self.socket, 'POST', '/v1/uploads', request)
        assert status == 201 and value['state'] == 'waiting', value
        return request

    def restart(self):
        call('systemctl', 'stop', self.unit, check=False)
        call('systemctl', 'reset-failed', self.unit, check=False)
        # Units retained for recovery can still reference the transient supervisor.
        # Restart that definition if collection cannot finish; do not overwrite it.
        deadline = time.monotonic() + 5
        while call('systemctl', 'show', self.unit, '-p', 'LoadState', '--value').stdout.strip() != 'not-found':
            if time.monotonic() >= deadline:
                expected = 'PATH=' + getattr(self, 'launch_path', '/usr/bin:/bin')
                assert call('systemctl', 'show', self.unit, '-p', 'Environment', '--value').stdout.strip() == expected
                call('systemctl', 'start', self.unit)
                self.wait_ready()
                return
            time.sleep(.025)
        self.start()

    def send(self, request, content):
        status, _, data = binary_http(self.socket, 'PUT', f'/v1/uploads/{request["id"]}/content', content)
        value = json.loads(data)
        assert status == 200, value
        return value

    def upload(self, session, path, content, **options):
        request = self.plan(session, path, content, **options)
        return request, self.send(request, content)

    def forget_upload(self, request):
        assert http(self.socket, 'POST', f'/v1/uploads/{request["id"]}/forget', {}) == (200, {'forgotten': True})

    def capture(self, session, path, **options):
        status, headers, content = binary_http(self.socket, 'POST', f'/v1/sessions/{session["id"]}/snapshot',
            json.dumps({'path': path, 'format': 'raw', **options}).encode())
        assert status == 200, (status, content)
        assert headers['Content-Length'] == str(len(content))
        assert headers['ETag'] == '"' + hashlib.sha256(content).hexdigest() + '"'
        return content

    def command(self, session, code):
        request, result = self.session_exec(session, code)
        self.forget(request)
        assert result['state'] == 'succeeded', result
        return result['result']['stdout']

    def no_stages(self, volume=None):
        assert not list((self.storage / 'state/uploads/stages').glob('*.json'))
        if volume:
            assert not list((self.data / 'volumes' / volume['id']).glob('.transfer-*'))

    def pending_upload(self, request):
        stream = socket.socket(socket.AF_UNIX)
        stream.settimeout(45)
        connect(stream, self.socket)
        stream.sendall((f'PUT /v1/uploads/{request["id"]}/content HTTP/1.1\r\nHost: sandcrab\r\n'
                        f'Content-Length: {request["bytes"]}\r\nExpect: 100-continue\r\n\r\n').encode())
        interim = b''
        while not interim.endswith(b'\r\n\r\n'):
            part = stream.recv(1)
            assert part and len(interim) < 8192
            interim += part
        assert interim == b'HTTP/1.1 100 Continue\r\n\r\n', interim
        return stream

    def upload_wait(self, request):
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            status, result = http(self.socket, 'GET', f'/v1/uploads/{request["id"]}')
            assert status == 200, result
            if result['state'] in ('succeeded', 'failed', 'unknown', 'closing'):
                return result
            time.sleep(.025)
        raise AssertionError('upload did not finish')

    def tests(self):
        self.bootstrap_recovery()
        session = self.session_open()
        content = bytes((i * 73) % 256 for i in range(131173))
        request, result = self.upload(session, 'data.bin', content)
        assert result['state'] == 'succeeded' and result['publication'] == 'committed', result
        assert self.capture(session, 'data.bin') == content
        assert http(self.socket, 'POST', '/v1/uploads', request) == (200, result)
        changed = {**request, 'sha256': '0' * 64}
        assert http(self.socket, 'POST', '/v1/uploads', changed)[1]['error']['code'] == 'ID_CONFLICT'
        self.forget_upload(request)
        for payload in (b'', b'\0binary\xff\n'):
            request, result = self.upload(session, 'data.bin', payload, replace=True)
            assert result['state'] == 'succeeded', result
            assert self.capture(session, 'data.bin') == payload
            self.forget_upload(request)
        self.done('files-stream-beyond-json-limit-empty-binary-replace-and-replay')
        request = self.plan(session, 'continue.bin', content)
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(30)
            connect(stream, self.socket)
            stream.sendall((f'PUT /v1/uploads/{request["id"]}/content HTTP/1.1\r\nHost: sandcrab\r\n'
                            f'Content-Length: {len(content)}\r\nExpect: 100-continue\r\n\r\n').encode())
            interim = b''
            while not interim.endswith(b'\r\n\r\n'):
                part = stream.recv(1)
                assert part and len(interim) < 8192
                interim += part
            assert interim == b'HTTP/1.1 100 Continue\r\n\r\n', interim
            stream.sendall(content)
            response = HTTPResponse(stream)
            response.begin()
            assert response.status == 200
            assert json.loads(response.read())['state'] == 'succeeded'
        assert self.capture(session, 'continue.bin') == content
        self.forget_upload(request)
        self.done('files-expect-continue-after-admission')

        before = self.capture(session, 'data.bin')
        request, result = self.upload(session, 'data.bin', b'overwrite')
        assert result['state'] == 'failed' and result['code'] == 'PATH_EXISTS', result
        self.forget_upload(request)
        request, result = self.upload(session, 'data.bin', b'wrong checksum', replace=True, sha256='0' * 64)
        assert result['state'] == 'failed' and result['code'] == 'CONTENT_MISMATCH', result
        assert self.capture(session, 'data.bin') == before
        self.forget_upload(request)
        self.done('files-refusals-and-checksum-failure-preserve-the-old-file')

        data = archive([('pkg', tarfile.DIRTYPE, b'', 0o750), ('pkg/你好.txt', tarfile.REGTYPE, 'hello 世界'.encode(), 0o640),
                        ('pkg/alias.txt', tarfile.LNKTYPE, 'pkg/你好.txt', 0o640),
                        ('pkg/link', tarfile.SYMTYPE, '你好.txt', 0o777), ('host', tarfile.SYMTYPE, str(self.secret), 0o777)])
        request, result = self.upload(session, 'project', data, format='tar')
        assert result['state'] == 'succeeded', result
        self.forget_upload(request)
        workspace = self.root / 'runtime/jobs' / session['id'] / 'work'
        assert (workspace / 'project/pkg/你好.txt').read_bytes() == 'hello 世界'.encode()
        assert (workspace / 'project/pkg').stat().st_mode & 0o777 == 0o750
        assert (workspace / 'project/pkg/你好.txt').stat().st_ino == (workspace / 'project/pkg/alias.txt').stat().st_ino
        assert os.readlink(workspace / 'project/host') == str(self.secret)
        captured = self.capture(session, 'project', format='tar')
        with tarfile.open(fileobj=io.BytesIO(captured)) as source:
            assert source.extractfile('pkg/你好.txt').read() == 'hello 世界'.encode()
            assert source.extractfile('pkg/alias.txt').read() == 'hello 世界'.encode()
            assert source.getmember('host').issym() and source.getmember('host').linkname == str(self.secret)
            assert sum(member.islnk() for member in source.getmembers()) == 1
            assert self.secret.read_bytes() not in b''.join(source.extractfile(m).read() for m in source.getmembers() if m.isfile())
        status, _, body = binary_http(self.socket, 'POST', f'/v1/sessions/{session["id"]}/snapshot', json.dumps({'path': 'project/host', 'format': 'raw'}).encode())
        assert status == 400, (status, body)
        self.done('files-ordinary-tar-preserves-unicode-modes-and-links-without-following-host-links')

        for entries in [
            [('../escape', tarfile.REGTYPE, b'bad', 0o644)],
            [('/absolute', tarfile.REGTYPE, b'bad', 0o644)],
            [('..\\escape', tarfile.REGTYPE, b'bad', 0o644)],
            [('link', tarfile.SYMTYPE, str(self.root), 0o777), ('link/host-sentinel', tarfile.REGTYPE, b'bad', 0o644)],
            [('hard', tarfile.LNKTYPE, str(self.secret), 0o644)],
            [('fifo', tarfile.FIFOTYPE, b'', 0o644)],
        ]:
            original = self.secret.read_bytes()
            payload = archive(entries)
            request, result = self.upload(session, 'refused', payload, format='tar')
            assert result['state'] == 'failed', result
            assert not (workspace / 'refused').exists()
            assert self.secret.read_bytes() == original
            self.forget_upload(request)
        self.no_stages()
        self.done('files-tar-escape-links-and-special-nodes-never-publish')
        sparse = self.root / 'sparse-input'
        sparse.mkdir()
        with (sparse / 'file').open('wb') as stream:
            stream.seek(1024 * 1024 - 1)
            stream.write(b'x')
        for format in ('gnu', 'pax'):
            target = sparse / (format + '.tar')
            call('tar', '--format=' + format, '--sparse', '-cf', str(target), '-C', str(sparse), 'file')
            request, result = self.upload(session, 'refused', target.read_bytes(), format='tar')
            assert result['state'] == 'failed' and result['code'] == 'UNSUPPORTED_ARCHIVE_ENTRY', result
            assert not (workspace / 'refused').exists()
            self.forget_upload(request)
        self.done('files-gnu-and-pax-sparse-archives-are-refused-without-publication')
        original = self.secret.read_bytes()
        replacement = archive([('new.txt', tarfile.REGTYPE, b'replaced directory', 0o644)])
        request, result = self.upload(session, 'project', replacement, format='tar', replace=True)
        assert result['state'] == 'succeeded', result
        assert not (workspace / 'project/pkg').exists()
        assert (workspace / 'project/new.txt').read_bytes() == b'replaced directory'
        assert self.secret.read_bytes() == original
        self.forget_upload(request)
        self.no_stages()
        self.done('files-tar-replaces-a-nonempty-directory-and-cleans-the-old-tree')
        self.cli(session, content)
        self.session_close(session)
        self.session_forget(session)
        self.quota()
        self.record_limits()
        self.interrupted_uploads()
        self.publication_faults()

    def bootstrap_recovery(self):
        volume, result = self.volume()
        assert result['state'] == 'ready', result
        session = self.session_open(volumeId=volume['id'])
        assert self.command(session, 'printf prior-version-data > kept; printf written') == 'written'
        prior_job = self.socket.parent / 'jobs' / session['id']
        assert prior_job.exists()
        call('systemctl', 'kill', '--kill-whom=main', '--signal=KILL', self.unit)
        call('systemctl', 'stop', self.unit, check=False)
        call('systemctl', 'reset-failed', self.unit, check=False)
        # Seed the pre-files release state: a stopped session remains, but no file
        # metadata has ever been owned. There are no upload records or stages to discard.
        uploads = self.storage / 'state/uploads'
        owner = json.loads((uploads / 'owner.json').read_text())
        assert owner['runtimeRoot'] == str(self.socket.parent)
        assert owner['unitPrefix'] == self.name + '-'
        (uploads / 'records').rmdir()
        (uploads / 'stages').rmdir()
        (uploads / 'owner.json').unlink()
        unowned = uploads / 'operator-sentinel'
        unowned.write_text('preserve unowned upload state')
        try:
            self.restart()
        except AssertionError:
            assert 'Refusing unowned file state' in call('journalctl', '-u', self.unit, '--no-pager', '-n', '30').stdout
        else:
            raise AssertionError('unowned file state was adopted')
        assert unowned.read_text() == 'preserve unowned upload state'
        assert not (uploads / 'owner.json').exists()
        assert prior_job.exists()
        self.done('files-first-start-refuses-unowned-upload-state-before-touching-prior-workspaces')
        unowned.unlink()
        self.restart()
        assert not prior_job.exists()
        assert (uploads / 'owner.json').exists()
        assert http(self.socket, 'GET', '/v1/sessions/' + session['id'])[0] == 404
        session = self.session_open(volumeId=volume['id'])
        assert self.command(session, 'cat kept') == 'prior-version-data'
        self.session_close(session)
        self.session_forget(session)
        self.volume_delete(volume)
        self.volume_forget(volume)
        self.done('files-first-start-recovers-prior-session-residue-and-preserves-durable-volume-data')

    def cli(self, session, content):
        local = self.root / 'client-files'
        local.mkdir(mode=0o750)
        os.chown(local, *native_probe.CLIENT)
        source = local / 'source.bin'
        source.write_bytes(content)
        source.chmod(0o644)
        output = local / 'result.bin'
        cli = ['runuser', '-u', 'daemon', '--', str(self.binary), 'files']
        uploaded = call(*cli, 'put', '--socket', str(self.socket), session['id'], str(source), 'cli.bin', '--keep-result')
        receipt = json.loads(uploaded.stdout)
        assert receipt['state'] == 'succeeded' and 'uploadId=' + receipt['id'] in uploaded.stderr
        assert json.loads(call(*cli, 'status', '--socket', str(self.socket), receipt['id']).stdout)['state'] == 'succeeded'
        downloaded = call(*cli, 'get', '--socket', str(self.socket), session['id'], 'cli.bin', str(output))
        assert json.loads(downloaded.stdout)['sha256'] == hashlib.sha256(content).hexdigest()
        assert output.read_bytes() == content
        output.write_bytes(b'old local bytes')
        refused = call(*cli, 'get', '--socket', str(self.socket), session['id'], 'cli.bin', str(output), check=False)
        assert refused.returncode != 0 and output.read_bytes() == b'old local bytes'
        assert not list(local.glob('.sandcrab-*.part'))
        call(*cli, 'get', '--socket', str(self.socket), session['id'], 'cli.bin', str(output), '--replace')
        assert output.read_bytes() == content
        call(*cli, 'forget', '--socket', str(self.socket), receipt['id'])
        self.done('files-cli-roundtrip-status-and-safe-local-installation')
        endpoint = self.root / 'download-peer.sock'
        for payload in (content[:-1], b'x' * len(content)):
            errors = []
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(endpoint))
                endpoint.chmod(0o660)
                os.chown(endpoint, 0, native_probe.CLIENT[1])
                listener.listen(1)
                listener.settimeout(10)

                def serve():
                    try:
                        with listener.accept()[0] as stream:
                            stream.settimeout(10)
                            received = b''
                            while b'\r\n\r\n' not in received:
                                part = stream.recv(4096)
                                assert part
                                received += part
                                assert len(received) < 8192
                            header, body = received.split(b'\r\n\r\n', 1)
                            size = int(next(line.split(b':', 1)[1] for line in header.split(b'\r\n') if line.lower().startswith(b'content-length:')))
                            while len(body) < size:
                                part = stream.recv(size - len(body))
                                assert part
                                body += part
                            assert header.startswith(b'POST /v1/sessions/')
                            stream.sendall((f'HTTP/1.1 200 OK\r\nContent-Length: {len(content)}\r\n'
                                            f'ETag: "{hashlib.sha256(content).hexdigest()}"\r\nConnection: close\r\n\r\n').encode() + payload)
                    except BaseException as error:
                        errors.append(error)

                server = threading.Thread(target=serve)
                server.start()
                output.write_bytes(b'preserved local file')
                try:
                    result = call(*cli, 'get', '--socket', str(endpoint), session['id'], 'cli.bin', str(output), '--replace', check=False)
                finally:
                    server.join(timeout=15)
                assert not server.is_alive() and not errors, errors
                assert result.returncode != 0, result
                assert output.read_bytes() == b'preserved local file'
                assert not list(local.glob('.sandcrab-*.part'))
            endpoint.unlink()
        self.done('files-cli-truncated-or-corrupted-download-preserves-local-destination')

    def quota(self):
        volume, state = self.volume(byteLimit=1048576, inodeLimit=32)
        assert state['state'] == 'ready', state
        session = self.session_open(volumeId=volume['id'])
        payload = b'x' * (2 * 1024 * 1024)
        request = self.plan(session, 'too-big', payload)
        try:
            result = self.send(request, payload)
            self.receipt['quotaResponseLost'] = False
        except (BrokenPipeError, ConnectionResetError, native_probe.HTTPException):
            # A quota failure may close while the sender still has bytes queued.
            # Recover by identity; never resend content under a fresh upload ID.
            self.receipt['quotaResponseLost'] = True
            result = self.upload_wait(request)
        assert result['state'] == 'failed' and result['code'] == 'FILE_CAPACITY', result
        self.forget_upload(request)
        assert self.command(session, 'test ! -e too-big; printf usable') == 'usable'
        self.no_stages(volume)
        request, result = self.upload(session, 'ok', b'kept')
        assert result['state'] == 'succeeded', result
        self.session_close(session)
        self.session_forget(session)
        self.restart()
        replay = http(self.socket, 'POST', '/v1/uploads', {**request, 'serverId': self.info['serverId']})
        assert replay == (200, result), replay
        assert replay[1]['volumeId'] == volume['id']
        session = self.session_open(volumeId=volume['id'])
        assert self.capture(session, 'ok') == b'kept'
        self.forget_upload(request)
        self.session_close(session)
        self.session_forget(session)
        self.volume_delete(volume)
        self.volume_forget(volume)
        self.done('files-volume-quota-and-restart-retain-data-and-upload-identity')

    def record_limits(self):
        session = self.session_open()
        requests = [self.plan(session, str(index), b'') for index in range(6)]
        extra = {**requests[0], 'id': str(uuid.uuid4())}
        assert http(self.socket, 'POST', '/v1/uploads', extra)[1]['error']['code'] == 'FILE_RECORD_CAPACITY'
        listed = http(self.socket, 'GET', '/v1/uploads')[1]
        assert [row['id'] for row in listed['uploads']] == sorted(r['id'] for r in requests)
        for request in requests:
            cancelled = http(self.socket, 'POST', f'/v1/uploads/{request["id"]}/cancel', {})[1]
            assert cancelled['state'] == 'failed' and cancelled['publication'] == 'none'
            self.forget_upload(request)
        self.session_close(session)
        self.session_forget(session)
        self.done('files-bounded-records-discovery-and-cancel-before-content')

    def interrupted_uploads(self):
        volume, state = self.volume()
        assert state['state'] == 'ready', state
        session = self.session_open(volumeId=volume['id'])
        request, result = self.upload(session, 'kept', b'original')
        assert result['state'] == 'succeeded', result
        self.forget_upload(request)
        for action, expected in [('disconnect', 'CONTENT_INCOMPLETE'), ('cancel', 'FILE_CANCELLED'),
                                 ('deadline', 'FILE_TIMEOUT')]:
            request = self.plan(session, 'kept', b'replacement', replace=True)
            start = time.monotonic()
            with self.pending_upload(request) as stream:
                stream.sendall(b're')
                if action == 'disconnect':
                    stream.shutdown(socket.SHUT_WR)
                elif action == 'cancel':
                    assert http(self.socket, 'POST', f'/v1/uploads/{request["id"]}/cancel', {})[0] == 200
                response = HTTPResponse(stream)
                response.begin()
                assert response.status == 200
                result = json.loads(response.read())
            elapsed = time.monotonic() - start
            assert result['state'] == 'failed' and result['code'] == expected, result
            if action == 'deadline':
                assert 29 <= elapsed < 40, elapsed
                self.receipt['uploadDeadlineSeconds'] = round(elapsed, 3)
            assert self.capture(session, 'kept') == b'original'
            assert self.command(session, 'printf usable') == 'usable'
            self.no_stages(volume)
            self.forget_upload(request)
        self.done('files-disconnect-cancel-and-body-deadline-preserve-data-and-release-admission')

        request = self.plan(session, 'kept', b'replacement', replace=True)
        with self.pending_upload(request) as stream:
            stream.sendall(b're')
            self.session_close(session)
            result = self.upload_wait(request)
            assert result['state'] == 'failed', result
        self.no_stages(volume)
        self.forget_upload(request)
        self.session_forget(session)
        session = self.session_open(volumeId=volume['id'])
        assert self.capture(session, 'kept') == b'original'
        self.done('files-session-close-cancels-receive-before-releasing-the-volume')

        request = self.plan(session, 'kept', b'replacement', replace=True)
        with self.pending_upload(request) as stream:
            stream.sendall(b're')
            assert http(self.socket, 'POST', f'/v1/sessions/{session["id"]}/renew', {'ttlMillis': 300})[0] == 200
            assert self.session_wait(session, terminal=True)['state'] == 'expired'
            assert self.upload_wait(request)['state'] == 'failed'
        self.no_stages(volume)
        self.forget_upload(request)
        self.session_forget(session)
        session = self.session_open(volumeId=volume['id'])
        assert self.capture(session, 'kept') == b'original'
        self.done('files-session-expiry-cancels-an-active-upload-and-retains-volume-data')

        request = self.plan(session, 'kept', b'replacement', replace=True)
        with self.pending_upload(request) as stream:
            stream.sendall(b're')
            call('systemctl', 'kill', '--kill-whom=main', '--signal=KILL', self.unit)
            self.restart()
        result = self.upload_wait(request)
        assert result['state'] == 'failed' and result['code'] == 'INTERRUPTED', result
        assert result['publication'] == 'none'
        self.no_stages(volume)
        assert http(self.socket, 'POST', '/v1/uploads', request) == (200, result)
        self.forget_upload(request)
        session = self.session_open(volumeId=volume['id'])
        assert self.capture(session, 'kept') == b'original'
        self.session_close(session)
        self.session_forget(session)
        self.volume_delete(volume)
        self.volume_forget(volume)
        self.done('files-supervisor-loss-before-publication-recovers-without-writing')

    def publication_faults(self):
        helpers = self.root / 'file-helpers'
        helpers.mkdir(mode=0o755)
        gate, entered = helpers / 'gate.json', helpers / 'entered'
        (helpers / 'systemd-run').write_text(f'''#!/usr/bin/python3
import json,os,subprocess,sys,time
from pathlib import Path
args=sys.argv[1:]
gate=Path({str(gate)!r})
if '__file' not in args or not gate.exists():
    os.execv('/usr/bin/systemd-run',['systemd-run',*args])
job=json.loads(Path(args[args.index('__file')+1]).read_text())
fault=json.loads(gate.read_text())
if job['action']!=fault['action']:
    os.execv('/usr/bin/systemd-run',['systemd-run',*args])
def hold():
    Path({str(entered)!r}).write_text(job['action'])
    while gate.exists(): time.sleep(.02)
if fault['phase']=='fail':
    # Fail inside the real bounded unit, so Result/ExecMainStatus describe the fault.
    args=args[:args.index('__file')-1]+['/usr/bin/false']
if fault['phase']=='before': hold()
if fault['phase']=='oom':
    args=['MemoryMax=8388608' if arg.startswith('MemoryMax=') else arg for arg in args]
result=subprocess.run(['/usr/bin/systemd-run',*args])
if fault['phase']=='oom':
    unit=args[args.index('--unit')+1]
    observed=subprocess.run(['/usr/bin/systemctl','show',unit,'-p','Result','--value'],capture_output=True,text=True,check=True)
    Path({str(entered)!r}).write_text(observed.stdout.strip())
if result.returncode==0 and fault['phase']=='after': hold()
sys.exit(result.returncode)
''')
        (helpers / 'systemd-run').chmod(0o755)
        self.launch_path = str(helpers) + ':/usr/bin:/bin'
        self.restart()

        def arm(action, phase):
            entered.unlink(missing_ok=True)
            gate.write_text(json.dumps({'action': action, 'phase': phase}))

        def await_gate():
            deadline = time.monotonic() + 10
            while not entered.exists() and time.monotonic() < deadline:
                time.sleep(.025)
            assert entered.exists(), 'file helper did not reach the controlled delay'

        volume, result = self.volume()
        assert result['state'] == 'ready', result
        workspace = self.data / 'volumes' / volume['id'] / 'data'
        try:
            for phase in ('before', 'after', 'metadata'):
                session = self.session_open(volumeId=volume['id'])
                self.command(session, 'printf original > kept')
                request = self.plan(session, 'kept', b'replacement', replace=True)
                arm('publish', 'after' if phase == 'metadata' else phase)
                with self.pending_upload(request) as stream:
                    stream.sendall(b'replacement')
                    await_gate()
                    record_path = self.storage / 'state/uploads/records' / (request['id'] + '.json')
                    assert json.loads(record_path.read_text())['state'] == 'publishing'
                    assert (workspace / 'kept').read_bytes() == (b'original' if phase == 'before' else b'replacement')
                    if phase == 'metadata':
                        saved = helpers / 'saved-record.json'
                        record_path.rename(saved)
                        record_path.mkdir(mode=0o700)
                        try:
                            gate.unlink()
                            response = HTTPResponse(stream)
                            response.begin()
                            assert response.status == 503, response.read()
                            assert json.loads(response.read())['error']['code'] == 'FILE_STATE_UNCERTAIN'
                            assert not http(self.socket, 'GET', '/v1/info')[1]['files']['available']
                            view = http(self.socket, 'GET', f'/v1/uploads/{request["id"]}')[1]
                            assert view['state'] == 'unknown' and view['publication'] == 'unknown', view
                        finally:
                            record_path.rmdir()
                            saved.rename(record_path)
                    else:
                        call('systemctl', 'kill', '--kill-whom=main', '--signal=KILL', self.unit)
                        gate.unlink()
                    self.restart()
                recovered = self.upload_wait(request)
                assert recovered['state'] == 'unknown' and recovered['publication'] == 'unknown', recovered
                self.no_stages(volume)
                session = self.session_open(volumeId=volume['id'])
                self.command(session, 'printf later-edit > kept')
                assert http(self.socket, 'POST', '/v1/uploads', request) == (200, recovered)
                assert self.send(request, b'replacement') == recovered
                assert self.capture(session, 'kept') == b'later-edit'
                self.forget_upload(request)
                self.session_close(session)
                self.session_forget(session)
                self.done('files-' + phase + '-publication-loss-reconciles-without-overwriting-a-later-edit')

            session = self.session_open(volumeId=volume['id'])
            self.command(session, 'printf x > kept')
            arm('cleanup', 'before')
            with socket.socket(socket.AF_UNIX) as stream:
                stream.settimeout(20)
                connect(stream, self.socket)
                body = json.dumps({'path': 'kept', 'format': 'raw'}).encode()
                stream.sendall((f'POST /v1/sessions/{session["id"]}/snapshot HTTP/1.1\r\nHost: sandcrab\r\n'
                                f'Content-Length: {len(body)}\r\n\r\n').encode() + body)
                response = HTTPResponse(stream)
                response.begin()
                assert response.status == 200
                await_gate()
                assert http(self.socket, 'POST', f'/v1/sessions/{session["id"]}/close', {})[0] == 200
                assert http(self.socket, 'GET', '/v1/volumes/' + volume['id'])[1]['attachedTo'] == session['id']
                refused = self.session_open(wait=False, volumeId=volume['id'])
                assert self.session_wait(refused, terminal=True)['code'] == 'VOLUME_IN_USE'
                self.session_forget(refused)
                gate.unlink()
                # Closure cancels the transfer. No fixed-length success can precede cleanup.
                try:
                    response.read()
                except native_probe.HTTPException:
                    pass
                else:
                    raise AssertionError('cancelled snapshot completed as successful')
            assert self.session_wait(session, terminal=True)['state'] == 'closed'
            self.session_forget(session)
            self.no_stages(volume)
            self.done('files-snapshot-cleanup-pins-volume-and-withholds-success-until-release')

            session = self.session_open(volumeId=volume['id'])
            arm('snapshot', 'before')
            with socket.socket(socket.AF_UNIX) as stream:
                connect(stream, self.socket)
                body = json.dumps({'path': 'kept', 'format': 'raw'}).encode()
                stream.sendall((f'POST /v1/sessions/{session["id"]}/snapshot HTTP/1.1\r\nHost: sandcrab\r\n'
                                f'Content-Length: {len(body)}\r\n\r\n').encode() + body)
                await_gate()
                group = call('systemctl', 'show', self.name + '-' + session['id'], '-p', 'ControlGroup', '--value').stdout.strip()
                events = Path('/sys/fs/cgroup') / group.lstrip('/') / 'cgroup.events'
                assert 'frozen 1' in events.read_text()
            gate.unlink()
            deadline = time.monotonic() + 15
            while list((self.storage / 'state/uploads/stages').glob('*.json')) and time.monotonic() < deadline:
                time.sleep(.025)
            self.no_stages(volume)
            assert 'frozen 0' in events.read_text()
            assert self.command(session, 'printf thawed') == 'thawed'
            self.done('files-disconnected-snapshot-thaws-the-session-and-removes-staging')

            arm('cleanup', 'fail')
            request, result = self.upload(session, 'kept', b'committed', replace=True)
            assert result['state'] == 'closing' and result['publication'] == 'committed', result
            assert (workspace / 'kept').read_bytes() == b'committed'
            assert http(self.socket, 'POST', f'/v1/uploads/{request["id"]}/forget', {})[1]['error']['code'] == 'UPLOAD_ACTIVE'
            assert self.session_wait(session, terminal=True)['state'] == 'closing'
            assert http(self.socket, 'GET', '/v1/volumes/' + volume['id'])[1]['attachedTo'] == session['id']
            gate.unlink()
            self.restart()
            result = self.upload_wait(request)
            assert result['state'] == 'succeeded' and result['publication'] == 'committed', result
            self.no_stages(volume)
            self.forget_upload(request)
            session = self.session_open(volumeId=volume['id'])
            assert self.capture(session, 'kept') == b'committed'
            self.session_close(session)
            self.session_forget(session)
            self.done('files-uncertain-cleanup-retains-ownership-until-restart-recovery')

            session = self.session_open(volumeId=volume['id'])
            payload = io.BytesIO()
            with tarfile.open(fileobj=payload, mode='w', format=tarfile.GNU_FORMAT) as output:
                entry = tarfile.TarInfo('a' * (4 * 1024 * 1024))
                output.addfile(entry, io.BytesIO(b''))
            payload = payload.getvalue()
            request = self.plan(session, 'oversized-name', payload, format='tar')
            epoch = self.info['serverId']
            arm('receive', 'oom')
            try:
                result = self.send(request, payload)
            except (BrokenPipeError, ConnectionResetError, native_probe.HTTPException):
                result = self.upload_wait(request)
            assert result['state'] == 'failed' and result['code'] == 'FILE_RESOURCE_LIMIT', result
            assert entered.read_text() == 'oom-kill'
            self.receipt['fileHelperOom'] = {'injectedMemoryMaxBytes': 8388608, 'unitResult': 'oom-kill'}
            gate.unlink()
            assert http(self.socket, 'GET', '/v1/info')[1]['serverId'] == epoch
            assert self.command(session, 'test ! -e oversized-name; printf alive') == 'alive'
            assert self.capture(session, 'kept') == b'committed'
            self.no_stages(volume)
            self.forget_upload(request)
            self.session_close(session)
            self.session_forget(session)
            self.done('files-receive-helper-oom-is-contained-without-ending-the-service-or-session')
        finally:
            gate.unlink(missing_ok=True)
            del self.launch_path
        self.restart()
        self.volume_delete(volume)
        self.volume_forget(volume)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0
    assert not args.report.exists(), 'Use a fresh receipt for every attempt'
    def interrupted(signum, frame):
        raise KeyboardInterrupt('File probe interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    probe = FileProbe(args.binary.resolve(), args.tools.resolve(), args.report.resolve())
    try:
        probe.setup()
        probe.tests()
        probe.receipt['result'] = 'PASS'
    except BaseException as error:
        probe.receipt['result'] = 'FAIL'
        probe.receipt['failureType'] = type(error).__name__
        details = str(error)
        if isinstance(error, subprocess.CalledProcessError):
            details += '\n' + (error.stdout or '') + '\n' + (error.stderr or '')
        args.report.with_suffix('.diagnostic.txt').write_text(details)
        raise
    finally:
        try:
            probe.cleanup()
        except BaseException as error:
            probe.receipt['cleanup'] = 'FAIL'
            probe.receipt['cleanupFailureType'] = type(error).__name__
            args.report.with_suffix('.cleanup-diagnostic.txt').write_text(str(error))
            raise
        finally:
            probe.save()


if __name__ == '__main__':
    main()
