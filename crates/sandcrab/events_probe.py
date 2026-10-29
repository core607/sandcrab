#!/usr/bin/env python3
"""Native command event acceptance. Every sandbox, observer and fault belongs to this fixture."""
import argparse
import base64
import hashlib
from http.client import HTTPException, HTTPResponse
import json
import os
from pathlib import Path
import selectors
import shlex
import signal
import socket
import subprocess
import threading
import time
import uuid

from file_probe import binary_http
import native_probe
from native_probe import Probe, call, connect, http


class Events:
    def __init__(self, endpoint, run, after=None, *, connection=None, headers=None):
        self.socket = connection or socket.socket(socket.AF_UNIX)
        self.socket.settimeout(8)
        if connection is None:
            connect(self.socket, endpoint)
        cursor = f'Last-Event-ID: {after}\r\n' if after else ''
        extra = ''.join(f'{key}: {value}\r\n' for key, value in (headers or {}).items())
        self.socket.sendall(f'GET /v1/runs/{run["id"]}/events HTTP/1.1\r\nHost: sandcrab\r\n{cursor}{extra}\r\n'.encode())
        self.response = HTTPResponse(self.socket)
        self.response.begin()
        assert self.response.status == 200, self.response.read()
        assert self.response.chunked and self.response.getheader('Content-Type') == 'text/event-stream'
        self.cursor = after
        self.offsets = list(map(int, after.split(':')[1:])) if after else [0, 0]
        self.output = [bytearray(), bytearray()]
        initial = self.next()
        assert initial['event'] == 'state' and initial['data']['id'] == run['id']
        assert initial['data']['serverId'] == run['serverId']

    def next(self):
        fields, size = {}, 0
        while True:
            line = self.response.readline(16385)
            assert line.endswith(b'\n'), 'Event ended without a complete frame'
            size += len(line)
            assert size <= 16384, 'Oversized event'
            line = line.rstrip(b'\r\n')
            if not line:
                if fields:
                    break
                size = 0
                continue
            if line.startswith(b':'):
                continue
            key, value = line.decode().split(':', 1)
            assert key not in fields
            fields[key] = value.removeprefix(' ')
        assert fields.keys() == {'id', 'event', 'data'}
        fields['data'] = json.loads(fields['data'])
        incarnation, *offsets = fields['id'].split(':')
        assert len(offsets) == 2
        if self.cursor:
            assert incarnation == self.cursor.split(':')[0]
        kind, data = fields['event'], fields['data']
        if kind in ('stdout', 'stderr'):
            index = int(kind == 'stderr')
            value = base64.b64decode(data['base64'], validate=True)
            assert 1 <= len(value) <= 4096 and data['offset'] == self.offsets[index]
            self.output[index].extend(value)
            self.offsets[index] += len(value)
        assert list(map(int, offsets)) == self.offsets
        if kind == 'result':
            assert [data['stdoutBytes'], data['stderrBytes']] == self.offsets
            assert data['state'] not in ('running', 'closing')
            assert 'stdout' not in data['result'] and 'stderr' not in data['result']
        self.cursor = fields['id']
        return fields

    def until(self, kind):
        while True:
            event = self.next()
            if event['event'] == kind:
                return event['data']
            assert event['event'] not in ('result', 'error'), event

    def end(self):
        assert self.response.read(1) == b'', 'Bytes followed the terminal event'

    def close(self):
        self.response.close()
        self.socket.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class EventProbe(Probe):
    def __init__(self, binary, tools, report):
        super().__init__(binary, tools, report)
        self.config.write_text(self.config.read_text().replace('output_limit_bytes = 4096', 'output_limit_bytes = 1048576')
                               .replace('timeout_millis = 10000', 'timeout_millis = 30000'))
        self.receipt['scope'] = 'Real native command events, explicit resume, CLI, observer bounds and containment faults; no model calls or production cutover'
        self.receipt['eventProbeSha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    def submit(self, code, **extra):
        return super().submit(code, **{'outputLimitBytes': 4096, **extra})

    def active(self, expected):
        deadline = time.monotonic() + 9
        while time.monotonic() < deadline:
            status, info = http(self.socket, 'GET', '/v1/info')
            assert status == 200
            if info['events']['activeStreams'] == expected:
                return
            time.sleep(.05)
        raise AssertionError(f'Observer count did not become {expected}')

    def cancel(self, run):
        assert http(self.socket, 'POST', f'/v1/runs/{run["id"]}/cancel', {})[0] == 200

    def finite(self):
        run = self.submit('import os,time; os.write(1,b"ready"); time.sleep(60)')
        with Events(self.socket, run) as events:
            assert events.until('stdout')['offset'] == 0
            assert events.output[0] == b'ready'
            assert http(self.socket, 'GET', f'/v1/runs/{run["id"]}')[1]['state'] == 'running'
            # Cancellation is impossible until the observer has received live output.
            self.cancel(run)
            assert events.until('result')['state'] == 'cancelled'
            events.end()
            # Consume the zero chunk before issuing the next request on this connection.
            events.socket.sendall(b'GET /v1/info HTTP/1.1\r\nHost: sandcrab\r\nConnection: close\r\n\r\n')
            response = HTTPResponse(events.socket)
            response.begin()
            assert response.status == 200 and json.loads(response.read())['serverId'] == self.info['serverId']
        assert not (self.socket.parent / 'jobs' / run['id']).exists()
        self.forget(run)
        self.active(0)
        self.done('finite-live-output-cancel-containment-and-connection-reuse')

    def gate(self, session, path='gate'):
        content = b'go'
        request = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId'], 'sessionId': session['id'],
                   'path': path, 'format': 'raw', 'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()}
        assert http(self.socket, 'POST', '/v1/uploads', request)[0] == 201
        assert binary_http(self.socket, 'PUT', f'/v1/uploads/{request["id"]}/content', content)[0] == 200
        assert http(self.socket, 'POST', f'/v1/uploads/{request["id"]}/forget', {})[0] == 200

    def session_resume(self):
        session = self.session_open()
        source = ('import os,time\nfrom pathlib import Path\n'
                  'with open("invocations","ab") as count: count.write(b"x")\n'
                  'os.write(1,b"\\xe4")\nos.write(2,b"err")\n'
                  'while not Path("gate").exists(): time.sleep(.02)\n'
                  'os.write(1,b"\\xb8\\xad\\x00\\xff")\nos.write(2,b"or")')
        run, _ = self.session_exec(session, 'python3 -c ' + shlex.quote(source), wait=False, outputLimitBytes=4096)
        with Events(self.socket, run) as first:
            first.until('stdout')
            cursor = first.cursor
            before = [bytes(value) for value in first.output]
        self.active(0)
        assert http(self.socket, 'GET', f'/v1/runs/{run["id"]}')[1]['state'] == 'running'
        with Events(self.socket, run, cursor) as resumed:
            self.gate(session)
            assert resumed.until('result')['state'] == 'succeeded'
            resumed.end()
            output = [before[i] + resumed.output[i] for i in range(2)]
            assert output == [b'\xe4\xb8\xad\x00\xff', b'error'], output
        assert self.wait(run)['result']['stdout'] == '\u4e2d\x00\ufffd'
        self.forget(run)
        check, result = self.session_exec(session, 'cat invocations', outputLimitBytes=4096)
        assert result['result']['stdout'] == 'x', 'Resuming must not reexecute the command'
        self.forget(check)
        self.session_close(session)
        self.session_forget(session)
        self.done('session-live-output-binary-resume-and-single-execution')

    def cursor_binding(self):
        run = self.submit('print("retained")')
        self.wait(run)
        with Events(self.socket, run) as events:
            cursor = events.cursor
            events.until('result')
            events.end()
        for value, status, code in [('invalid', 400, 'INVALID_EVENT_CURSOR'),
                                     (cursor.split(':')[0] + ':1048576:0', 409, 'EVENT_CURSOR_MISMATCH'),
                                     (str(uuid.uuid4()) + ':0:0', 409, 'EVENT_CURSOR_MISMATCH')]:
            self.refusal(run, value, status, code)
        self.forget(run)
        self.refusal(run, cursor, 404, 'RUN_NOT_FOUND')
        assert http(self.socket, 'POST', '/v1/runs', run)[0] == 202
        self.refusal(run, cursor, 409, 'EVENT_CURSOR_MISMATCH')
        self.wait(run)
        self.forget(run)
        self.done('cursor-rejects-invalid-future-foreign-and-reused-identities')

    def refusal(self, run, cursor, status, code):
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(8)
            connect(stream, self.socket)
            stream.sendall(f'GET /v1/runs/{run["id"]}/events HTTP/1.1\r\nLast-Event-ID: {cursor}\r\n\r\n'.encode())
            response = HTTPResponse(stream)
            response.begin()
            assert response.status == status and json.loads(response.read())['error']['code'] == code

    def observer_bounds(self):
        run = self.submit('import time; time.sleep(60)')
        observers = []
        try:
            for _ in range(self.info['limits']['maxEventStreams']):
                observers.append(Events(self.socket, run))
            self.active(len(observers))
            status, value = http(self.socket, 'GET', f'/v1/runs/{run["id"]}/events')
            assert (status, value['error']['code']) == (429, 'EVENT_CAPACITY')
            self.cancel(run)
            for observer in observers:
                assert observer.until('result')['state'] == 'cancelled'
                observer.end()
        finally:
            for observer in observers:
                observer.close()
        self.active(0)
        self.forget(run)
        # A non-reading observer must lose its slot without killing or blocking the job.
        run = self.submit('import os,time; os.write(1,b"x"*1048576); time.sleep(60)', outputLimitBytes=1048576)
        with socket.socket(socket.AF_UNIX) as slow:
            slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
            slow.settimeout(8)
            connect(slow, self.socket)
            slow.sendall(f'GET /v1/runs/{run["id"]}/events HTTP/1.1\r\n\r\n'.encode())
            self.active(1)
            self.active(0)
        assert http(self.socket, 'GET', f'/v1/runs/{run["id"]}')[1]['state'] == 'running'
        self.cancel(run)
        result = self.wait(run)
        assert result['state'] == 'cancelled' and len(result['result']['stdout']) == 1048576
        self.forget(run)
        self.done('observer-capacity-reserves-control-and-slow-reader-does-not-stop-run')

    def cli(self):
        args = ['runuser', '-u', 'daemon', '--', str(self.binary)]
        process = subprocess.Popen([*args, 'run', '--socket', str(self.socket), '--profile', 'python', '--stream', '--',
                                    'python3', '-c', 'import os,time; os.write(1,b"\\x00\\xffready"); time.sleep(60)'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                assert selector.select(10), 'CLI buffered output until completion'
                assert os.read(process.stdout.fileno(), 7) == b'\x00\xffready'
            os.killpg(process.pid, signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=15)
            assert process.returncode != 0 and stdout == b'' and b'cancelled' in stderr, stderr
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        session = self.session_open()
        result = call(*args, 'session', 'exec', '--socket', str(self.socket), session['id'], '--stream', '--',
                      'printf session-stream; printf diagnostic >&2')
        assert result.stdout == 'session-stream' and 'diagnostic' in result.stderr
        self.session_close(session)
        self.session_forget(session)
        run = self.submit('print("observer")')
        self.wait(run)
        with Events(self.socket, run) as events:
            cursor = events.cursor
        result = call(*args, 'events', '--socket', str(self.socket), run['id'], '--after', cursor)
        frames = [json.loads(line) for line in result.stdout.splitlines()]
        assert frames[0]['event'] == 'state' and frames[-1]['event'] == 'result'
        assert http(self.socket, 'GET', f'/v1/runs/{run["id"]}')[0] == 200
        self.forget(run)
        self.done('cli-live-binary-output-cancellation-session-and-explicit-resume')

    def containment_fault(self):
        call('systemctl', 'stop', self.unit)
        helpers = self.root / 'event-cleanup-fault'
        helpers.mkdir(mode=0o755)
        failure = helpers / 'fail-id'
        (helpers / 'umount').write_text(f'''#!/usr/bin/python3
import os, sys
from pathlib import Path
flag=Path({str(failure)!r})
if flag.exists() and Path(sys.argv[-1]).name == flag.read_text():
    raise SystemExit(79)
os.execv('/usr/bin/umount', ['umount', *sys.argv[1:]])
''')
        (helpers / 'umount').chmod(0o755)
        self.launch_path = str(helpers) + ':/usr/bin:/bin'
        self.start()
        run = self.submit('import time; print("live",flush=True); time.sleep(60)')
        failure.write_text(run['id'])
        with Events(self.socket, run) as events:
            events.until('stdout')
            self.cancel(run)
            assert events.until('error')['code'] == 'CONTAINMENT_UNCONFIRMED'
            events.end()
        assert http(self.socket, 'GET', f'/v1/runs/{run["id"]}')[1]['state'] == 'closing'
        assert http(self.socket, 'POST', f'/v1/runs/{run["id"]}/forget', {})[1]['error']['code'] == 'RUN_ACTIVE'
        other = self.submit('import time; time.sleep(60)')
        rejected = {**other, 'id': str(uuid.uuid4())}
        assert http(self.socket, 'POST', '/v1/runs', rejected)[1]['error']['code'] == 'RUN_CAPACITY'
        self.cancel(other)
        self.wait(other)
        self.forget(other)
        failure.unlink()
        call('systemctl', 'stop', self.unit, check=False)
        call('systemctl', 'reset-failed', self.unit, check=False)
        del self.launch_path
        self.start()
        assert not list((self.socket.parent / 'jobs').iterdir())
        self.done('unconfirmed-containment-emits-error-and-keeps-admission')

    def cli_lost_terminator(self):
        # A protected root peer injects transport faults only. Native execution is
        # exercised separately; these responses must never count as model evidence.
        for terminal, partial in [('succeeded', False), ('failed', False), ('succeeded', True)]:
            endpoint = self.root / 'event-cli-fault.sock'
            errors, requests = [], []
            cursor = str(uuid.uuid4())
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(endpoint))
                os.chown(endpoint, 0, native_probe.CLIENT[1])
                endpoint.chmod(0o660)
                listener.listen()
                listener.settimeout(15)

                def serve():
                    try:
                        run_id = None
                        for index in range(3 if partial else 4):
                            stream, _ = listener.accept()
                            with stream, stream.makefile('rb') as reader:
                                stream.settimeout(10)
                                method, path, _ = reader.readline(65537).decode().split()
                                headers = {}
                                while True:
                                    line = reader.readline(65537)
                                    if line == b'\r\n':
                                        break
                                    key, value = line.decode().split(':', 1)
                                    headers[key.lower()] = value.strip()
                                size = int(headers.get('content-length', '0'))
                                assert 0 <= size <= 65536
                                body = json.loads(reader.read(size)) if size else None
                                requests.append((method, path))
                                if index == 0:
                                    assert (method, path) == ('GET', '/v1/info')
                                    status, value = 200, self.info
                                elif index == 1:
                                    assert (method, path) == ('POST', '/v1/runs')
                                    run_id = body['id']
                                    status, value = 202, {'id': run_id, 'state': 'running'}
                                elif index == 2:
                                    assert (method, path) == ('GET', f'/v1/runs/{run_id}/events')
                                    stream.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n')
                                    state = {'id': run_id, 'serverId': self.info['serverId'], 'state': 'running', 'result': None}
                                    result = {**state, 'state': terminal, 'stdoutBytes': 3, 'stderrBytes': 0,
                                              'result': {'exitCode': 0 if terminal == 'succeeded' else 7, 'truncated': False}}
                                    for kind, offset, value in [('state', 0, state), ('stdout', 3, {'offset': 0, 'base64': 'YWNr'}), ('result', 3, result)]:
                                        frame = f'id: {cursor}:{offset}:0\nevent: {kind}\ndata: {json.dumps(value)}\n\n'.encode()
                                        if partial and kind == 'result':
                                            frame = frame[:-1]
                                        stream.sendall(f'{len(frame):x}\r\n'.encode() + frame + b'\r\n')
                                    # Deliberately omit the HTTP zero chunk in both cases.
                                    continue
                                else:
                                    assert (method, path) == ('POST', f'/v1/runs/{run_id}/forget')
                                    status, value = 503, {'error': {'code': 'STOPPING'}}
                                raw = json.dumps(value).encode()
                                stream.sendall(f'HTTP/1.1 {status} Fixture\r\nContent-Length: {len(raw)}\r\nConnection: close\r\n\r\n'.encode() + raw)
                        listener.settimeout(1)
                        try:
                            extra, _ = listener.accept()
                        except TimeoutError:
                            return
                        extra.close()
                        raise AssertionError('CLI retried after observation ended')
                    except BaseException as error:
                        errors.append(error)

                server = threading.Thread(target=serve)
                server.start()
                try:
                    result = call('runuser', '-u', 'daemon', '--', str(self.binary), 'run', '--socket', str(endpoint),
                                  '--profile', 'python', '--stream', '--', 'true', check=False)
                finally:
                    server.join(timeout=20)
                assert not server.is_alive() and not errors, errors
                assert sum(path == '/v1/runs' for _, path in requests) == 1
                assert result.stdout == 'ack', result
                assert result.returncode == (0 if not partial and terminal == 'succeeded' else 1), result
                if partial:
                    assert f'lastEventId={cursor}:3:0' in result.stderr and 'observation failed' in result.stderr, result
                else:
                    assert 'outcome is final' in result.stderr and 'forgetting its record failed' in result.stderr, result
            endpoint.unlink()
        self.done('cli-complete-result-survives-lost-terminator-partial-result-does-not')

    def daemon_loss(self):
        run = self.submit('import time; print("live",flush=True); time.sleep(60)')
        with Events(self.socket, run) as events:
            events.until('stdout')
            cursor = events.cursor
            call('systemctl', 'kill', '--kill-whom=main', '--signal=KILL', self.unit)
            try:
                event = events.next()
            except (AssertionError, OSError, EOFError, HTTPException):
                pass
            else:
                assert event['event'] == 'error', event
        call('systemctl', 'stop', self.unit, check=False)
        call('systemctl', 'reset-failed', self.unit, check=False)
        self.start()
        assert self.info['serverId'] != run['serverId']
        self.refusal(run, cursor, 404, 'RUN_NOT_FOUND')
        assert http(self.socket, 'POST', '/v1/runs', run)[1]['error']['code'] == 'SERVER_CHANGED'
        assert not list((self.socket.parent / 'jobs').iterdir())
        self.done('daemon-loss-does-not-acknowledge-completion-or-replay-command')

    def cli_repeated_cancel(self):
        # Hold the cancellation response while delivering real signals. This root
        # peer tests client I/O only; finite() separately proves sandbox containment.
        endpoint = self.root / 'signal-peer.sock'
        requests, errors = [], []
        cancelled, release = threading.Event(), threading.Event()
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(endpoint))
            os.chown(endpoint, 0, native_probe.CLIENT[1])
            endpoint.chmod(0o660)
            listener.listen()
            listener.settimeout(8)

            def receive():
                stream, _ = listener.accept()
                stream.settimeout(8)
                with stream.makefile('rb') as reader:
                    method, path, _ = reader.readline(65537).decode().split()
                    headers = {}
                    while True:
                        line = reader.readline(65537)
                        if line == b'\r\n':
                            break
                        key, value = line.decode().split(':', 1)
                        headers[key.lower()] = value.strip()
                    size = int(headers.get('content-length', '0'))
                    assert 0 <= size <= 65536
                    body = json.loads(reader.read(size)) if size else None
                requests.append((method, path))
                return stream, path, body

            def reply(stream, value):
                body = json.dumps(value).encode()
                stream.sendall(f'HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode() + body)

            def serve():
                try:
                    stream, path, _ = receive()
                    with stream:
                        assert path == '/v1/info'
                        reply(stream, self.info)
                    stream, path, body = receive()
                    run_id = body['id']
                    state = {'id': run_id, 'serverId': self.info['serverId'], 'profile': 'python', 'state': 'running', 'result': None}
                    with stream:
                        assert path == '/v1/runs'
                        reply(stream, state)
                    stream, path, _ = receive()
                    with stream:
                        assert path == f'/v1/runs/{run_id}/events'
                        stream.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n')
                        incarnation = str(uuid.uuid4())
                        def frame(kind, offset, value):
                            data = f'id: {incarnation}:{offset}:0\nevent: {kind}\ndata: {json.dumps(value)}\n\n'.encode()
                            stream.sendall(f'{len(data):x}\r\n'.encode() + data + b'\r\n')
                        frame('state', 0, state)
                        frame('stdout', 5, {'offset': 0, 'base64': 'cmVhZHk='})
                        control, path, _ = receive()
                        with control:
                            assert path == f'/v1/runs/{run_id}/cancel'
                            cancelled.set()
                            assert release.wait(8)
                            reply(control, state)
                        frame('result', 5, {**state, 'state': 'cancelled', 'stdoutBytes': 5, 'stderrBytes': 0,
                                           'result': {'exitCode': 137, 'truncated': False}})
                        # A complete result lets the CLI close before the HTTP terminator.
                    stream, path, _ = receive()
                    with stream:
                        assert path == f'/v1/runs/{run_id}/forget'
                        reply(stream, {'forgotten': True})
                except BaseException as error:
                    errors.append(type(error).__name__)

            server = threading.Thread(target=serve)
            server.start()
            process = subprocess.Popen([str(self.binary), 'run', '--socket', str(endpoint), '--profile', 'python', '--stream', '--', 'true'],
                                       user=native_probe.CLIENT[0], group=native_probe.CLIENT[1], extra_groups=[native_probe.CLIENT[1]],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    assert selector.select(8)
                    assert os.read(process.stdout.fileno(), 5) == b'ready'
                process.send_signal(signal.SIGTERM)
                assert cancelled.wait(8)
                time.sleep(.05)
                for _ in range(5):
                    if process.poll() is not None:
                        break
                    process.send_signal(signal.SIGTERM)
                    time.sleep(.02)
                release.set()
                stdout, stderr = process.communicate(timeout=12)
                assert process.returncode == 1 and stdout == b'' and b'runState="cancelled"' in stderr, stderr
                assert b'observation failed' not in stderr, stderr
            finally:
                release.set()
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                server.join(timeout=20)
            assert not server.is_alive() and not errors, errors
            assert len(requests) == 5 and sum(path.endswith('/cancel') for _, path in requests) == 1, requests
        endpoint.unlink()
        self.done('cli-repeated-cancellation-signals-preserve-the-original-response')

    def tests(self):
        self.finite()
        self.session_resume()
        self.cursor_binding()
        self.observer_bounds()
        self.cli()
        self.cli_lost_terminator()
        self.cli_repeated_cancel()
        self.daemon_loss()
        self.containment_fault()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and not args.report.exists()
    probe = EventProbe(args.binary.resolve(), args.tools.resolve(), args.report.resolve())
    try:
        probe.setup()
        probe.tests()
        probe.receipt['result'] = 'PASS'
    except BaseException as error:
        probe.receipt.update(result='FAIL', failureType=type(error).__name__)
        details = str(error)
        if isinstance(error, subprocess.CalledProcessError):
            details += '\n' + (error.stdout or '') + '\n' + (error.stderr or '')
        args.report.with_suffix('.diagnostic.txt').write_text(details)
        raise
    finally:
        try:
            probe.cleanup()
        finally:
            probe.save()


if __name__ == '__main__':
    main()
