#!/usr/bin/env python3
"""Opaque host-call acceptance through a disposable native service and its guest CLI."""
import argparse
import base64
from contextlib import ExitStack, closing
import hashlib
import hmac
from http.client import HTTPConnection, HTTPResponse
import json
import os
from pathlib import Path
import selectors
import secrets
import shlex
import shutil
import signal
import socket
import subprocess
import time
import uuid
import zlib

from native_probe import Probe, call, connect, http
import native_probe
from events_probe import Events as OutputEvents


class Calls:
    def __init__(self, endpoint, run, after=None, *, connection=None, headers=None):
        self.endpoint, self.run = endpoint, run
        self.socket = connection or socket.socket(socket.AF_UNIX)
        self.socket.settimeout(8)
        if connection is None:
            connect(self.socket, endpoint)
        cursor = f'Last-Event-ID: {after}\r\n' if after else ''
        extra = ''.join(f'{name}: {value}\r\n' for name, value in (headers or {}).items())
        self.socket.sendall(f'GET /v1/runs/{run["id"]}/calls/events HTTP/1.1\r\nHost: sandcrab\r\n{cursor}{extra}\r\n'.encode())
        self.response = HTTPResponse(self.socket)
        self.response.begin()
        assert self.response.status == 200, self.response.read()
        self.cursor = None

    def frame(self):
        fields, total = {}, 0
        while True:
            line = self.response.readline(131073 - total)
            total += len(line)
            assert line and total <= 131072 and line.endswith(b'\n'), 'incomplete or oversized call event'
            line = line.rstrip(b'\r\n')
            if not line:
                if not fields:
                    total = 0
                    continue
                assert set(fields) == {'id', 'event', 'data'}
                incarnation, sequence = fields['id'].split(':')
                uuid.UUID(incarnation)
                assert 0 <= int(sequence) <= 64
                self.cursor = fields['id']
                value = json.loads(fields['data'])
                if fields['event'] == 'state':
                    assert value['runId'] == self.run['id']
                    assert value['serverId'] == self.run['serverId']
                return fields['event'], value
            if line.startswith(b':'):
                continue
            key, value = line.decode().split(':', 1)
            assert key not in fields
            fields[key] = value.removeprefix(' ')

    def until(self, kind):
        while True:
            event, value = self.frame()
            assert event != 'error', value
            if event == kind:
                return value
            assert event != 'result', http(self.endpoint, 'GET', f'/v1/runs/{self.run["id"]}')

    def end(self):
        assert self.response.read(1) == b''

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.response.close()
        self.socket.close()


def program(payload):
    # Generate the fixed binary fixture inside the guest without enlarging command argv.
    return ('import base64,json,subprocess,zlib\n'
            f'payload=zlib.decompress(base64.b64decode({base64.b64encode(zlib.compress(payload)).decode()!r}))\n'
            'r=subprocess.run(["sandcrab","call","-"],input=payload,capture_output=True)\n'
            'print(json.dumps({"code":r.returncode,"out":base64.b64encode(r.stdout).decode(),"err":r.stderr.decode()}))\n')


class HostCallsProbe(Probe):
    def __init__(self, binary, tools, report, example):
        super().__init__(binary, tools, report)
        self.example = self.root / 'host-caller.py'
        shutil.copyfile(example, self.example)
        self.example.chmod(0o644)
        self.config.write_text(self.config.read_text().replace('network = "none"', 'network = "none"\nhost_calls = true')
                               .replace('output_limit_bytes = 4096', 'output_limit_bytes = 131072'))
        self.receipt['scope'] = 'Actual guest CLI, native HTTP/SSE and command lifecycle for opaque host calls; synthetic caller effects, no model or production cutover'
        self.receipt['hostCallsProbeSha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        self.receipt['callerExampleSha256'] = hashlib.sha256(example.read_bytes()).hexdigest()

    def reply(self, run, request, payload):
        return http(self.socket, 'POST', f'/v1/runs/{run["id"]}/calls/{request["id"]}/reply',
                    {'base64': base64.b64encode(payload).decode()})

    def records(self, run):
        status, value = http(self.socket, 'GET', f'/v1/runs/{run["id"]}/calls')
        assert status == 200, value
        assert value['runId'] == run['id'] and value['serverId'] == run['serverId']
        assert str(uuid.UUID(value['incarnation'])) == value['incarnation']
        return value

    def output(self, run, expected):
        result = self.wait(run)
        assert result['state'] == 'succeeded', result
        payload = json.loads(result['result']['stdout'])
        assert payload['code'] == 0 and base64.b64decode(payload['out']) == expected, payload
        assert 'requestId=' in payload['err'] and 'runId=' + run['id'] in payload['err']

    def exchange(self, run, payload, answer):
        with Calls(self.socket, run) as events:
            request = events.until('call')
            assert base64.b64decode(request['base64']) == payload
            assert request['requestSha256'] == hashlib.sha256(payload).hexdigest()
            assert self.reply(run, request, answer)[0] == 200
            result = events.until('result')
            assert result['run']['state'] == 'succeeded', result
            assert result['calls']['closed'] is True
            events.end()
        self.output(run, answer)
        assert self.reply(run, request, answer)[0] == 200
        different = bytes([answer[0] ^ 1]) + answer[1:] if answer else b'different'
        assert self.reply(run, request, different)[1]['error']['code'] == 'CALL_REPLY_CONFLICT'
        records = self.records(run)
        assert records['closed'] and len(records['calls']) == 1
        assert records['calls'][0]['state'] == 'replied' and 'base64' not in records['calls'][0]
        return request

    def finite(self):
        for payload, answer in [(b'opaque\x00\xffrequest', b'\xe4\xb8\xad\x00\xffreply'), (b'', b'')]:
            run = self.submit(program(payload))
            self.exchange(run, payload, answer)
            self.forget(run)
        self.done('finite-guest-call-relays-opaque-bytes-and-idempotent-replies')

    def sessions(self):
        session = self.session_open()
        first, _ = self.session_exec(session, 'export HOST_CALL_STATE=retained; python3 -c ' + shlex.quote(program(b'first')), wait=False)
        request = self.exchange(first, b'first', b'answer one')
        second, _ = self.session_exec(session, 'test "$HOST_CALL_STATE" = retained && python3 -c ' + shlex.quote(program(b'second')), wait=False)
        assert self.reply(second, request, b'wrong command')[1]['error']['code'] == 'CALL_NOT_FOUND'
        self.exchange(second, b'second', b'answer two')
        self.forget(first)
        self.forget(second)
        self.session_close(session)
        self.session_forget(session)
        self.done('session-calls-preserve-shell-state-and-bind-replies-to-the-command')

    def resume_and_lost_reply(self):
        run = self.submit(program(b'reconcile'))
        with Calls(self.socket, run) as events:
            request = events.until('call')
        with Calls(self.socket, run) as events:
            assert events.until('call') == request
            answer = b'published once'
            data = json.dumps({'base64': base64.b64encode(answer).decode()}).encode()
            with socket.socket(socket.AF_UNIX) as stream:
                connect(stream, self.socket)
                stream.sendall((f'POST /v1/runs/{run["id"]}/calls/{request["id"]}/reply HTTP/1.1\r\n'
                                f'Content-Length: {len(data)}\r\nConnection: close\r\n\r\n').encode() + data)
                # Intentionally lose the HTTP acknowledgement after sending the same reply once.
            assert events.until('result')['run']['state'] == 'succeeded'
            events.end()
        self.output(run, answer)
        assert self.reply(run, request, answer)[0] == 200
        with Calls(self.socket, run) as events:
            assert events.frame()[0] == 'state'
            assert events.frame()[0] == 'result', 'published work was offered again'
        self.forget(run)
        self.done('unanswered-call-resumes-by-id-and-lost-reply-acknowledgement-is-reconciled')

    def cancellation(self):
        run = self.submit(program(b'waiting'))
        with Calls(self.socket, run) as events:
            request = events.until('call')
            assert http(self.socket, 'POST', f'/v1/runs/{run["id"]}/cancel', {})[0] == 200
            assert self.reply(run, request, b'late')[1]['error']['code'] == 'CALL_CLOSED'
            assert events.until('result')['run']['state'] == 'cancelled'
        assert self.wait(run)['state'] == 'cancelled'
        records = self.records(run)
        assert records['closed'] and records['calls'][0]['state'] == 'abandoned'
        self.forget(run)
        self.done('cancelled-command-closes-pending-calls-before-accepting-late-replies')

    def bounds(self):
        payload, answer = bytes(range(256)) * 256, b'R' * 65536
        run = self.submit(program(payload))
        self.exchange(run, payload, answer)
        self.forget(run)
        run = self.submit(program(payload + b'x'))
        result = self.wait(run)
        assert result['state'] == 'succeeded', result
        result = json.loads(result['result']['stdout'])
        assert result['code'] != 0 and 'exceeds 65536 bytes' in result['err']
        assert self.records(run)['calls'] == []
        self.forget(run)
        self.done('maximum-binary-request-and-reply-cross-chunks-and-oversize-input-is-not-sent')

    def cli(self):
        run = self.submit(program(b'cli consumer'))
        observer = subprocess.Popen(['runuser', '-u', 'daemon', '--', str(self.binary), 'calls', 'events',
                                     '--socket', str(self.socket), run['id']], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        buffered = bytearray()
        def frame():
            deadline = time.monotonic() + 8
            with selectors.DefaultSelector() as selector:
                selector.register(observer.stdout, selectors.EVENT_READ)
                while b'\n' not in buffered:
                    assert selector.select(max(0, deadline - time.monotonic())), 'CLI observer did not receive a frame'
                    chunk = os.read(observer.stdout.fileno(), 65536)
                    assert chunk, 'CLI observer exited before the request'
                    buffered.extend(chunk)
            row, _, rest = buffered.partition(b'\n')
            buffered[:] = rest
            return json.loads(row)
        try:
            assert frame()['event'] == 'state'
            row = frame()
            assert row['event'] == 'call' and base64.b64decode(row['data']['base64']) == b'cli consumer'
            request = row['data']
            answer = self.root / 'reply.bin'
            answer.write_bytes(b'\x00\xffCLI reply')
            answer.chmod(0o644)
            result = call('runuser', '-u', 'daemon', '--', str(self.binary), 'calls', 'reply', '--socket',
                          str(self.socket), run['id'], request['id'], str(answer))
            assert json.loads(result.stdout)['state'] == 'replied'
            out, err = observer.communicate(timeout=15)
            assert observer.returncode == 0, err
            assert json.loads(bytes(buffered) + out)['event'] == 'result'
            self.output(run, answer.read_bytes())
            resumed = call('runuser', '-u', 'daemon', '--', str(self.binary), 'calls', 'events', '--socket',
                           str(self.socket), run['id'], '--after', row['id'])
            assert [json.loads(line)['event'] for line in resumed.stdout.splitlines()] == ['state', 'result']
            refused = call('runuser', '-u', 'daemon', '--', str(self.binary), 'calls', 'events', '--socket',
                           str(self.socket), run['id'], '--after', str(uuid.uuid4()) + ':0', check=False)
            assert refused.returncode != 0 and 'CALL_CURSOR_MISMATCH' in refused.stderr
            listed = call('runuser', '-u', 'daemon', '--', str(self.binary), 'calls', 'list', '--socket', str(self.socket), run['id'])
            assert json.loads(listed.stdout)['closed'] is True
        finally:
            if observer.poll() is None:
                observer.kill()
                observer.wait(timeout=5)
        self.forget(run)
        self.done('ordinary-client-cli-observes-replies-lists-and-resumes-host-calls')

    def guest_ids_are_not_reply_handles(self):
        request_id = str(uuid.uuid4())
        code = f'''import base64,fcntl,json,os,struct,time
from pathlib import Path
root=Path('/sandcrab-calls')
request={request_id!r}
execution=os.environ['SANDBOX_EXECUTION_ID']
def send(value):
    data=json.dumps(value).encode()
    with (root/'lock').open('rb') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        with (root/'requests').open('wb',buffering=0) as pipe: pipe.write(struct.pack('>I',len(data))+data)
send({{'requestId':request,'executionId':execution,'operation':'call','arguments':{{'base64':'aWRlbnRpdHk='}}}})
reply=root/'responses'/(request+'.json')
while not reply.exists(): time.sleep(.01)
data=json.loads(reply.read_bytes())
send({{'requestId':request,'executionId':execution,'operation':'ack'}})
print(base64.b64decode(data['base64']).decode())
'''
        first = self.submit(code)
        with Calls(self.socket, first) as events:
            old = events.until('call')
            assert old['requestId'] == request_id and old['id'] != request_id
            assert self.reply(first, old, b'first generation')[0] == 200
            assert events.until('result')['run']['state'] == 'succeeded'
        self.forget(first)
        # Deliberately reuse both caller-owned and guest-owned IDs. The daemon's reply handle stays fresh.
        second = self.submit(code, id=first['id'])
        with Calls(self.socket, second) as events:
            current = events.until('call')
            assert current['requestId'] == request_id and current['id'] != old['id']
            assert self.reply(second, old, b'stale reply')[1]['error']['code'] == 'CALL_NOT_FOUND'
            assert http(self.socket, 'GET', f'/v1/runs/{second["id"]}')[1]['state'] == 'running'
            assert self.reply(second, current, b'second generation')[0] == 200
            assert events.until('result')['run']['state'] == 'succeeded'
        result = self.wait(second)
        assert result['result']['stdout'] == 'second generation\n'
        self.forget(second)
        self.done('daemon-reply-handles-isolate-reused-run-and-guest-request-identities')

    def tests(self):
        self.discovery()
        self.permissions()
        self.finite()
        self.sessions()
        self.resume_and_lost_reply()
        self.cancellation()
        self.bounds()
        self.cli()
        self.guest_ids_are_not_reply_handles()
        self.retained_cli()
        self.signing_consumer()
        self.command_limits()
        self.expiry_and_restart()
        self.uncertain_reply()
        self.malformed_requests()
        self.observer_capacity()
        self.tcp()
        self.disabled_default()

    def malformed_requests(self):
        run = self.submit(program(b'reply validation'))
        with Calls(self.socket, run) as events:
            request = events.until('call')
            for body in [{'base64': '!'}, {'base64': '', 'unknown': True},
                         {'base64': base64.b64encode(b'x' * 65537).decode()}]:
                status, value = http(self.socket, 'POST', f'/v1/runs/{run["id"]}/calls/{request["id"]}/reply', body)
                assert status == 400 and value['error']['code'] in ('INVALID_CALL_PAYLOAD', 'CALL_PAYLOAD_LIMIT')
                assert self.records(run)['calls'][0]['state'] == 'pending'
            assert self.reply(run, request, b'valid after refusal')[0] == 200
            assert events.until('result')['run']['state'] == 'succeeded'
        self.output(run, b'valid after refusal')
        self.forget(run)
        for oversized, expected in [(False, 'INVALID_CALL_PAYLOAD'), (True, 'HOST_CALL_CHANNEL_FAILED')]:
            run = self.submit(f'''import fcntl,json,os,struct,time,uuid
from pathlib import Path
root=Path('/sandcrab-calls')
data=json.dumps({{'requestId':str(uuid.uuid4()),'executionId':os.environ['SANDBOX_EXECUTION_ID'],
                 'operation':'call','arguments':{{'base64':'!'}}}}).encode()
packet=struct.pack('>I',524289) if {oversized!r} else struct.pack('>I',len(data))+data
with (root/'lock').open('rb') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX)
    with (root/'requests').open('wb',buffering=0) as pipe: pipe.write(packet)
while True: time.sleep(1)
''')
            result = self.wait(run)
            records = self.records(run)
            assert result['state'] == 'failed' and records['error'] == expected, result
            assert records['closed'] and records['calls'] == []
            self.forget(run)
        self.done('malformed-http-replies-preserve-pending-calls-and-invalid-guest-frames-fail-closed')

    def observer_capacity(self):
        run = self.submit(program(b'observers'))
        with ExitStack() as stack:
            observers = [stack.enter_context(Calls(self.socket, run) if index % 2 else OutputEvents(self.socket, run))
                         for index in range(self.info['limits']['maxEventStreams'])]
            assert http(self.socket, 'GET', '/v1/info')[1]['events']['activeStreams'] == len(observers)
            for suffix in ['events', 'calls/events']:
                status, value = http(self.socket, 'GET', f'/v1/runs/{run["id"]}/{suffix}')
                assert (status, value['error']['code']) == (429, 'EVENT_CAPACITY')
            assert http(self.socket, 'POST', f'/v1/runs/{run["id"]}/cancel', {})[0] == 200
            for observer in observers:
                value = observer.until('result')
                assert (value['run']['state'] if isinstance(observer, Calls) else value['state']) == 'cancelled'
                observer.end()
        self.forget(run)
        self.done('host-call-and-output-observers-share-capacity-and-preserve-cancellation')

    def tcp(self):
        original = self.config.read_text()
        with socket.socket() as free:
            free.bind(('127.0.0.1', 0))
            address = free.getsockname()
        key = secrets.token_hex(32)
        server_key, client_key = self.root / 'server.token', self.root / 'client.token'
        for path in [server_key, client_key]:
            path.write_text(key + '\n')
            path.chmod(0o600)
        os.chown(client_key, *native_probe.CLIENT)
        authority = f'{address[0]}:{address[1]}'
        self.config.write_text(original + f'\n[tcp]\nlisten = "{authority}"\ntoken_file = {json.dumps(str(server_key))}\n')
        call('systemctl', 'restart', self.unit)
        self.wait_ready()
        run = self.submit(program(b'TCP request'))
        with Calls(self.socket, run, connection=socket.create_connection(address, timeout=8),
                   headers={'Authorization': 'Bearer ' + key}) as events:
            request = events.until('call')
            for suffix in ['calls', 'calls/events']:
                with closing(HTTPConnection(*address, timeout=8)) as connection:
                    connection.request('GET', f'/v1/runs/{run["id"]}/{suffix}')
                    response = connection.getresponse()
                    assert response.status == 401 and json.loads(response.read())['error']['code'] == 'AUTH_REQUIRED'
            with socket.create_connection(address, timeout=8) as stream:
                stream.sendall((f'POST /v1/runs/{run["id"]}/calls/{request["id"]}/reply HTTP/1.1\r\n'
                                'Content-Length: 131072\r\n\r\n').encode())
                response = HTTPResponse(stream)
                response.begin()
                assert response.status == 401
            reply_file = self.root / 'tcp-reply.bin'
            reply_file.write_bytes(b'TCP answer')
            reply_file.chmod(0o644)
            cli = ['runuser', '-u', 'daemon', '--', str(self.binary), '--token-file', str(client_key)]
            result = call(*cli, 'calls', 'reply', '--endpoint', 'http://' + authority, run['id'], request['id'], str(reply_file))
            assert json.loads(result.stdout)['state'] == 'replied'
            assert events.until('result')['run']['state'] == 'succeeded'
            events.end()
        self.output(run, b'TCP answer')
        result = call(*cli, 'calls', 'events', '--endpoint', 'http://' + authority, run['id'])
        assert [json.loads(line)['event'] for line in result.stdout.splitlines()] == ['state', 'result']
        assert key not in result.stdout + result.stderr
        self.forget(run)
        self.config.write_text(original)
        call('systemctl', 'restart', self.unit)
        self.wait_ready()
        self.done('authenticated-tcp-host-call-events-and-cli-replies-refuse-unauthenticated-bodies')

    def command_limits(self):
        code = '''import subprocess
for index in range(65):
    result=subprocess.run(['sandcrab','call','-'],input=b'bounded',capture_output=True)
    if result.returncode: raise SystemExit(1)
'''
        run = self.submit(code)
        with Calls(self.socket, run) as events:
            for sequence in range(1, 65):
                request = events.until('call')
                assert request['sequence'] == sequence
                assert self.reply(run, request, b'')[0] == 200
            result = events.until('result')
            assert result['run']['state'] == 'failed' and result['calls']['error'] == 'CALL_CAPACITY', result
        assert len(self.records(run)['calls']) == 64
        self.forget(run)
        run = self.submit('''import subprocess
children=[]
for _ in range(5):
    child=subprocess.Popen(['sandcrab','call','-'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    child.stdin.write(b'pending')
    child.stdin.close()
    children.append(child)
for child in children: child.wait()
''')
        result = self.wait(run)
        records = self.records(run)
        assert result['state'] == 'failed' and records['error'] == 'HOST_CALL_CHANNEL_FAILED', result
        assert len(records['calls']) == 4 and records['closed'] is True
        self.forget(run)
        self.done('per-command-total-and-unacknowledged-call-limits-contain-excess-work')

    def expiry_and_restart(self):
        run = self.submit(program(b'timeout'), timeoutMillis=1500)
        with Calls(self.socket, run) as events:
            request = events.until('call')
            assert events.until('result')['run']['state'] == 'timed_out'
        assert self.reply(run, request, b'late')[1]['error']['code'] == 'CALL_CLOSED'
        self.forget(run)
        session = self.session_open(ttlMillis=1500)
        run, _ = self.session_exec(session, 'python3 -c ' + shlex.quote(program(b'expiry')), wait=False)
        with Calls(self.socket, run) as events:
            request = events.until('call')
            assert events.until('result')['run']['state'] == 'cancelled'
        assert self.session_wait(session, terminal=True)['state'] == 'expired'
        assert self.reply(run, request, b'late')[1]['error']['code'] == 'CALL_CLOSED'
        self.forget(run)
        self.session_forget(session)
        run = self.submit(program(b'restart'))
        with Calls(self.socket, run) as events:
            request = events.until('call')
        epoch = self.info['serverId']
        call('systemctl', 'restart', self.unit)
        self.wait_ready()
        assert self.info['serverId'] != epoch
        assert self.reply(run, request, b'old epoch')[1]['error']['code'] == 'RUN_NOT_FOUND'
        assert not (self.socket.parent / 'jobs' / run['id']).exists()
        fresh = self.submit(program(b'fresh'))
        self.exchange(fresh, b'fresh', b'after restart')
        self.forget(fresh)
        self.done('timeout-session-expiry-and-daemon-restart-refuse-late-replies-and-recover')

    def uncertain_reply(self):
        run = self.submit(program(b'publication fault'))
        with Calls(self.socket, run) as events:
            request = events.until('call')
            pending = self.socket.parent / 'jobs' / run['id'] / 'calls' / 'responses' / (request['requestId'] + '.pending')
            assert pending.resolve().is_relative_to(self.socket.parent / 'jobs') and not pending.exists()
            # An owned fixture directory forces publication failure without weakening permissions.
            pending.mkdir()
            result = self.reply(run, request, b'caller result')
            assert result[0] == 503 and result[1]['error']['code'] == 'CALL_REPLY_UNCERTAIN', result
            assert self.reply(run, request, b'caller result')[1]['error']['code'] == 'CALL_REPLY_UNCERTAIN'
            result = events.until('result')
            assert result['run']['state'] == 'failed' and result['calls']['error'] == 'CALL_REPLY_UNCERTAIN', result
        record = self.records(run)['calls'][0]
        assert record['state'] == 'uncertain' and record['replySha256'] == hashlib.sha256(b'caller result').hexdigest()
        assert self.reply(run, request, b'caller result')[1]['error']['code'] == 'CALL_REPLY_UNCERTAIN'
        self.forget(run)
        self.done('uncertain-reply-publication-cancels-the-command-and-never-republishes-on-retry')

    def disabled_default(self):
        enabled = self.config.read_text()
        self.config.write_text(enabled.replace('\nhost_calls = true', ''))
        call('systemctl', 'restart', self.unit)
        self.wait_ready()
        assert self.info['profiles']['python']['hostCalls'] is False
        run = self.submit('''import os
from pathlib import Path
assert not Path('/sandcrab-calls').exists()
assert not Path('/sandcrab/sandcrab').exists()
assert not os.environ['PATH'].startswith('/sandcrab:')
print('disabled')
''')
        assert self.wait(run)['result']['stdout'] == 'disabled\n'
        assert http(self.socket, 'GET', f'/v1/runs/{run["id"]}/calls')[1]['error']['code'] == 'HOST_CALLS_DISABLED'
        assert http(self.socket, 'GET', f'/v1/runs/{run["id"]}/calls/events')[1]['error']['code'] == 'HOST_CALLS_DISABLED'
        refused = call('runuser', '-u', 'daemon', '--', str(self.binary), 'calls', 'events', '--socket',
                       str(self.socket), run['id'], check=False)
        assert refused.returncode != 0 and 'HOST_CALLS_DISABLED' in refused.stderr
        self.forget(run)
        request = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId'], 'profile': 'python', 'command': ['true'], 'hostCalls': True}
        assert http(self.socket, 'POST', '/v1/runs', request)[1]['error']['code'] == 'INVALID_REQUEST'
        self.config.write_text(enabled)
        call('systemctl', 'restart', self.unit)
        self.wait_ready()
        self.done('host-calls-default-off-without-guest-mounts-and-callers-cannot-enable-them')

    def retained_cli(self):
        session = self.session_open()
        for session_command in [False, True]:
            for streaming in [False, True]:
                command = ['session', 'exec', '--socket', str(self.socket), session['id']] if session_command else [
                    'run', '--socket', str(self.socket), '--profile', 'python']
                command += ['--keep-result'] + (['--stream'] if streaming else [])
                command += ['--', 'printf retained'] if session_command else ['--', 'printf', 'retained']
                result = call('runuser', '-u', 'daemon', '--', str(self.binary), *command)
                identity = next(line.removeprefix('runId=') for line in result.stderr.splitlines() if line.startswith('runId='))
                status, value = http(self.socket, 'GET', '/v1/runs/' + identity)
                assert status == 200 and value['state'] == 'succeeded' and value['result']['stdout'] == 'retained'
                assert result.stdout == 'retained' if streaming else json.loads(result.stdout)['state'] == 'succeeded'
                self.forget({'id': identity})
                failed = ['session', 'exec', '--socket', str(self.socket), session['id']] if session_command else [
                    'run', '--socket', str(self.socket), '--profile', 'python']
                failed += ['--keep-result'] + (['--stream'] if streaming else [])
                failed += ['--', 'printf failed; false'] if session_command else ['--', 'sh', '-c', 'printf failed; exit 9']
                result = call('runuser', '-u', 'daemon', '--', str(self.binary), *failed, check=False)
                assert result.returncode != 0
                identity = next(line.removeprefix('runId=') for line in result.stderr.splitlines() if line.startswith('runId='))
                status, value = http(self.socket, 'GET', '/v1/runs/' + identity)
                assert status == 200 and value['state'] == 'failed' and value['result']['stdout'] == 'failed'
                self.forget({'id': identity})
        self.session_close(session)
        self.session_forget(session)
        self.done('run-and-session-cli-retain-results-for-independent-observers-when-requested')

    def signing_consumer(self):
        key = secrets.token_bytes(32)
        key_file = self.root / 'provider.key'
        key_file.write_bytes(key)
        key_file.chmod(0o600)
        assert native_probe.CLIENT[0] != 0
        os.chown(key_file, *native_probe.CLIENT)
        process = subprocess.Popen(['python3', str(self.example), '--binary', str(self.binary),
                                 '--socket', str(self.socket), '--key-file', str(key_file)],
                                user=native_probe.CLIENT[0], group=native_probe.CLIENT[1],
                                extra_groups=[native_probe.CLIENT[1]], env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'},
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            out, err = process.communicate(timeout=45)
            assert process.returncode == 0, err
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=10)
        receipt = json.loads(out)
        digest = hashlib.sha256(b'independent build output').hexdigest()
        assert receipt['digest'] == digest and receipt['hostCalls'] == 1
        assert receipt['signature'] == hmac.new(key, bytes.fromhex(digest), hashlib.sha256).hexdigest()
        assert http(self.socket, 'GET', '/v1/runs/' + receipt['runId'])[0] == 404
        self.done('independent-unprivileged-build-caller-signs-and-verifies-an-artifact-digest')

    def discovery(self):
        assert self.info['profiles']['python']['hostCalls'] is True
        assert self.info['hostCalls']['payloadBytes'] == 65536
        status, schema = http(self.socket, 'GET', '/v1/openapi?capability=calls')
        assert status == 200 and len(json.dumps(schema, separators=(',', ':')).encode()) < 18000
        assert '/v1/runs/{id}/calls/events' in schema['paths']
        status, schema = http(self.socket, 'GET', '/v1/openapi?capability=runs')
        assert status == 200 and not any('/calls' in path for path in schema['paths'])
        for path in ['/sandcrab', '/sandcrab-calls', '/sandcrab-driver']:
            bad = self.root / 'invalid-mount.toml'
            bad.write_text(self.config.read_text().replace('"/usr"', json.dumps(path)))
            bad.chmod(0o600)
            result = call(str(self.binary), 'check', '--config', str(bad), check=False)
            assert result.returncode != 0 and 'Host-call profiles cannot mount' in result.stderr
        self.done('host-call-capability-is-discoverable-and-reserved-mounts-are-refused')

    def permissions(self):
        run = self.submit('''import errno,os
from pathlib import Path
root=Path('/sandcrab-calls')
operations=[lambda:os.open(root/'state',os.O_WRONLY),
            lambda:os.open(root/'new-file',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),
            lambda:os.open(root/'responses'/'forged.json',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),
            lambda:os.unlink(root/'requests')]
for operation in operations:
    try: operation()
    except OSError as error: assert error.errno in (errno.EACCES,errno.EPERM,errno.EROFS)
    else: raise AssertionError('guest modified a protected host-call path')
print('protected')
''')
        result = self.wait(run)
        assert result['state'] == 'succeeded' and result['result']['stdout'] == 'protected\n', result
        assert self.records(run)['calls'] == []
        self.forget(run)
        self.done('guest-cannot-modify-mailbox-state-requests-or-host-responses')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--example', type=Path, default=Path(__file__).resolve().parents[3] / 'examples/sandcrab-host-calls.py')
    args = parser.parse_args()
    assert os.geteuid() == 0 and not args.report.exists()
    assert args.example.is_file()
    probe = HostCallsProbe(args.binary.resolve(), args.tools.resolve(), args.report.resolve(), args.example.resolve())
    try:
        probe.setup()
        probe.tests()
        probe.receipt['result'] = 'PASS'
    except BaseException as error:
        probe.receipt.update(result='FAIL', failureType=type(error).__name__)
        detail = str(error)
        if isinstance(error, subprocess.CalledProcessError):
            detail += '\n' + (error.stdout or '') + '\n' + (error.stderr or '')
        args.report.with_suffix('.diagnostic.txt').write_text(detail)
        raise
    finally:
        try:
            probe.cleanup()
        finally:
            probe.save()


if __name__ == '__main__':
    main()
