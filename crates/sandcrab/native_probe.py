#!/usr/bin/env python3
"""Bounded native Sandcrab acceptance. Owns only its temporary slice, unit and directory."""
import argparse
import hashlib
from http.client import HTTPException, HTTPResponse
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid

CLIENT = (0, 0)


def call(*args, check=True, timeout=30):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=timeout)


def connect(stream, path):
    # Connect with the ordinary client's actual filesystem permissions and peer identity.
    # Restore the controller before invoking any test code or privileged cleanup.
    uid, gid, groups = os.geteuid(), os.getegid(), os.getgroups()
    try:
        os.setgroups([CLIENT[1]])
        os.setegid(CLIENT[1])
        os.seteuid(CLIENT[0])
        stream.connect(str(path))
    finally:
        os.seteuid(uid)
        os.setegid(gid)
        os.setgroups(groups)


def http(path, method, route, data=None):
    body = json.dumps(data).encode() if data is not None else b''
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(15)
        connect(stream, path)
        stream.sendall((f'{method} {route} HTTP/1.1\r\nHost: sandcrab\r\n'
                        f'Content-Length: {len(body)}\r\n\r\n').encode() + body)
        response = HTTPResponse(stream)
        response.begin()
        raw = response.read(8 * 1024 * 1024 + 1)
        assert len(raw) <= 8 * 1024 * 1024
        return response.status, json.loads(raw)


class Probe:
    def __init__(self, binary, tools, report):
        global CLIENT
        client = pwd.getpwnam('daemon')
        CLIENT = (client.pw_uid, client.pw_gid)
        self.report = report
        self.root = Path(tempfile.mkdtemp(prefix='sandcrab-native-', dir='/var/lib'))
        self.root.chmod(0o755)
        self.binary = self.root / 'sandcrab'
        shutil.copyfile(binary, self.binary)
        self.binary.chmod(0o755)
        self.name = 'sandcrab-probe-' + uuid.uuid4().hex[:10]
        self.unit = self.name + '.service'
        self.slice = self.name + '.slice'
        self.slice_file = Path('/run/systemd/system') / self.slice
        self.socket = self.root / 'runtime' / 'control.sock'
        self.config = self.root / 'config.toml'
        self.secret = self.root / 'host-sentinel'
        self.secret.write_text('host-sentinel-is-not-mounted\n')
        self.secret.chmod(0o644)
        user = pwd.getpwnam('nobody')
        self.uid = user.pw_uid
        self.config.write_text(f'''[service]
runtime_root = {json.dumps(str(self.socket.parent))}
socket = {json.dumps(str(self.socket))}
client_uid = {client.pw_uid}
client_gid = {client.pw_gid}
resource_slice = "{self.slice}"
supervisor_unit = "{self.unit}"
unit_prefix = "{self.name}-"
max_sandboxes = 2
max_records = 8
max_output_bytes = 1048576
[profiles.python]
exec_user = "nobody"
tools = {json.dumps(str(tools))}
read_only = ["/usr", "/bin", "/lib", "/lib64", "/etc/ld.so.cache"]
memory_bytes = 67108864
temporary_bytes = 8388608
temporary_inodes = 1024
tasks_max = 64
cpu_quota_percent = 50
timeout_millis = 10000
session_ttl_millis = 60000
output_limit_bytes = 4096
network = "none"
''')
        self.config.chmod(0o600)
        self.receipt = {'scope': 'Standalone binary, real systemd/bubblewrap/cgroup isolation; no model or Poketto application',
                        'binarySha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                        'probeSha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                        'checks': [], 'cleanup': 'NOT_RUN'}

    def start(self):
        call('systemd-run', '--quiet', '--collect', '--unit', self.unit, '--slice', self.slice,
             '-p', 'MemoryMax=128M', '-p', 'MemorySwapMax=0', '-p', 'TasksMax=128',
             '-p', 'Environment=PATH=' + getattr(self, 'launch_path', '/usr/bin:/bin'),
             '-p', 'KillMode=control-group', str(self.binary), 'serve', '--config', str(self.config))
        self.wait_ready()

    def wait_ready(self):
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            try:
                status, info = http(self.socket, 'GET', '/v1/info')
                if status == 200:
                    self.info = info
                    return
            except (OSError, ValueError, HTTPException):
                pass
            if call('systemctl', 'show', self.unit, '-p', 'ActiveState', '--value', check=False).stdout.strip() in ('failed', 'inactive'):
                raise AssertionError('native service stopped before becoming ready')
            time.sleep(.1)
        raise AssertionError('native service did not become ready')

    def setup(self):
        self.slice_file.write_text('[Unit]\nDescription=Disposable Sandcrab acceptance\n[Slice]\n'
                                   'MemoryMax=384M\nMemorySwapMax=0\nTasksMax=256\nCPUQuota=50%\n')
        call('systemctl', 'daemon-reload')
        call('systemctl', 'start', self.slice)
        self.start()

    def submit(self, code, **extra):
        request = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId'], 'profile': 'python',
                   'command': ['python3', '-c', code], **extra}
        status, response = http(self.socket, 'POST', '/v1/runs', request)
        assert status == 202, response
        return request

    def wait(self, request):
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            status, response = http(self.socket, 'GET', '/v1/runs/' + request['id'])
            assert status == 200, response
            if response['state'] != 'running':
                assert response['state'] != 'closing', response
                return response
            time.sleep(.05)
        raise AssertionError('run did not reach a terminal state')

    def forget(self, request):
        assert http(self.socket, 'POST', '/v1/runs/' + request['id'] + '/forget', {}) == (200, {'forgotten': True})

    def done(self, label):
        self.receipt['checks'].append({'name': label, 'result': 'PASS'})
        self.save()
        print(label + ': PASS', flush=True)

    def save(self):
        self.report.parent.mkdir(parents=True, exist_ok=True)
        self.report.write_text(json.dumps(self.receipt, indent=2) + '\n')

    def tests(self):
        assert self.info['capabilities'] == ['runs', 'sessions', 'files', 'events', 'calls']
        self.transport()
        self.inventory_tests()
        status, schema = http(self.socket, 'GET', '/v1/openapi')
        assert status == 200 and schema['openapi'] == '3.1.0'
        assert schema['paths']['/v1/runs']['post']['operationId'] == 'createRun'
        cli = call('runuser', '-u', 'daemon', '--', str(self.binary), 'run', '--socket', str(self.socket), '--profile', 'python',
                   '--', 'python3', '-c', 'print(6*7)')
        assert json.loads(cli.stdout)['result']['stdout'] == '42\n'
        self.done('independent-cli')
        self.cli_completed_outcome()
        self.cli_lost_response()

        request = self.submit('import os; print(os.geteuid()); print(os.getcwd()); print(any(k.startswith("POKETTO") for k in os.environ))')
        result = self.wait(request)
        assert result['result']['stdout'] == f'{self.uid}\n/workspace\nFalse\n', result
        assert http(self.socket, 'POST', '/v1/runs', request) == (200, result)
        changed = {**request, 'command': ['true']}
        assert http(self.socket, 'POST', '/v1/runs', changed)[1]['error']['code'] == 'ID_CONFLICT'
        self.forget(request)
        self.done('profile-identity-workspace-and-replay')

        for change, expected in [({'profile': 'missing'}, 'PROFILE_NOT_FOUND'),
                                 ({'timeoutMillis': 10001}, 'PROFILE_LIMIT'),
                                 ({'uid': 0}, 'INVALID_REQUEST'),
                                 ({'mounts': ['/']}, 'INVALID_REQUEST')]:
            rejected = {**request, 'id': str(uuid.uuid4()), **change}
            assert http(self.socket, 'POST', '/v1/runs', rejected)[1]['error']['code'] == expected
        alias = self.root / 'runtime-alias'
        alias.symlink_to(self.socket.parent)
        bad = self.root / 'unsafe-profile.toml'
        bad.write_text(self.config.read_text().replace('"/usr"', json.dumps(str(alias))))
        bad.chmod(0o600)
        checked = call(str(self.binary), 'check', '--config', str(bad), check=False)
        assert checked.returncode != 0 and 'resolves into runtime storage' in checked.stderr
        self.done('request-authority-and-profile-bounds')

        # The execution account can read this sentinel outside the sandbox; denial therefore
        # exercises mount isolation rather than merely ordinary Unix file permissions.
        assert call('runuser', '-u', 'nobody', '--', 'cat', str(self.secret)).stdout == self.secret.read_text()
        request = self.submit(f'from pathlib import Path; assert not Path({str(self.secret)!r}).exists(); print("hidden")')
        assert self.wait(request)['result']['stdout'] == 'hidden\n'
        self.forget(request)
        with socket.socket() as peer:
            peer.bind(('127.0.0.1', 0))
            peer.listen()
            port = peer.getsockname()[1]
            request = self.submit(f'import socket\ntry:\n socket.create_connection(("127.0.0.1",{port}),.2)\nexcept OSError:\n print("isolated")\nelse:\n raise Exception("host network reached")')
            assert self.wait(request)['result']['stdout'] == 'isolated\n'
            self.forget(request)
        request = self.submit('import socket\ntry:\n socket.socket(socket.AF_UNIX)\nexcept PermissionError:\n print("seccomp")\nelse:\n raise Exception("unix socket permitted")')
        assert self.wait(request)['result']['stdout'] == 'seccomp\n'
        self.forget(request)
        self.done('host-network-and-unix-socket-denial')

        request = self.submit('raise SystemExit(7)')
        response = self.wait(request)
        assert response['state'] == 'failed' and response['result']['exitCode'] == 7, response
        self.forget(request)
        request = self.submit('import time; time.sleep(20)', timeoutMillis=200)
        assert self.wait(request)['state'] == 'timed_out'
        self.forget(request)
        request = self.submit('print("x"*10000)', outputLimitBytes=64)
        response = self.wait(request)
        assert response['state'] == 'output_limit' and response['result']['truncated'], response
        assert len(response['result']['stdout']) + len(response['result']['stderr']) <= 64
        self.forget(request)
        self.done('exit-timeout-and-output-bounds')

        request = self.submit('import errno\ntry:\n open("large","wb").write(b"x"*(16*1024*1024))\nexcept OSError as e:\n assert e.errno==errno.ENOSPC; print("quota")\nelse:\n raise Exception("workspace quota absent")')
        assert self.wait(request)['result']['stdout'] == 'quota\n'
        self.forget(request)
        request = self.submit('import subprocess; subprocess.Popen(["sleep","30"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); print("child")')
        assert self.wait(request)['state'] == 'succeeded'
        group = call('systemctl', 'show', self.slice, '-p', 'ControlGroup', '--value').stdout.strip()
        unit_group = Path('/sys/fs/cgroup') / group.lstrip('/') / (self.name + '-' + request['id'] + '.service')
        assert not any(path.read_text().strip() for path in unit_group.rglob('cgroup.procs'))
        assert not list((self.socket.parent / 'jobs').iterdir())
        self.forget(request)
        self.done('workspace-quota-and-descendant-cleanup')

        one = self.submit('import time; time.sleep(8)')
        two = self.submit('import time; time.sleep(8)')
        assert http(self.socket, 'POST', '/v1/runs/' + one['id'] + '/cancel', {'uid': 0})[1]['error']['code'] == 'INVALID_REQUEST'
        overflow = {**one, 'id': str(uuid.uuid4())}
        assert http(self.socket, 'POST', '/v1/runs', overflow)[1]['error']['code'] == 'RUN_CAPACITY'
        assert http(self.socket, 'POST', '/v1/runs/' + one['id'] + '/forget', {})[1]['error']['code'] == 'RUN_ACTIVE'
        for request in [one, two]:
            assert http(self.socket, 'POST', '/v1/runs/' + request['id'] + '/cancel', {})[0] == 200
            assert self.wait(request)['state'] == 'cancelled'
            self.forget(request)
        self.done('admission-and-cancellation')

        retained = []
        for _ in range(8):
            request = self.submit('print(1)')
            assert self.wait(request)['state'] == 'succeeded'
            retained.append(request)
        overflow = {**retained[0], 'id': str(uuid.uuid4())}
        assert http(self.socket, 'POST', '/v1/runs', overflow)[1]['error']['code'] == 'RESULT_CAPACITY'
        for request in retained:
            self.forget(request)
        self.done('bounded-results-and-release')

        # Deliberately grant transport access only on this disposable socket to exercise the
        # peer check even when filesystem permissions alone would not stop the caller.
        self.socket.chmod(0o666)
        try:
            code = f'import socket; s=socket.socket(socket.AF_UNIX); s.connect({str(self.socket)!r}); print(s.recv(1024).decode())'
            refused = call('runuser', '-u', 'nobody', '--', 'python3', '-c', code)
            assert '403' in refused.stdout and 'PEER_REJECTED' in refused.stdout
        finally:
            self.socket.chmod(0o660)
        self.done('peer-refusal-before-request')

        stale = self.submit('import time; time.sleep(8)')
        previous = self.info['serverId']
        call('systemctl', 'kill', '--kill-whom=main', '--signal=KILL', self.unit)
        call('systemctl', 'stop', self.unit, check=False)
        call('systemctl', 'reset-failed', self.unit, check=False)
        self.start()
        assert self.info['serverId'] != previous
        assert http(self.socket, 'POST', '/v1/runs', stale)[1]['error']['code'] == 'SERVER_CHANGED'
        assert http(self.socket, 'GET', '/v1/runs/' + stale['id'])[0] == 404
        request = self.submit('print("restarted")')
        assert self.wait(request)['result']['stdout'] == 'restarted\n'
        self.forget(request)
        self.done('abrupt-loss-cleanup-and-stale-epoch')

    def session_wait(self, identity, terminal=False):
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            status, result = http(self.socket, 'GET', '/v1/sessions/' + identity['id'])
            assert status == 200, result
            if result['state'] in ('closed', 'expired', 'failed', 'closing') or (not terminal and result['state'] == 'ready'):
                return result
            time.sleep(.025)
        raise AssertionError('session did not reach expected state')

    def session_open(self, wait=True, **extra):
        identity = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId'], 'profile': 'python', **extra}
        status, result = http(self.socket, 'POST', '/v1/sessions', identity)
        assert status == 202, result
        if wait:
            assert self.session_wait(identity)['state'] == 'ready'
        return identity

    def session_exec(self, session, command, wait=True, **extra):
        request = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId'], 'command': command, **extra}
        status, result = http(self.socket, 'POST', '/v1/sessions/' + session['id'] + '/commands', request)
        assert status == 202, result
        return request, self.wait(request) if wait else result

    def session_forget(self, session):
        assert http(self.socket, 'POST', '/v1/sessions/' + session['id'] + '/forget', {}) == (200, {'forgotten': True})

    def session_close(self, session):
        assert http(self.socket, 'POST', '/v1/sessions/' + session['id'] + '/close', {})[0] == 200
        result = self.session_wait(session, terminal=True)
        assert result['state'] == 'closed', result
        assert not (self.socket.parent / 'jobs' / session['id']).exists()
        group = call('systemctl', 'show', self.slice, '-p', 'ControlGroup', '--value').stdout.strip()
        pool = Path('/sys/fs/cgroup') / group.lstrip('/')
        for unit in pool.rglob(self.name + '-' + session['id'] + '.service'):
            assert not any(p.read_text().strip() for p in unit.rglob('cgroup.procs'))
        return result

    def inventory_tests(self):
        session = self.session_open()
        records = [self.session_exec(session, 'printf private-output')[0] for _ in range(2)]
        active, _ = self.session_exec(session, 'sleep 30', wait=False)
        records.append(active)
        ids = sorted(record['id'] for record in records)
        status, runs = http(self.socket, 'GET', '/v1/runs')
        assert status == 200 and runs == {'serverId': self.info['serverId'], 'ids': ids, 'nextAfter': None}, runs
        prefix = ['runuser', '-u', 'daemon', '--', str(self.binary)]
        assert json.loads(call(*prefix, 'list', '--socket', str(self.socket)).stdout) == runs
        status, sessions = http(self.socket, 'GET', '/v1/sessions')
        assert status == 200 and sessions['ids'] == [session['id']], sessions
        assert json.loads(call(*prefix, 'session', 'list', '--socket', str(self.socket)).stdout) == sessions
        for kind in ('runs', 'sessions'):
            for query in ('after=bad', 'after=', 'limit=2', 'after=' + session['id'] + '&after=' + session['id']):
                assert http(self.socket, 'GET', '/v1/' + kind + '?' + query) == (400, {'error': {'code': 'INVALID_REQUEST'}})
        self.session_close(session)
        assert self.wait(active)['state'] == 'cancelled'
        assert http(self.socket, 'GET', '/v1/sessions')[1] == sessions, 'closing must not erase retained identity'
        cursor = ids[1]
        self.forget({'id': cursor})
        tail = {'serverId': self.info['serverId'], 'ids': ids[2:], 'nextAfter': None}
        assert http(self.socket, 'GET', '/v1/runs?after=' + cursor) == (200, tail)
        assert json.loads(call(*prefix, 'list', '--socket', str(self.socket), '--after', cursor).stdout) == tail
        for record in records:
            if record['id'] != cursor:
                self.forget(record)
        self.session_forget(session)
        for kind in ('runs', 'sessions'):
            assert http(self.socket, 'GET', '/v1/' + kind) == (200, {'serverId': self.info['serverId'], 'ids': [], 'nextAfter': None})
        self.done('native-inventories-retain-active-and-terminal-identities-without-output')

    def session_tests(self):
        session = self.session_open()
        route = '/v1/sessions/' + session['id']
        assert http(self.socket, 'POST', '/v1/sessions', session)[0] == 200
        assert http(self.socket, 'POST', '/v1/sessions', {**session, 'ttlMillis': 5000})[1]['error']['code'] == 'ID_CONFLICT'
        assert http(self.socket, 'POST', route + '/forget', {})[1]['error']['code'] == 'SESSION_ACTIVE'
        assert http(self.socket, 'POST', route + '/renew', {'ttlMillis': 60001})[1]['error']['code'] == 'PROFILE_LIMIT'
        for change, expected in [({'timeoutMillis': 10001}, 'PROFILE_LIMIT'),
                                 ({'outputLimitBytes': 4097}, 'PROFILE_LIMIT'),
                                 ({'outputLimitBytes': 0}, 'PROFILE_LIMIT'),
                                 ({'profile': 'python'}, 'INVALID_REQUEST')]:
            invalid = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId'], 'command': 'true', **change}
            assert http(self.socket, 'POST', route + '/commands', invalid)[1]['error']['code'] == expected
        for field in ['uid', 'mounts', 'accountId', 'workspaceId']:
            assert http(self.socket, 'POST', '/v1/sessions', {**session, 'id': str(uuid.uuid4()), field: 0})[1]['error']['code'] == 'INVALID_REQUEST'
        # Disable timestamp-based bytecode caching for same-second, same-length repairs.
        request, result = self.session_exec(session, "mkdir project; cd project; export CHECK=retained; "
                                             "printf 'def add(a,b): return a-b\n' > calc.py; "
                                             "printf 'import unittest\nfrom calc import add\nclass Check(unittest.TestCase):\n def test_add(self): self.assertEqual(5, add(2,3))\n' > test_calc.py; "
                                             "python3 -B -m unittest")
        assert result['state'] == 'failed' and 'FAILED' in result['result']['stderr'], result
        self.forget(request)
        request, result = self.session_exec(session, "test \"$CHECK\" = retained; sed -i 's/a-b/a+b/' calc.py; python3 -B -m unittest")
        assert result['state'] == 'succeeded' and 'OK' in result['result']['stderr'], result
        self.forget(request)
        assert (self.socket.parent / 'jobs' / session['id'] / 'work/project/calc.py').read_text() == 'def add(a,b): return a+b\n'
        request, result = self.session_exec(session, f'test ! -e {self.secret}; printf "$CHECK"')
        assert result['state'] == 'succeeded' and result['result']['stdout'] == 'retained', result
        self.forget(request)
        request, result = self.session_exec(session, 'sleep 30 & printf background')
        self.forget(request)
        self.session_close(session)
        self.session_forget(session)
        self.done('session-build-repair-state-isolation-and-descendant-cleanup')

        # CLI operations reconnect each time; no connection is an identity or lifetime owner.
        prefix = ['runuser', '-u', 'daemon', '--', str(self.binary), 'session']
        opened = call(*prefix, 'open', '--socket', str(self.socket), '--profile', 'python')
        cli_session = json.loads(opened.stdout)
        assert 'sessionId=' + cli_session['id'] in opened.stderr
        for source, expected in [('export VALUE=42', ''), ('printf "$VALUE"', '42')]:
            result = call(*prefix, 'exec', '--socket', str(self.socket), cli_session['id'], '--', source)
            assert json.loads(result.stdout)['result']['stdout'] == expected
        assert json.loads(call(*prefix, 'renew', '--socket', str(self.socket), cli_session['id'], '--ttl-ms', '5000').stdout)['state'] == 'ready'
        assert json.loads(call(*prefix, 'close', '--socket', str(self.socket), cli_session['id']).stdout)['state'] == 'closed'
        call(*prefix, 'forget', '--socket', str(self.socket), cli_session['id'])
        self.done('session-cli-reconnects-and-explicit-lifecycle')

        one, two = self.session_open(), self.session_open()
        rejected = {**one, 'id': str(uuid.uuid4())}
        assert http(self.socket, 'POST', '/v1/sessions', rejected)[1]['error']['code'] == 'SESSION_CAPACITY'
        finite = {**rejected, 'command': ['true']}
        assert http(self.socket, 'POST', '/v1/runs', finite)[1]['error']['code'] == 'RUN_CAPACITY'
        request = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId'],
                   'command': 'printf x >> replay-count; sleep 1; cat replay-count'}
        command_route = '/v1/sessions/' + one['id'] + '/commands'
        body = json.dumps(request).encode()
        with socket.socket(socket.AF_UNIX) as lost:
            connect(lost, self.socket)
            lost.sendall((f'POST {command_route} HTTP/1.1\r\nHost: sandcrab\r\n'
                          f'Content-Length: {len(body)}\r\n\r\n').encode() + body)
            lost.shutdown(socket.SHUT_WR)
            # Discard the response; reconnect with the original ID rather than resubmitting work.

        assert http(self.socket, 'POST', command_route, request)[0] in (200, 202)
        assert http(self.socket, 'POST', command_route, {**request, 'id': str(uuid.uuid4())})[1]['error']['code'] == 'SESSION_NOT_READY'
        assert http(self.socket, 'POST', command_route, {**request, 'command': 'false'})[1]['error']['code'] == 'ID_CONFLICT'
        assert http(self.socket, 'POST', '/v1/sessions/' + two['id'] + '/commands', request)[1]['error']['code'] == 'ID_CONFLICT'
        result = self.wait(request)
        assert result['result']['stdout'] == 'x'
        assert (self.socket.parent / 'jobs' / one['id'] / 'work/replay-count').read_bytes() == b'x'
        self.session_close(one)
        self.session_forget(one)
        assert http(self.socket, 'POST', command_route, request) == (200, result)
        self.forget(request)
        self.session_close(two)
        self.session_forget(two)
        self.done('session-shared-admission-exclusive-command-and-replay')

        session = self.session_open()
        records = [self.session_exec(session, 'true')[0] for _ in range(7)]
        overflow = {**records[0], 'id': str(uuid.uuid4())}
        assert http(self.socket, 'POST', '/v1/sessions/' + session['id'] + '/commands', overflow)[1]['error']['code'] == 'RESULT_CAPACITY'
        for record in records:
            self.forget(record)
        self.session_close(session)
        self.session_forget(session)
        self.done('session-results-share-the-global-retention-bound')

        session = self.session_open()
        unit_group = call('systemctl', 'show', self.name + '-' + session['id'] + '.service',
                          '-p', 'ControlGroup', '--value').stdout.strip()
        assert unit_group.startswith('/') and unit_group.endswith('/' + self.name + '-' + session['id'] + '.service')
        group = Path('/sys/fs/cgroup') / unit_group.lstrip('/')
        assert (group / 'memory.oom.group').read_text().strip() == '1'
        for source in ['(exit 137)', "python3 -c 'import os, signal; os.kill(os.getpid(), signal.SIGKILL)'"]:
            request, result = self.session_exec(session, source)
            assert result['state'] == 'failed' and result['result']['exitCode'] == 137, result
            assert http(self.socket, 'GET', '/v1/sessions/' + session['id'])[1]['state'] == 'ready'
            self.forget(request)
        self.session_close(session)
        self.session_forget(session)
        self.done('session-sigkill-and-exit-137-are-not-memory-evidence')

        for source, options, expected in [
            ('sleep 30 & sleep 30', {'timeoutMillis': 200}, 'timed_out'),
            ("python3 -c 'print(\"x\"*10000)'", {'outputLimitBytes': 63}, 'output_limit'),
            ('exit 0', {}, 'succeeded'),
            # Repeated child OOMs cover the shell-result/systemd-event race. A shell
            # that catches the child's exit must not turn an OOM into success either.
            *[("python3 -c 'x=bytearray(128*1024*1024)'" + suffix, {}, 'resource_limit')
              for _ in range(4) for suffix in ['', '; true']],
        ]:
            session = self.session_open()
            request, result = self.session_exec(session, source, **options)
            assert result['state'] == expected, result
            if expected == 'output_limit':
                assert result['result']['truncated'] and len(result['result']['stdout'].encode()) <= 63
            assert self.session_wait(session, terminal=True)['state'] == ('closed' if expected == 'succeeded' else 'failed')
            call(*prefix, 'close', '--socket', str(self.socket), session['id'])
            assert not (self.socket.parent / 'jobs' / session['id']).exists()
            assert http(self.socket, 'POST', '/v1/sessions/' + session['id'] + '/commands', {**request, 'id': str(uuid.uuid4())})[1]['error']['code'] == 'SESSION_NOT_READY'
            self.forget(request)
            self.session_forget(session)
        self.done('session-timeout-output-memory-and-shell-exit-end-the-session')

        session = self.session_open(ttlMillis=3000)
        assert http(self.socket, 'POST', '/v1/sessions/' + session['id'] + '/renew', {'ttlMillis': 6000})[0] == 200
        request, result = self.session_exec(session, 'sleep 4; printf renewed')
        assert result['result']['stdout'] == 'renewed', result
        self.forget(request)
        assert http(self.socket, 'POST', '/v1/sessions/' + session['id'] + '/renew', {'ttlMillis': 300})[0] == 200
        request, _ = self.session_exec(session, 'sleep 30 & sleep 30', wait=False)
        assert self.wait(request)['state'] == 'cancelled'
        assert self.session_wait(session, terminal=True)['state'] == 'expired'
        call(*prefix, 'close', '--socket', str(self.socket), session['id'])
        assert http(self.socket, 'POST', '/v1/sessions/' + session['id'] + '/renew', {'ttlMillis': 6000})[1]['error']['code'] == 'SESSION_ENDED'
        self.forget(request)
        self.session_forget(session)
        self.done('session-renewal-and-expiry-cancel-an-active-command')

        session = self.session_open()
        request, _ = self.session_exec(session, 'sleep 30 & sleep 30', wait=False)
        assert http(self.socket, 'POST', '/v1/runs/' + request['id'] + '/cancel', {})[0] == 200
        assert self.wait(request)['state'] == 'cancelled'
        self.session_close(session)
        self.forget(request)
        self.session_forget(session)
        self.done('session-command-cancellation-closes-the-whole-session')

        session = self.session_open()
        self.session_exec(session, 'sleep 30 & printf retained')
        call('systemctl', 'kill', '--kill-whom=main', '--signal=KILL', self.unit)
        call('systemctl', 'stop', self.unit, check=False)
        call('systemctl', 'reset-failed', self.unit, check=False)
        self.start()
        assert http(self.socket, 'POST', '/v1/sessions', session)[1]['error']['code'] == 'SERVER_CHANGED'
        assert http(self.socket, 'GET', '/v1/sessions/' + session['id'])[0] == 404
        assert not list((self.socket.parent / 'jobs').iterdir())
        session = self.session_open()
        self.session_close(session)
        self.session_forget(session)
        self.done('session-supervisor-loss-cleans-units-and-invalidates-the-epoch')

    def session_cleanup_failure(self):
        call('systemctl', 'stop', self.unit)
        helpers = self.root / 'failed-session-cleanup'
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
        session = self.session_open()
        failure.write_text(session['id'])
        assert http(self.socket, 'POST', '/v1/sessions/' + session['id'] + '/close', {})[0] == 200
        assert self.session_wait(session, terminal=True)['state'] == 'closing'
        assert http(self.socket, 'POST', '/v1/sessions/' + session['id'] + '/forget', {})[1]['error']['code'] == 'SESSION_ACTIVE'
        other = self.session_open()
        assert http(self.socket, 'POST', '/v1/sessions', {**other, 'id': str(uuid.uuid4())})[1]['error']['code'] == 'SESSION_CAPACITY'
        self.session_close(other)
        self.session_forget(other)
        failure.unlink()
        call('systemctl', 'stop', self.unit, check=False)
        call('systemctl', 'reset-failed', self.unit, check=False)
        del self.launch_path
        self.start()
        assert not list((self.socket.parent / 'jobs').iterdir())
        first, second = self.session_open(), self.session_open()
        for current in [first, second]:
            self.session_close(current)
            self.session_forget(current)
        self.done('session-unconfirmed-cleanup-holds-capacity-until-restart')

    def example(self, source):
        staged = self.root / 'build-test.sh'
        shutil.copyfile(source, staged)
        staged.chmod(0o644)
        result = call('runuser', '-u', 'daemon', '--', 'env', '-i', 'PATH=/usr/bin:/bin',
                      'SANDCRAB_BIN=' + str(self.binary), 'SANDCRAB_SOCKET=' + str(self.socket),
                      'bash', str(staged))
        assert '"state":"succeeded"' in result.stdout, result.stdout
        assert not list((self.socket.parent / 'jobs').iterdir())
        self.receipt['exampleSha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
        self.done('independent-build-test-example')

    def cleanup(self):
        call('systemctl', 'stop', self.unit, check=False)
        units = call('systemctl', 'list-units', '--all', '--plain', '--no-legend', self.name + '-*.service').stdout
        for line in units.splitlines():
            unit = line.split()[0]
            call('systemctl', 'stop', unit)
            call('systemctl', 'reset-failed', unit, check=False)
        # Verify the slice is empty before unmounting or deleting any fixture path.
        group = call('systemctl', 'show', self.slice, '-p', 'ControlGroup', '--value').stdout.strip()
        if group:
            for path in (Path('/sys/fs/cgroup') / group.lstrip('/')).rglob('cgroup.procs'):
                assert not path.read_text().strip(), 'fixture process survived cleanup'
        mounts = [line.split()[4] for line in Path('/proc/self/mountinfo').read_text().splitlines()
                  if line.split()[4].startswith(str(self.root) + '/')]
        for mount in sorted(mounts, key=len, reverse=True):
            self.unmount_fixture(Path(mount))
        assert not any(line.split()[4].startswith(str(self.root) + '/') for line in Path('/proc/self/mountinfo').read_text().splitlines())
        assert self.secret.read_text() == 'host-sentinel-is-not-mounted\n'
        call('systemctl', 'stop', self.slice, check=False)
        call('systemctl', 'reset-failed', self.unit, self.slice, check=False)
        self.slice_file.unlink(missing_ok=True)
        call('systemctl', 'daemon-reload')
        assert self.root.parent == Path('/var/lib') and self.root.name.startswith('sandcrab-native-') and not self.root.is_symlink()
        shutil.rmtree(self.root)
        self.receipt['cleanup'] = 'PASS'

    def unmount_fixture(self, mount):
        assert mount.parent == self.socket.parent / 'jobs'
        uuid.UUID(mount.name)
        call('umount', str(mount))

    def startup_cancellation(self, session=False):
        call('systemctl', 'stop', self.unit)
        helpers = self.root / ('delayed-session-launch' if session else 'delayed-launch')
        helpers.mkdir(mode=0o755)
        entered, release, attempts = [helpers / name for name in ['entered', 'release', 'kill-attempts']]
        # Delay registration, not the sandbox command. The first kill reaches the real
        # systemd manager while the unit does not exist; the controller then permits launch.
        (helpers / 'systemd-run').write_text(f'''#!/usr/bin/python3
import os, sys, time
from pathlib import Path
Path({str(entered)!r}).touch()
deadline = time.monotonic() + 8
while not Path({str(release)!r}).exists():
    if time.monotonic() > deadline:
        raise SystemExit(91)
    time.sleep(.01)
os.execv('/usr/bin/systemd-run', ['systemd-run', *sys.argv[1:]])
''')
        (helpers / 'systemctl').write_text(f'''#!/usr/bin/python3
import subprocess, sys
result = subprocess.run(['/usr/bin/systemctl', *sys.argv[1:]])
if sys.argv[1:2] == ['kill']:
    with open({str(attempts)!r}, 'a') as log:
        log.write(str(result.returncode) + '\\n')
raise SystemExit(result.returncode)
''')
        for helper in [helpers / 'systemd-run', helpers / 'systemctl']:
            helper.chmod(0o755)
        self.launch_path = str(helpers) + ':/usr/bin:/bin'
        self.start()
        request = self.session_open(wait=False) if session else self.submit('import time; time.sleep(20)')
        deadline = time.monotonic() + 5
        while not entered.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        assert entered.exists(), 'launcher did not enter the registration gate'
        started = time.monotonic()
        cancel_path = f'/v1/sessions/{request["id"]}/close' if session else f'/v1/runs/{request["id"]}/cancel'
        assert http(self.socket, 'POST', cancel_path, {})[0] == 200
        while (not attempts.exists() or not attempts.read_text().strip()) and time.monotonic() < deadline:
            time.sleep(.01)
        assert attempts.exists() and attempts.read_text().strip(), 'cancellation did not attempt to kill the pending unit'
        unit = self.name + '-' + request['id'] + '.service'
        assert call('systemctl', 'show', unit, '-p', 'LoadState', '--value').stdout.strip() == 'not-found'
        initial = int(attempts.read_text().splitlines()[0])
        assert initial != 0, 'first kill unexpectedly found a registered unit'
        release.touch()
        result = self.session_wait(request, terminal=True) if session else self.wait(request)
        elapsed = time.monotonic() - started
        self.receipt['sessionStartupCancellation' if session else 'startupCancellation'] = {
            'initialKillExitCode': initial, 'killAttempts': len(attempts.read_text().splitlines()),
            'seconds': round(elapsed, 3), 'state': result['state'], 'limitSeconds': 3,
        }
        self.save()
        self.session_forget(request) if session else self.forget(request)
        assert result['state'] == ('closed' if session else 'cancelled'), result
        assert elapsed < 3, f'pending cancellation waited {elapsed:.3f}s for the runtime deadline'
        self.done('session-close-before-unit-registration' if session else 'cancellation-before-unit-registration')
        call('systemctl', 'stop', self.unit)
        del self.launch_path
        self.start()

    def transport(self):
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(10)
            connect(stream, self.socket)
            for index in range(128):
                route = '/v1/missing' if index == 1 else '/v1/info'
                stream.sendall(f'GET {route} HTTP/1.1\r\nHost: sandcrab\r\n\r\n'.encode())
                response = HTTPResponse(stream)
                response.begin()
                value = json.loads(response.read())
                assert response.status == (404 if index == 1 else 200), value
                assert response.getheader('Connection') == ('close' if index == 127 else 'keep-alive')
                response.close()
            assert stream.recv(1) == b''
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(10)
            connect(stream, self.socket)
            body = b'{}' + b' ' * (65536 - 2)
            stream.sendall(b'POST /v1/missing HTTP/1.1\r\nContent-Length: 65536\r\n\r\n' + body)
            response = HTTPResponse(stream)
            response.begin()
            assert response.status == 404, response.read()
            response.read()
            response.close()
            stream.sendall(b'GET /v1/info HTTP/1.1\r\nConnection: CLOSE\r\n\r\n')
            response = HTTPResponse(stream)
            response.begin()
            assert json.loads(response.read())['serverId'] == self.info['serverId']
            assert response.getheader('Connection') == 'close'
            response.close()
            assert stream.recv(1) == b''
        self.done('http-sequential-reuse-body-boundary-and-declared-close')

        for request in [b'POST /v1/runs HTTP/1.1\r\nContent-Length: 65537\r\n\r\n',
                        b'POST /v1/runs HTTP/1.1\r\nContent-Length: 2\r\ncontent-length: 2\r\n\r\n{}',
                        b'POST /v1/runs HTTP/1.1\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}',
                        b'POST /v1/runs HTTP/1.1\r\nContent-Length: 3\r\n\r\n{}',
                        b'GET /v1/info HTTP/1.1\r\n\r\nGET /v1/info HTTP/1.1\r\n\r\n']:
            with socket.socket(socket.AF_UNIX) as stream:
                stream.settimeout(10)
                connect(stream, self.socket)
                stream.sendall(request)
                stream.shutdown(socket.SHUT_WR)
                response = HTTPResponse(stream)
                response.begin()
                assert response.status == 400 and json.loads(response.read())['error']['code'] == 'INVALID_HTTP'
                assert response.getheader('Connection') == 'close'
                response.close()
                assert stream.recv(1) == b''
        self.done('http-invalid-framing-closes-without-dispatch')

        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(10)
            connect(stream, self.socket)
            started = time.monotonic()
            finished = threading.Event()

            def slow_sender():
                try:
                    while not finished.wait(.25):
                        stream.sendall(b'G')
                except OSError:
                    pass

            sender = threading.Thread(target=slow_sender)
            sender.start()
            try:
                response = HTTPResponse(stream)
                response.begin()
                assert response.status == 400 and json.loads(response.read())['error']['code'] == 'INVALID_HTTP'
                elapsed = time.monotonic() - started
                assert 4.5 <= elapsed < 7, elapsed
                self.receipt['slowRequestDeadlineSeconds'] = round(elapsed, 3)
            finally:
                finished.set()
                sender.join(timeout=2)
            assert not sender.is_alive()
        self.done('http-deadline-does-not-reset-on-progress')
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(10)
            connect(stream, self.socket)
            started = time.monotonic()
            assert stream.recv(1) == b'', 'Idle expiry must not queue an unsolicited error response'
            elapsed = time.monotonic() - started
            assert 4.5 <= elapsed < 7, elapsed
            self.receipt['idleDisconnectSeconds'] = round(elapsed, 3)
        self.done('http-idle-expiry-closes-without-an-unsolicited-response')

    def cli_lost_response(self):
        endpoint = self.root / 'cli-lost.sock'
        errors, requests = [], []
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(endpoint))
            os.chown(endpoint, 0, CLIENT[1])
            endpoint.chmod(0o660)
            listener.listen()
            listener.settimeout(15)

            def serve():
                try:
                    stream, _ = listener.accept()
                    with stream, stream.makefile('rb') as reader:
                        stream.settimeout(10)
                        for index in range(2):
                            method, path, _ = reader.readline(65537).decode().split()
                            headers = {}
                            while True:
                                line = reader.readline(65537)
                                if line == b'\r\n':
                                    break
                                key, value = line.decode().split(':', 1)
                                headers[key.lower()] = value.strip()
                            size = int(headers['content-length'])
                            assert 0 <= size <= 65536
                            body = json.loads(reader.read(size)) if size else None
                            requests.append((method, path, body))
                            if index == 0:
                                assert (method, path) == ('GET', '/v1/info')
                                raw = json.dumps(self.info).encode()
                                stream.sendall(f'HTTP/1.1 200 OK\r\nContent-Length: {len(raw)}\r\nConnection: keep-alive\r\n\r\n'.encode() + raw)
                            else:
                                assert (method, path) == ('POST', '/v1/runs')
                                stream.sendall(b'HTTP/1.1 202 Accepted\r\nContent-Length: 100\r\nConnection: keep-alive\r\n\r\n{"id":')
                    listener.settimeout(1)
                    try:
                        replay, _ = listener.accept()
                    except TimeoutError:
                        return
                    replay.close()
                    raise AssertionError('CLI reconnected after an incomplete response')
                except BaseException as error:
                    errors.append(error)

            server = threading.Thread(target=serve)
            server.start()
            try:
                result = call('runuser', '-u', 'daemon', '--', str(self.binary), 'run', '--socket', str(endpoint),
                              '--profile', 'python', '--', 'true', check=False)
            finally:
                server.join(timeout=20)
            assert not server.is_alive() and not errors, errors
            assert len(requests) == 2 and result.returncode != 0, (requests, result)
            assert f'runId={requests[1][2]["id"]}' in result.stderr, result
            assert 'inspect the existing ID before retrying' in result.stderr, result
            assert result.stdout == '', result
        endpoint.unlink()
        self.done('cli-reuses-connection-and-does-not-replay-incomplete-response')

    def cli_completed_outcome(self):
        # A protected root peer injects a post-result transport failure. This checks CLI
        # reporting only; independent-cli above exercises actual sandbox execution.
        for terminal in ['succeeded', 'failed']:
            endpoint = self.root / 'cli-fault.sock'
            errors, requests = [], []
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(endpoint))
                os.chown(endpoint, 0, CLIENT[1])
                endpoint.chmod(0o660)
                listener.listen()
                listener.settimeout(15)

                def serve():
                    try:
                        run_id = None
                        for index in range(4):
                            stream, _ = listener.accept()
                            with stream:
                                stream.settimeout(15)
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
                                if index == 0:
                                    assert (method, path) == ('GET', '/v1/info')
                                    status, value = 200, self.info
                                elif index == 1:
                                    assert (method, path) == ('POST', '/v1/runs')
                                    run_id = body['id']
                                    status, value = 202, {'id': run_id, 'state': 'running'}
                                elif index == 2:
                                    assert (method, path) == ('GET', '/v1/runs/' + run_id)
                                    status, value = 200, {'id': run_id, 'state': terminal,
                                                          'result': {'exitCode': 0 if terminal == 'succeeded' else 7}}
                                else:
                                    assert (method, path) == ('POST', '/v1/runs/' + run_id + '/forget')
                                    status, value = 503, {'error': {'code': 'STOPPING'}}
                                raw = json.dumps(value).encode()
                                stream.sendall(f'HTTP/1.1 {status} Fixture\r\nContent-Length: {len(raw)}\r\nConnection: close\r\n\r\n'.encode() + raw)
                    except BaseException as error:
                        errors.append(error)

                server = threading.Thread(target=serve)
                server.start()
                try:
                    result = call('runuser', '-u', 'daemon', '--', str(self.binary), 'run', '--socket', str(endpoint),
                                  '--profile', 'python', '--', 'true', check=False)
                finally:
                    server.join(timeout=20)
                assert not server.is_alive(), 'CLI fixture peer did not finish'
                assert not errors, errors
                assert len(requests) == 4, requests
                assert json.loads(result.stdout)['state'] == terminal, result
                assert result.returncode == (0 if terminal == 'succeeded' else 1), result
                assert 'forgetting its record failed' in result.stderr and 'do not rerun' in result.stderr, result
            endpoint.unlink()
        self.done('cli-outcome-survives-forget-failure')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--example', type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0, 'native probe requires root'
    assert not args.report.exists(), 'preserve the previous receipt; use a fresh output file'
    probe = Probe(args.binary.resolve(), args.tools.resolve(), args.report.resolve())
    try:
        probe.setup()
        probe.tests()
        probe.session_tests()
        if args.example:
            probe.example(args.example)
        probe.session_cleanup_failure()
        probe.startup_cancellation()
        probe.startup_cancellation(session=True)
        probe.receipt['result'] = 'PASS'
    except BaseException as error:
        probe.receipt['result'] = 'FAIL'
        probe.receipt['failureType'] = type(error).__name__
        # Operator paths and command diagnostics are private, separate from the portable receipt.
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
