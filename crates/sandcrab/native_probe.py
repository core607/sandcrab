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


def http(path, method, route, data=None):
    body = json.dumps(data).encode() if data is not None else b''
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(15)
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
max_runs = 2
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
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            try:
                status, info = http(self.socket, 'GET', '/v1/info')
                if status == 200:
                    self.info = info
                    return
            except (OSError, ValueError, HTTPException):
                pass
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
        assert self.info['capabilities'] == ['runs']
        status, schema = http(self.socket, 'GET', '/v1/openapi')
        assert status == 200 and schema['openapi'] == '3.1.0'
        assert schema['paths']['/v1/runs']['post']['operationId'] == 'createRun'
        cli = call('runuser', '-u', 'daemon', '--', str(self.binary), 'run', '--socket', str(self.socket), '--profile', 'python',
                   '--', 'python3', '-c', 'print(6*7)')
        assert json.loads(cli.stdout)['result']['stdout'] == '42\n'
        self.done('independent-cli')
        self.cli_completed_outcome()

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
            assert Path(mount).parent == self.socket.parent / 'jobs'
            uuid.UUID(Path(mount).name)
            call('umount', mount)
        assert not any(line.split()[4].startswith(str(self.root) + '/') for line in Path('/proc/self/mountinfo').read_text().splitlines())
        assert self.secret.read_text() == 'host-sentinel-is-not-mounted\n'
        call('systemctl', 'stop', self.slice, check=False)
        call('systemctl', 'reset-failed', self.unit, self.slice, check=False)
        self.slice_file.unlink(missing_ok=True)
        call('systemctl', 'daemon-reload')
        assert self.root.parent == Path('/var/lib') and self.root.name.startswith('sandcrab-native-') and not self.root.is_symlink()
        shutil.rmtree(self.root)
        self.receipt['cleanup'] = 'PASS'

    def startup_cancellation(self):
        call('systemctl', 'stop', self.unit)
        helpers = self.root / 'delayed-launch'
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
        request = self.submit('import time; time.sleep(20)')
        deadline = time.monotonic() + 5
        while not entered.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        assert entered.exists(), 'launcher did not enter the registration gate'
        started = time.monotonic()
        assert http(self.socket, 'POST', f'/v1/runs/{request["id"]}/cancel', {})[0] == 200
        while (not attempts.exists() or not attempts.read_text().strip()) and time.monotonic() < deadline:
            time.sleep(.01)
        assert attempts.exists() and attempts.read_text().strip(), 'cancellation did not attempt to kill the pending unit'
        unit = self.name + '-' + request['id'] + '.service'
        assert call('systemctl', 'show', unit, '-p', 'LoadState', '--value').stdout.strip() == 'not-found'
        initial = int(attempts.read_text().splitlines()[0])
        assert initial != 0, 'first kill unexpectedly found a registered unit'
        release.touch()
        result = self.wait(request)
        elapsed = time.monotonic() - started
        self.receipt['startupCancellation'] = {
            'initialKillExitCode': initial, 'killAttempts': len(attempts.read_text().splitlines()),
            'seconds': round(elapsed, 3), 'state': result['state'], 'limitSeconds': 3,
        }
        self.save()
        self.forget(request)
        assert result['state'] == 'cancelled', result
        assert elapsed < 3, f'pending cancellation waited {elapsed:.3f}s for the runtime deadline'
        self.done('cancellation-before-unit-registration')
        call('systemctl', 'stop', self.unit)
        del self.launch_path
        self.start()

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
    args = parser.parse_args()
    assert os.geteuid() == 0, 'native probe requires root'
    assert not args.report.exists(), 'preserve the previous receipt; use a fresh output file'
    probe = Probe(args.binary.resolve(), args.tools.resolve(), args.report.resolve())
    try:
        probe.setup()
        probe.tests()
        probe.startup_cancellation()
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
