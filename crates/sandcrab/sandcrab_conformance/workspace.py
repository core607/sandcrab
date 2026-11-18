"""Exercise durable caller keys through independent native client connections."""
import hashlib
import io
import json
from pathlib import Path
import socket
import tarfile
import time
import uuid

from .file import FileProbe, archive, binary_http
from .host_calls import Calls
from .native import Probe, call, connect, http
from .streaming_file import header


class WorkspaceProbe(Probe):
    restart = FileProbe.restart

    def __init__(self, binary, tools, report):
        super().__init__(binary, tools, report)
        storage = self.root / 'workspace-storage'
        storage.mkdir(mode=0o755)
        (storage / 'data').mkdir(mode=0o711)
        config = self.config.read_text().replace('max_records = 8', 'max_records = 48')
        config = config.replace('session_ttl_millis = 60000', 'session_ttl_millis = 1000')
        config = config.replace('network = "none"', 'network = "none"\nhost_calls = true')
        self.config.write_text(config + f'''
[storage]
root = {json.dumps(str(storage))}
pool_bytes = 67108864
max_volume_bytes = 8388608
max_volume_inodes = 256
max_volumes = 4
max_records = 12
''')
        self.receipt['scope'] = 'Ordinary storage, native workspace lifecycle and command replay.'
        self.receipt['probeSha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    def until(self, read):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            value = read()
            if value:
                return value
            time.sleep(.03)
        raise TimeoutError('workspace transition')

    def ensure(self, route, **options):
        status, value = http(self.socket, 'POST', route, {'profile': 'python', **options})
        assert status in (200, 202), (status, value)
        self.until(lambda: http(self.socket, 'GET', route)[1]['state'] == 'ready')
        return value

    def command(self, route, generation, source, **options):
        status, workspace = http(self.socket, 'GET', route)
        assert status == 200, workspace
        request = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId'],
                   'generation': generation, 'submissionWindow': workspace['submissionWindow'], 'command': source, **options}
        status, run = http(self.socket, 'POST', route + '/commands', request)
        assert status == 202, (status, run)
        return request, run

    def tests(self):
        assert 'workspaces' in self.info['capabilities']
        route = '/v1/workspaces/editor-1'
        first = self.ensure(route)
        generation = first['generation']
        assert generation == self.ensure(route)['generation']
        assert http(self.socket, 'POST', route, {'profile': 'different'})[0] == 409
        assert self.ensure('/v1/workspaces/editor-2')['id'] != first['id']
        request, accepted = self.command(route, generation, 'printf a >> saved; export VALUE=42; sleep 1.2')
        _, second = self.command(route, generation, 'printf b >> saved; printf %s "$VALUE"')
        assert self.wait(request)['freshShell'] is True
        reused = self.wait(second)
        assert reused['state'] == 'succeeded' and reused['result']['stdout'] == '42' and not reused['freshShell'], reused
        self.measure_idle_reopen(route, generation, second['sessionId'])
        files = route + '/files'
        headers = {'X-Sandcrab-Workspace-Generation': generation}
        assert binary_http(self.socket, 'PUT', files + '?path=note', b'first\nsecond\n', headers)[0] == 200
        status, response, selected = binary_http(self.socket, 'GET', files + '?path=note&offset=2&limit=1',
                                                 b'', {**headers, 'X-Sandcrab-Read-Version': 'sha256'})
        assert status == 200 and selected == b'second' and 'X-Sandcrab-File-Sha256' in response
        edit = {'path': 'note', 'expectedSha256': response['X-Sandcrab-File-Sha256'], 'old': 'second', 'new': 'changed'}
        assert binary_http(self.socket, 'POST', files + '/edit', json.dumps(edit).encode(), headers)[0] == 200
        assert binary_http(self.socket, 'GET', files + '?path=note', b'', headers)[2] == b'first\nchanged\n'
        assert binary_http(self.socket, 'PUT', files + '?path=cross.txt', b'x' * 32766 + b'needle', headers)[0] == 200
        status, _, found = binary_http(self.socket, 'GET', files + '/search?pattern=*.txt&contains=needle', b'', headers)
        assert status == 200 and [v['path'] for v in json.loads(found)['entries']] == ['cross.txt']
        status, schema = http(self.socket, 'GET', '/v1/openapi?capability=workspace-files')
        assert status == 200 and '/v1/workspaces/{key}/files/edit' in schema['paths']
        wrong = {'X-Sandcrab-Workspace-Generation': str(uuid.uuid4())}
        assert binary_http(self.socket, 'PUT', files + '?path=note', b'stale', wrong)[0] == 409
        self.done('file-operations-reopen-by-key-and-fence-stale-generations')
        status, seen = http(self.socket, 'POST', route + '/commands', request)
        assert status == 200 and seen['id'] == accepted['id'] and seen['state'] == 'succeeded', seen
        assert http(self.socket, 'POST', route + '/commands', {**request, 'command': 'false'})[0] == 409
        assert http(self.socket, 'POST', '/v1/runs/' + request['id'] + '/forget', {})[0] == 200
        status, retired = http(self.socket, 'POST', route + '/commands', request)
        assert status == 409 and retired['error']['code'] == 'WORKSPACE_SUBMISSION_EXPIRED', retired
        _, reopened = self.command(route, generation, 'cat saved; printf %s "${VALUE:-reset}"')
        outcome = self.wait(reopened)
        assert outcome['freshShell'] and outcome['result']['stdout'] == 'abreset', outcome
        self.done('same-key-ordered-commands-survive-idle-close-and-replay-without-duplicate-writes')

        self.restart()
        assert self.ensure(route)['generation'] == generation
        status, stale = http(self.socket, 'POST', route + '/commands', request)
        assert status == 409 and stale['error']['code'] == 'SERVER_CHANGED', stale
        _, after = self.command(route, generation, 'cat saved')
        result = self.wait(after)
        assert result['freshShell'] and result['result']['stdout'] == 'ab', result
        self.done('daemon-restart-preserves-files-and-rejects-submissions-from-the-previous-epoch')

        raw = self.session_open()
        volume = '/v1/volumes/' + first['id']
        assert http(self.socket, 'POST', volume + '/delete', {})[1]['error']['code'] == 'WORKSPACE_MANAGED'
        expected = {'generation': generation}
        self.until(lambda: http(self.socket, 'POST', route + '/delete', expected)[0] in (200, 202))
        self.until(lambda: http(self.socket, 'GET', route)[1]['state'] == 'deleted')
        assert http(self.socket, 'POST', route + '/forget', expected)[0] == 200
        self.until(lambda: http(self.socket, 'GET', '/v1/sessions/' + after['sessionId'])[0] == 404)
        assert http(self.socket, 'GET', '/v1/runs/' + after['id'])[0] == 200
        assert http(self.socket, 'GET', '/v1/sessions/' + raw['id'])[0] == 200
        self.session_close(raw)
        self.session_forget(raw)
        self.done('forgetting-a-workspace-releases-owned-shell-receipts-and-preserves-independent-records')
        new = self.ensure(route)
        assert new['generation'] != generation
        status, old = http(self.socket, 'POST', route + '/commands', {**request, 'serverId': self.info['serverId']})
        assert status == 409 and old['error']['code'] == 'WORKSPACE_CHANGED', old
        assert http(self.socket, 'POST', route + '/delete', expected)[0] == 409
        self.done('delayed-mutations-cannot-alter-a-new-generation-of-the-same-key')
        self.template_workspace()

    def measure_idle_reopen(self, route, generation, parent):
        samples = []
        for index in range(3):
            assert self.session_wait({'id': parent}, terminal=True)['state'] == 'expired'
            assert not (self.workloads_group / ('session-' + parent)).exists()
            sample = {'idleSessionCgroupPresent': False}
            for kind in (('workspace', 'session') if index % 2 == 0 else ('session', 'workspace')):
                start = time.monotonic_ns()
                if kind == 'session':
                    raw = self.session_open()
                    request, result = self.session_exec(raw, 'printf 42')
                else:
                    request, submitted = self.command(route, generation, 'printf 42')
                    parent = submitted['sessionId']
                    result = self.wait(submitted)
                    assert result['freshShell']
                sample[kind + 'ToFirstCommandMillis'] = (time.monotonic_ns() - start) / 1e6
                assert result['state'] == 'succeeded' and result['result']['stdout'] == '42'
                self.forget(request)
                if kind == 'session':
                    self.session_close(raw)
                    self.session_forget(raw)
            samples.append(sample)
        self.session_wait({'id': parent}, terminal=True)
        self.receipt['idleReopen'] = {'samples': samples, 'idleWindowMillis': 1000,
                                      'timing': 'Unix client to completed printf 42, including workspace lookup or raw session open and readiness.'}
        self.done('idle-workspace-releases-its-workload-cgroup-and-reopens-by-key')

    def template_workspace(self):
        tree = archive([('base', tarfile.REGTYPE, b'base', 0o644),
                        ('removed', tarfile.REGTYPE, b'old', 0o644)])
        status, _, metadata = binary_http(self.socket, 'POST', '/v1/templates?profile=python', tree)
        assert status == 200, metadata
        template_id = json.loads(metadata)['id']
        route = '/v1/workspaces/scoped-copy'
        workspace = self.ensure(route, templateId=template_id)
        generation = workspace['generation']
        headers = {'X-Sandcrab-Workspace-Generation': generation}
        assert workspace['templateId'] == template_id
        assert http(self.socket, 'POST', route, {'profile':'python'})[0] == 409
        template = '/v1/templates/' + template_id
        assert http(self.socket, 'DELETE', template)[0] == 409
        _, original = self.command(route, generation, 'test "$(cat base)" = base && export PARENT_ONLY=one')
        assert self.wait(original)['state'] == 'succeeded'
        body, first = self.command(route, generation,
            'test -z "${PARENT_ONLY:-}" && mkdir sub && cd sub && export CHILD_ONLY=two && printf edited > ../base && rm ../removed',
            freshChild=True)
        assert self.wait(first)['state'] == 'succeeded'
        _, next_child = self.command(route, generation,
            'printf "%s:%s:%s" "$PWD" "${CHILD_ONLY:-clean}" "$(cat base)"', freshChild=True)
        result = self.wait(next_child)
        assert result['freshShell'] and result['result']['stdout'] == '/workspace:clean:edited', result
        assert http(self.socket, 'POST', route + '/commands', body)[1]['id'] == first['id']
        assert http(self.socket, 'POST', route + '/commands', {**body, 'freshChild': False})[0] == 409
        setup, initialized = self.command(route, generation, 'printf "%s:%s" "$PWD" "$INIT_VALUE"',
            freshChild=True, shellInit='cd sub && export INIT_VALUE=ok')
        initialized = self.wait(initialized)
        assert initialized['state'] == 'succeeded' and initialized['result']['stdout'] == '/workspace/sub:ok', initialized
        assert http(self.socket, 'POST', route + '/commands', {**setup, 'shellInit': ':'})[0] == 409
        _, invalid = self.command(route, generation, 'touch should-not-exist', freshChild=True, shellInit='exit 0')
        failure = self.wait(invalid)
        assert failure['state'] == 'failed' and failure['result']['code'] == 'SHELL_INIT_FAILED', failure
        _, confirmed = self.command(route, generation, 'test ! -e should-not-exist', freshChild=True)
        assert self.wait(confirmed)['state'] == 'succeeded'
        _, calling = self.command(route, generation, "printf request | sandcrab call -", freshChild=True)
        calls = '/v1/runs/' + calling['id'] + '/calls'
        with Calls(self.socket, calling) as events:
            pending = events.until('call')
            assert pending['base64'] == 'cmVxdWVzdA==', pending
            reply = calls + '/' + pending['id'] + '/reply'
            assert http(self.socket, 'POST', reply, {'base64':'YW5zd2Vy'})[0] == 200
        called = self.wait(calling)
        assert called['state'] == 'succeeded' and called['result']['stdout'] == 'answer', called
        assert binary_http(self.socket, 'PUT', route + '/files?path=other', b'from client', headers)[0] == 200

        def checkpoint():
            status, response, diff = binary_http(self.socket, 'GET', route + '/diff', b'', headers)
            assert status == 200 and response['ETag'].strip('"') == hashlib.sha256(diff).hexdigest(), (status, response, diff[:100])
            with tarfile.open(fileobj=io.BytesIO(diff)) as changes:
                assert changes.extractfile('base').read() == b'edited'
                assert changes.extractfile('other').read() == b'from client'
                assert '.wh.removed' in changes.getnames(), changes.getnames()
            return diff

        before = checkpoint()
        self.session_wait({'id': first['sessionId']}, terminal=True)
        assert http(self.socket, 'DELETE', template)[0] == 409
        assert checkpoint() == before
        upper = self.root / 'workspace-storage/data/volumes' / workspace['id'] / 'upper'
        with socket.socket(socket.AF_UNIX) as partial:
            partial.settimeout(10)
            connect(partial, self.socket)
            partial.sendall((f'PUT {route}/files?path=interrupted HTTP/1.1\r\nHost: sandcrab\r\n'
                             f'X-Sandcrab-Workspace-Generation: {generation}\r\n'
                             'Content-Length: 4096\r\nExpect: 100-continue\r\n\r\n').encode())
            assert header(partial).startswith(b'HTTP/1.1 100 ')
            partial.sendall(b'partial')
            self.until(lambda: list(upper.glob('.transfer-*/owner.json')))
            call('systemctl', 'kill', '--kill-whom=main', '--signal=KILL', self.unit)
        self.restart()
        assert not list(upper.glob('.transfer-*'))
        assert self.ensure(route, templateId=template_id)['generation'] == generation
        assert http(self.socket, 'DELETE', template)[0] == 409
        assert checkpoint() == before
        assert binary_http(self.socket, 'GET', route + '/diff', b'', {'X-Sandcrab-Workspace-Generation': str(uuid.uuid4())})[0] == 409
        assert http(self.socket, 'POST', route + '/delete', {'generation':generation})[0] in (200, 202)
        self.until(lambda: http(self.socket, 'GET', route)[1]['state'] == 'deleted')
        assert http(self.socket, 'DELETE', template)[0] == 200
        self.done('template-and-upper-survive-idle-and-restart-with-fresh-children-and-a-frozen-checkpoint')
