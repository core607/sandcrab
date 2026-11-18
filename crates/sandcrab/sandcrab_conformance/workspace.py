"""Exercise durable caller keys through independent native client connections."""
import hashlib
import json
from pathlib import Path
import time
import uuid

from .file import FileProbe
from .native import Probe, http


class WorkspaceProbe(Probe):
    restart = FileProbe.restart

    def __init__(self, binary, tools, report):
        super().__init__(binary, tools, report)
        storage = self.root / 'workspace-storage'
        storage.mkdir(mode=0o755)
        (storage / 'data').mkdir(mode=0o711)
        config = self.config.read_text().replace('max_records = 8', 'max_records = 48')
        config = config.replace('session_ttl_millis = 60000', 'session_ttl_millis = 1000')
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

    def ensure(self, route):
        status, value = http(self.socket, 'POST', route, {'profile': 'python'})
        assert status in (200, 202), (status, value)
        self.until(lambda: http(self.socket, 'GET', route)[1]['state'] == 'ready')
        return value

    def command(self, route, generation, source):
        status, workspace = http(self.socket, 'GET', route)
        assert status == 200, workspace
        request = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId'],
                   'generation': generation, 'submissionWindow': workspace['submissionWindow'], 'command': source}
        status, run = http(self.socket, 'POST', route + '/commands', request)
        assert status == 202, (status, run)
        return request, run

    def tests(self):
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
        self.session_wait({'id': second['sessionId']}, terminal=True)
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

        volume = '/v1/volumes/' + first['id']
        assert http(self.socket, 'POST', volume + '/delete', {})[1]['error']['code'] == 'WORKSPACE_MANAGED'
        expected = {'generation': generation}
        self.until(lambda: http(self.socket, 'POST', route + '/delete', expected)[0] in (200, 202))
        self.until(lambda: http(self.socket, 'GET', route)[1]['state'] == 'deleted')
        assert http(self.socket, 'POST', route + '/forget', expected)[0] == 200
        new = self.ensure(route)
        assert new['generation'] != generation
        status, old = http(self.socket, 'POST', route + '/commands', {**request, 'serverId': self.info['serverId']})
        assert status == 409 and old['error']['code'] == 'WORKSPACE_CHANGED', old
        assert http(self.socket, 'POST', route + '/delete', expected)[0] == 409
        self.done('delayed-mutations-cannot-alter-a-new-generation-of-the-same-key')
