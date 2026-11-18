"""Verify kernel byte and inode bounds for each profile-selected workspace layout."""
import errno
import json
import shlex
import tarfile
import time

from .file import FileProbe, archive, binary_http
from .native import call, http
from .volume import VolumeProbe
from .workspace import WorkspaceProbe

WRITE = """
import errno, json, os
with open('bytes', 'xb', buffering=0) as target:
    try:
        block = b'x' * (32 * 1024 * 1024)
        written = target.write(block)
        os.fsync(target.fileno())
        while written < len(block):
            count = target.write(b'x' * min(1024 * 1024, len(block)-written))
            if not count:
                raise RuntimeError('Disk write did not advance')
            written += count
            os.fsync(target.fileno())
    except OSError as error:
        refused = error.errno
    else:
        refused = None
size = os.stat('bytes').st_size
os.unlink('bytes')
print(json.dumps([size, refused]))
"""
INODES = """
import json, os
os.mkdir('many')
count = 0
try:
    for index in range(512):
        with open(f'many/{index}', 'xb'):
            pass
        count += 1
except OSError as error:
    refused = error.errno
else:
    refused = None
for name in os.listdir('many'):
    os.unlink('many/' + name)
os.rmdir('many')
print(json.dumps([count, refused]))
"""


class HardQuotaProbe(VolumeProbe):
    until = WorkspaceProbe.until
    ensure = WorkspaceProbe.ensure
    command = WorkspaceProbe.command
    restart = FileProbe.restart

    def __init__(self, binary, tools, report):
        super().__init__(binary, tools, report)
        text = self.config.read_text().replace('max_records = 8\n', 'max_records = 64\n', 1)
        text = text.replace('[profiles.python]\n', '[profiles.python]\nhard_workspace_quota = true\n', 1)
        self.config.write_text(text.replace('temporary_inodes = 1024', 'temporary_inodes = 128'))
        self.receipt['scope'] = 'Disposable file-backed XFS, kernel project quotas and an ordinary control profile.'
        self.receipt['backings'] = {}

    def template(self, profile):
        data = archive([('seed', tarfile.REGTYPE, b'base', 0o644)])
        status, _, body = binary_http(self.socket, 'POST', '/v1/templates?profile=' + profile, data)
        assert status == 200, body
        return json.loads(body)['id']

    def tests(self):
        assert self.info['profiles']['python']['hardWorkspaceQuota'] is True
        assert self.info['profiles']['other']['hardWorkspaceQuota'] is False
        self.receipt['poolImageBytes'] = self.image.stat().st_size
        plain = self.root / 'ordinary-quota-control'
        plain.mkdir(mode=0o755)
        (plain/'data').mkdir(mode=0o755)
        config = self.root / 'ordinary-quota-control.toml'
        config.write_text(self.config.read_text().replace(json.dumps(str(self.storage)), json.dumps(str(plain))))
        config.chmod(0o600)
        result = call(str(self.binary), 'check', '--config', str(config), check=False)
        assert result.returncode and 'hard_workspace_quota requires' in result.stderr, result
        self.done('profile-rejects-ordinary-storage-on-startup')
        ordinary_base = self.template('other')
        for label, options in [('ordinary-directory', {}), ('ordinary-overlay', {'templateId': ordinary_base})]:
            start = time.monotonic_ns()
            session = self.session_open(profile='other', **options)
            elapsed = (time.monotonic_ns()-start)/1e6
            writable = self.socket.parent / ('workspace-overlays' if options else 'workspaces') / session['id']
            assert writable.is_dir(), writable
            self.receipt['backings'][label] = {'openMillis': elapsed, 'initialAllocatedBytes': self.allocated(writable)}
            assert not list((self.data/'volumes').iterdir())
            self.session_close(session)
            self.session_forget(session)
        base = self.template('python')
        for managed in (False, True):
            for template in (False, True):
                label = ('workspace' if managed else 'session') + ('-overlay' if template else '-directory')
                options = {'templateId': base} if template else {}
                start = time.monotonic_ns()
                if managed:
                    route = '/v1/workspaces/' + label
                    workspace = self.ensure(route, **options)
                    def execute(source):
                        _, run = self.command(route, workspace['generation'], source)
                        return run, self.wait(run)
                    ready, result = execute('printf ready')
                    assert result['result']['stdout'] == 'ready', result
                    self.forget(ready)
                else:
                    session = self.session_open(**options)
                    def execute(source):
                        return self.session_exec(session, source)
                    assert http(self.socket, 'GET', '/v1/volumes')[1]['volumes'] == []
                cost = {'openMillis': (time.monotonic_ns()-start)/1e6}
                self.receipt['backings'][label] = cost
                directories = list((self.data/'volumes').iterdir())
                assert len(directories) == 1, directories
                data = directories[0]
                cost['initialAllocatedBytes'] = self.allocated(data)
                if not managed:
                    assert http(self.socket, 'GET', '/v1/volumes/' + data.name)[0] == 404
                    assert http(self.socket, 'POST', '/v1/volumes/' + data.name + '/delete', {})[0] == 404
                for kind, program, limit in [('byteWrite', WRITE, 8*1024*1024), ('inodeCreate', INODES, 128)]:
                    request, result = execute('python3 -c ' + shlex.quote(program))
                    assert result['state'] == 'succeeded', result
                    used, refused = json.loads(result['result']['stdout'])
                    assert used <= limit and refused in (errno.EDQUOT, errno.ENOSPC), (label, kind, used, refused)
                    cost[kind] = {'observed': used, 'limit': limit, 'errno': refused}
                    self.forget(request)
                if managed:
                    expected = {'generation': workspace['generation']}
                    self.require_deleted(route, expected)
                else:
                    self.session_close(session)
                    self.session_forget(session)
                assert not list((self.data/'volumes').iterdir())
                self.done(label + '-enforces-byte-and-inode-limits-at-write')
        route = '/v1/workspaces/durable-after-restart'
        retained = self.ensure(route, templateId=base)
        expected = {'generation': retained['generation']}
        request, run = self.command(route, retained['generation'], 'printf intact > retained')
        assert self.wait(run)['state'] == 'succeeded'
        self.forget(request)
        live = self.session_open(templateId=base)
        assert len(list((self.data/'volumes').iterdir())) == 2
        call('systemctl', 'kill', '--kill-whom=main', '--signal=KILL', self.unit)
        self.restart()
        assert {path.name for path in (self.data/'volumes').iterdir()} == {retained['id']}
        assert http(self.socket, 'GET', '/v1/sessions/' + live['id'])[0] == 404
        request, run = self.command(route, retained['generation'], 'cat retained')
        assert self.wait(run)['result']['stdout'] == 'intact'
        self.forget(request)
        self.require_deleted(route, expected)
        assert http(self.socket, 'DELETE', '/v1/templates/' + base)[0] == 200
        self.done('restart-reclaims-private-projects-after-containment')

    @staticmethod
    def allocated(root):
        return sum(path.lstat().st_blocks*512 for path in [root, *root.rglob('*')])

    def require_deleted(self, route, expected):
        status, response = http(self.socket, 'POST', route + '/delete', expected)
        assert status in (200, 202), response
        self.until(lambda: http(self.socket, 'GET', route)[1]['state'] == 'deleted')
        assert http(self.socket, 'POST', route + '/forget', expected)[0] == 200
