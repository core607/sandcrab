#!/usr/bin/env python3
"""Real shared-overlay workspaces, template pins and contained crash recovery."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import uuid

from .native import call, http
from .file import archive, binary_http
from .template import TemplateProbe


class OverlayProbe(TemplateProbe):
    def __init__(self, binary, tools, report):
        super().__init__(binary, tools, report)
        self.data_root = self.root / 'overlay-data'
        self.data_root.mkdir(mode=0o755)
        self.backing = self.root / 'overlay.xfs'
        with self.backing.open('xb') as stream:
            stream.truncate(512 * 1024 * 1024)
        self.old_runtime = self.socket.parent
        self.socket = self.data_root / 'runtime/control.sock'
        self.config.write_text(self.config.read_text().replace(str(self.old_runtime), str(self.socket.parent))
            .replace('max_sandboxes = 2', 'max_sandboxes = 4').replace('max_records = 8', 'max_records = 16'))
        profile = self.config.read_text().split('[profiles.python]', 1)[1].split('\n[', 1)[0]
        self.config.write_text(self.config.read_text() + '\n[profiles.other]\n' + profile.replace('exec_user = "nobody"', 'exec_user = "bin"'))
        self.workloads_group = self.delegated_root / ('sandcrab-' + hashlib.sha256(str(self.socket.parent).encode()).hexdigest()) / 'workloads'
        self.receipt['scope'] = 'Native shared overlay workspaces and lifecycle on XFS; synthetic data, no density measurement'
        self.receipt['probeSha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    def setup(self):
        call('mkfs.xfs', '-f', '-m', 'reflink=1', str(self.backing))
        call('mount', '-o', 'loop,nosuid,nodev', str(self.backing), str(self.data_root))
        self.data_root.chmod(0o755)
        super().setup()

    def unmount_fixture(self, mount):
        if mount == self.data_root:
            assert mount.parent == self.root and mount.name == 'overlay-data'
            call('umount', str(mount))
        else:
            super().unmount_fixture(mount)

    def start(self):
        if not getattr(self, 'deny_overlay', False):
            return super().start()
        call('systemd-run', '--quiet', '--collect', '--unit', self.unit, '--slice', self.slice,
             '-p', 'Delegate=yes', '-p', 'MemorySwapMax=0', '-p', 'TasksMax=infinity',
             '-p', 'Environment=PATH=/usr/bin:/bin', '-p', 'KillMode=control-group',
             '-p', 'SystemCallFilter=~open_tree move_mount', '-p', 'SystemCallErrorNumber=ENOSYS',
             str(self.binary), 'serve', '--config', str(self.config))
        self.wait_ready()

    def execute(self, session, code):
        request, result = self.session_exec(session, code)
        self.forget(request)
        assert result['state'] == 'succeeded', result
        return result['result']['stdout']

    def child(self, parent):
        request = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId']}
        status, value = http(self.socket, 'POST', f'/v1/sessions/{parent["id"]}/shells', request)
        assert status == 202, value
        self.session_wait(request)
        return request

    def mount_targets(self):
        daemon = call('systemctl', 'show', self.unit, '-p', 'MainPID', '--value').stdout.strip()
        assert daemon.isdecimal() and int(daemon) > 1
        assert os.readlink(f'/proc/{daemon}/ns/mnt') != os.readlink('/proc/self/ns/mnt')
        return [line.split()[4] for line in Path(f'/proc/{daemon}/mountinfo').read_text().splitlines()]

    def tests(self):
        contents = archive([('base', tarfile.REGTYPE, b'original', 0o644),
                            ('gone', tarfile.REGTYPE, b'delete me', 0o644),
                            ('shared-cache', tarfile.REGTYPE, b'x' * 131072, 0o644)])
        tree = self.put(contents)
        for extra in [{'templateId': 'invalid'}, {'templateId': tree['id'], 'volumeId': str(uuid.uuid4())}]:
            request = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId'], 'profile': 'python', **extra}
            assert http(self.socket, 'POST', '/v1/sessions', request) == (400, {'error': {'code': 'INVALID_REQUEST'}})
        mismatch = self.session_open(templateId=tree['id'], profile='other', wait=False)
        refused = self.session_wait(mismatch, terminal=True)
        assert refused['state'] == 'failed' and refused['code'] == 'TEMPLATE_IDENTITY_MISMATCH', refused
        self.session_forget(mismatch)
        parent = json.loads(call('runuser', '-u', 'daemon', '--', str(self.binary), 'session', 'open',
                                 '--socket', str(self.socket), '--profile', 'python', '--template', tree['id']).stdout)
        opened = self.session_wait(parent)
        assert opened['state'] == 'ready', opened
        status, view = http(self.socket, 'GET', '/v1/sessions/'+parent['id'])
        assert status == 200 and view['templateId'] == tree['id']
        security = json.loads(self.execute(parent, '''python3 -c 'import json,os; s=dict(line.split(":",1) for line in open("/proc/self/status")); print(json.dumps({"uid":os.geteuid(),"caps":int(s["CapEff"],16),"nnp":int(s["NoNewPrivs"])}))' '''))
        assert security == {'uid': self.uid, 'caps': 0, 'nnp': 1}, security
        assert view['storageUsage']['allocatedBytes'] < tree['allocatedBytes'], view
        mount = str(self.socket.parent / 'workspaces' / parent['id'])
        assert self.mount_targets().count(mount) == 1
        assert mount not in [line.split()[4] for line in Path('/proc/self/mountinfo').read_text().splitlines()]
        assert http(self.socket, 'DELETE', '/v1/templates/'+tree['id'])[0] == 409
        self.done('template-view-is-private-single-mounted-and-charges-only-mutable-storage')

        self.execute(parent, 'printf changed > base; rm gone; printf parent > shared')
        child = self.child(parent)
        assert self.execute(child, 'cat base; printf ":"; cat shared; test ! -e gone') == 'changed:parent'
        self.execute(child, 'printf child > shared')
        assert self.execute(parent, 'cat shared') == 'child'
        independent = self.session_open(templateId=tree['id'])
        assert self.execute(independent, 'cat base; test -f gone; test ! -e shared') == 'original'
        base = self.socket.parent / 'templates/objects' / tree['id'] / 'lower/data'
        assert (base / 'base').read_bytes() == b'original' and (base / 'gone').exists()
        assert self.mount_targets().count(mount) == 1
        self.done('named-contexts-share-copy-up-and-independent-sessions-share-only-the-base')

        status, _, raw = binary_http(self.socket, 'PUT', f'/v1/sessions/{parent["id"]}/files?path=uploaded', b'atomic upload')
        assert status == 200, raw
        assert self.execute(child, 'cat uploaded') == 'atomic upload'
        status, _, raw = binary_http(self.socket, 'POST', f'/v1/sessions/{parent["id"]}/snapshot',
                                    json.dumps({'path': '.', 'format': 'tar'}).encode())
        assert status == 200, raw
        with tarfile.open(fileobj=io.BytesIO(raw)) as snapshot:
            assert snapshot.extractfile('base').read() == b'changed'
            assert snapshot.extractfile('uploaded').read() == b'atomic upload'
            assert 'gone' not in snapshot.getnames()
        self.done('streamed-files-publish-atomically-and-snapshot-reads-the-shared-overlay')

        self.session_close(parent)
        self.session_wait(child, terminal=True)
        self.session_forget(child)
        self.session_forget(parent)
        assert mount not in self.mount_targets()
        assert not (self.socket.parent / 'workspace-overlays' / parent['id']).exists()
        assert http(self.socket, 'DELETE', '/v1/templates/'+tree['id'])[0] == 409
        self.session_close(independent)
        self.session_forget(independent)
        assert http(self.socket, 'DELETE', '/v1/templates/'+tree['id']) == (200, {'deleted': True})
        self.done('closing-contains-all-contexts-unmounts-and-releases-only-its-own-template-pin')

        tree = self.put(contents)
        uncertain = self.session_open(templateId=tree['id'])
        mutable = self.socket.parent / 'workspace-overlays' / uncertain['id']
        mutable.chmod(0o777)
        assert http(self.socket, 'POST', '/v1/sessions/'+uncertain['id']+'/close', {})[0] == 200
        result = self.session_wait(uncertain, terminal=True)
        assert result['state'] == 'closing', result
        assert http(self.socket, 'DELETE', '/v1/templates/'+tree['id']) == (409, {'error': {'code': 'TEMPLATE_BUSY'}})
        assert mutable.exists()
        mutable.chmod(0o700)
        self.restart()
        assert not mutable.exists()
        assert http(self.socket, 'DELETE', '/v1/templates/'+tree['id'])[0] == 200
        self.done('uncertain-writable-layer-cleanup-retains-template-pin-until-contained-recovery')

        tree = self.put(contents)
        interrupted = self.session_open(templateId=tree['id'])
        self.execute(interrupted, 'printf disposable > base')
        call('systemctl', 'kill', '--kill-who=all', '--signal=SIGKILL', self.unit)
        self.restart()
        for name in ['workspaces', 'workspace-overlays']:
            assert sorted(path.name for path in (self.socket.parent / name).iterdir()) == ['owner.json']
        assert http(self.socket, 'GET', '/v1/sessions/'+interrupted['id'])[0] == 404
        assert http(self.socket, 'GET', '/v1/templates/'+tree['id']) == (200, tree)
        assert (base / 'base').read_bytes() == b'original'
        assert http(self.socket, 'DELETE', '/v1/templates/'+tree['id'])[0] == 200
        self.done('restart-contains-old-overlay-workloads-and-preserves-immutable-templates')

        self.deny_overlay = True
        try:
            self.restart()
        except AssertionError:
            assert 'Overlay startup check failed' in call('journalctl', '-u', self.unit, '--no-pager', '-n', '30').stdout
            assert call('systemctl', 'show', self.unit, '-p', 'MainPID', '--value').stdout.strip() == '0'
        else:
            raise AssertionError('service became ready without overlay mount syscalls')
        finally:
            self.deny_overlay = False
        self.restart()
        assert sorted(path.name for path in (self.socket.parent / 'workspace-overlays').iterdir()) == ['owner.json']
        self.done('startup-refuses-unavailable-overlay-syscalls-before-readiness-and-recovers-cleanly')
