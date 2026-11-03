#!/usr/bin/env python3
"""Ordinary volumes and session workspaces inside owned, bounded ext4 images."""
import argparse
import hashlib
from http.client import HTTPResponse
import json
import os
from pathlib import Path
import signal
import socket
import time
import traceback
import uuid

from native_probe import Probe, call, connect, http
from volume_probe import VolumeProbe


class PlainStorageProbe(VolumeProbe):
    def __init__(self, binary, tools, report):
        super().__init__(binary, tools, report)
        renamed = self.root / 'data.ext4'
        self.image.rename(renamed)
        self.image = renamed
        self.runtime_image = self.root / 'runtime.ext4'
        with self.runtime_image.open('xb') as image:
            image.truncate(64 * 1024 * 1024)
        self.receipt.update(
            scope='Ordinary directories on disposable 512 MiB volume and 64 MiB runtime ext4 images; no production data or model',
            plainStorageProbeSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())

    def setup(self):
        call('mkfs.ext4', '-F', '-q', '-m', '0', str(self.image))
        call('mount', '-o', 'loop,nosuid,nodev', str(self.image), str(self.storage))
        self.storage.chmod(0o755)
        self.data.mkdir(mode=0o755)
        self.socket.parent.mkdir(mode=0o755)
        call('mkfs.ext4', '-F', '-q', '-m', '0', str(self.runtime_image))
        call('mount', '-o', 'loop,nosuid,nodev', str(self.runtime_image), str(self.socket.parent))
        self.socket.parent.chmod(0o755)
        Probe.setup(self)
        assert self.info['storage']['quotaEnforced'] is False
        assert self.data.stat().st_dev == (self.storage / 'state').stat().st_dev
        self.done('plain-storage-starts-with-shared-metadata-without-enforced-quotas')

    def tests(self):
        volume, value = self.volume()
        assert value['state'] == 'ready', value
        self.write(volume, "python3 - <<'PY'\nfrom pathlib import Path\nimport os\np=Path('original')\np.write_bytes(b'A' * (2*1024*1024))\nos.link(p,'same')\nPath('outside').symlink_to('/etc/host-sentinel')\nPY")
        original = self.data / 'volumes' / volume['id'] / 'data'
        unsupported = self.storage / 'reflink-check'
        try:
            result = call('cp', '--reflink=always', str(original / 'original'), str(unsupported), check=False)
            assert result.returncode != 0, 'Fixture must actually require the ordinary-copy fallback'
        finally:
            unsupported.unlink(missing_ok=True)

        clone, value = self.volume(cloneFrom=volume['id'])
        assert value['state'] == 'ready', value
        copied = self.data / 'volumes' / clone['id'] / 'data'
        assert (copied / 'original').read_bytes() == b'A' * (2*1024*1024)
        assert (copied / 'original').stat().st_ino == (copied / 'same').stat().st_ino
        assert (copied / 'original').stat().st_ino != (original / 'original').stat().st_ino
        assert os.readlink(copied / 'outside') == '/etc/host-sentinel'
        self.write(clone, "python3 -c \"from pathlib import Path; Path('original').write_bytes(b'changed')\"")
        assert (original / 'original').read_bytes() == b'A' * (2*1024*1024)
        self.done('ordinary-copy-preserves-hardlinks-and-symlinks-with-independent-content')

        small, value = self.volume(cloneFrom=volume['id'], byteLimit=1048576)
        assert value['state'] == 'failed' and value['code'] == 'STORAGE_LIMIT', value
        assert not (self.data / 'volumes' / small['id']).exists()
        assert (original / 'original').read_bytes() == b'A' * (2*1024*1024)
        self.volume_forget(small)
        self.done('oversized-plain-clone-is-removed-before-publication-with-source-preserved')

        self.restart()
        assert http(self.socket, 'GET', '/v1/volumes/' + volume['id'])[1]['state'] == 'ready'
        assert (original / 'original').read_bytes() == b'A' * (2*1024*1024)
        self.done('ordinary-volumes-survive-daemon-restart')

        config = self.config.read_text()
        try:
            self.config.write_text(config.replace('[storage]\n', '[storage]\nrequire_quota = true\n'))
            checked = call(str(self.binary), 'check', '--config', str(self.config), check=False)
            assert checked.returncode != 0 and 'require_quota' in checked.stderr, checked
        finally:
            self.config.write_text(config)
        self.done('explicit-require-quota-refuses-the-ordinary-filesystem')
        for request in (clone, volume):
            self.volume_delete(request)
            self.volume_forget(request)
        self.done('plain-volumes-delete-and-forget-through-public-api')
        self.accounting_recovery()
        self.pool_accounting()
        self.disk_workspaces()

    def disk_workspaces(self):
        parent = self.session_open()
        workspace = self.session_workspace(parent)
        assert workspace.stat().st_dev == self.socket.parent.stat().st_dev
        assert workspace.stat().st_dev != self.daemon_path(self.socket.parent / 'jobs' / parent['id']).stat().st_dev
        request, result = self.session_exec(parent, 'printf disk-data > keep.txt')
        assert result['state'] == 'succeeded', result
        self.forget(request)
        value = http(self.socket, 'GET', '/v1/sessions/' + parent['id'])[1]
        assert value['storageUsage']['mode'] == 'periodic', value
        assert value['storageUsage']['byteLimit'] == 8388608, value
        child = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId']}
        status, value = http(self.socket, 'POST', f'/v1/sessions/{parent["id"]}/shells', child)
        assert status == 202 and value['parentSessionId'] == parent['id'], value
        assert self.session_wait(child)['state'] == 'ready'
        assert self.session_workspace(child) == workspace
        request, result = self.session_exec(child, 'cat keep.txt; printf child-data > child.txt')
        assert result['state'] == 'succeeded' and result['result']['stdout'] == 'disk-data', result
        self.forget(request)
        self.session_close(child)
        self.session_forget(child)
        assert (workspace / 'keep.txt').read_text() == 'disk-data'
        assert (workspace / 'child.txt').read_text() == 'child-data'
        self.session_close(parent)
        self.session_forget(parent)
        assert not workspace.parent.exists()
        self.done('session-disk-data-is-shared-until-parent-containment-and-then-removed')

        parent = self.session_open()
        workspace = self.session_workspace(parent)
        request, result = self.session_exec(parent, 'printf recover-only-if-owned > keep.txt')
        assert result['state'] == 'succeeded', result
        self.forget(request)
        old_epoch = self.info['serverId']
        call('systemctl', 'kill', '--kill-whom=main', '--signal=KILL', self.unit)
        call('systemctl', 'stop', self.unit, check=False)
        call('systemctl', 'reset-failed', self.unit, check=False)
        assert (workspace / 'keep.txt').read_text() == 'recover-only-if-owned'
        marker = self.socket.parent / 'workspaces/owner.json'
        original = marker.read_bytes()
        try:
            owner = json.loads(original)
            owner['cgroupRoot'] = '/different-owned-runtime'
            marker.write_text(json.dumps(owner))
            try:
                self.start()
            except AssertionError:
                assert (workspace / 'keep.txt').read_text() == 'recover-only-if-owned'
            else:
                raise AssertionError('Foreign disk workspace namespace was adopted')
        finally:
            marker.write_bytes(original)
            call('systemctl', 'stop', self.unit, check=False)
            call('systemctl', 'reset-failed', self.unit, check=False)
        unknown = marker.parent / 'unknown-entry'
        try:
            unknown.write_text('preserve')
            try:
                self.start()
            except AssertionError:
                assert unknown.read_text() == 'preserve'
                assert (workspace / 'keep.txt').read_text() == 'recover-only-if-owned'
            else:
                raise AssertionError('Unknown workspace entry permitted partial recovery')
        finally:
            unknown.unlink(missing_ok=True)
            call('systemctl', 'stop', self.unit, check=False)
            call('systemctl', 'reset-failed', self.unit, check=False)
        self.start()
        assert self.info['serverId'] != old_epoch
        assert not workspace.parent.exists()
        assert http(self.socket, 'GET', '/v1/sessions/' + parent['id'])[0] == 404
        fresh = self.session_open()
        self.session_close(fresh)
        self.session_forget(fresh)
        self.done('disk-workspace-recovery-refuses-foreign-or-unknown-data-before-new-epoch')

    def pool_accounting(self):
        self.config.write_text(self.config.read_text().replace('pool_bytes = 536870912', 'pool_bytes = 8388608'))
        self.restart()
        assert self.info['storage']['poolUsage']['state'] == 'complete'
        volumes = [self.volume()[0] for _ in range(2)]
        sessions = [self.session_open(volumeId=volume['id']) for volume in volumes]
        data = [self.data / 'volumes' / volume['id'] / 'data' for volume in volumes]
        groups = [self.workloads_group / ('session-' + session['id']) for session in sessions]
        # Each writer has a 7 MiB maximum, below its 8 MiB volume limit. Together
        # they exceed the smaller pool; the fixture itself remains bounded at 512 MiB.
        source = "printf preserved > keep.txt; python3 -c \"import time; f=open('growth','wb',buffering=0); [(f.write(b'x'*65536),time.sleep(.04)) for _ in range(112)]\" >/dev/null 2>&1 &"
        for session in sessions:
            request, result = self.session_exec(session, source)
            assert result['state'] == 'succeeded', result
            self.forget(request)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            pool = http(self.socket, 'GET', '/v1/info')[1]['storage']['poolUsage']
            if pool['state'] == 'exceeded' and all('frozen 1' in (group / 'cgroup.events').read_text() for group in groups):
                break
            time.sleep(.05)
        else:
            raise AssertionError('Aggregate pool growth did not pause both independent sessions')
        sizes = [(path / 'growth').stat().st_size for path in data]
        time.sleep(.25)
        assert sizes == [(path / 'growth').stat().st_size for path in data]
        for volume, session, path in zip(volumes, sessions, data):
            value = http(self.socket, 'GET', '/v1/volumes/' + volume['id'])[1]
            assert value['usage']['state'] == 'complete', value
            request = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId'], 'command': 'touch must-not-run'}
            status, refusal = http(self.socket, 'POST', '/v1/sessions/' + session['id'] + '/commands', request)
            assert status == 409 and refusal['error']['code'] == 'STORAGE_LIMIT', refusal
            assert not (path / 'must-not-run').exists()
        denied = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId'], 'profile': 'python'}
        status, refusal = http(self.socket, 'POST', '/v1/volumes', denied)
        assert status == 409 and refusal['error']['code'] == 'STORAGE_LIMIT', refusal
        assert http(self.socket, 'GET', '/v1/volumes/' + denied['id'])[0] == 404
        self.receipt['poolObservation'] = {'usage': pool, 'pausedFileSizes': sizes}
        self.done('aggregate-pool-limit-pauses-under-limit-volumes-and-refuses-new-growth')

        self.session_close(sessions[0])
        self.session_forget(sessions[0])
        self.volume_delete(volumes[0])
        self.volume_forget(volumes[0])
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            pool = http(self.socket, 'GET', '/v1/info')[1]['storage']['poolUsage']
            if pool['state'] == 'complete' and 'frozen 0' in (groups[1] / 'cgroup.events').read_text():
                break
            time.sleep(.05)
        else:
            raise AssertionError('Removing a volume did not restore the surviving session')
        request, result = self.session_exec(sessions[1], 'printf recovered')
        assert result['state'] == 'succeeded', result
        assert (data[1] / 'keep.txt').read_text() == 'preserved'
        self.forget(request)
        fresh, value = self.volume()
        assert value['state'] == 'ready', value
        self.volume_delete(fresh)
        self.volume_forget(fresh)
        self.session_close(sessions[1])
        self.session_forget(sessions[1])
        self.volume_delete(volumes[1])
        self.volume_forget(volumes[1])
        self.done('pool-deletion-restores-existing-session-and-new-volume-admission')

    def accounting_recovery(self):
        volume, value = self.volume(byteLimit=2 * 1024 * 1024)
        assert value['state'] == 'ready', value
        session = self.session_open(volumeId=volume['id'])
        source = "printf preserved > keep.txt; python3 -c \"import time; f=open('growth','wb',buffering=0); [(f.write(b'x'*65536),time.sleep(.03)) for _ in range(1024)]\" >/dev/null 2>&1 &"
        request, result = self.session_exec(session, source)
        assert result['state'] == 'succeeded', result
        self.forget(request)
        group = self.workloads_group / ('session-' + session['id'])
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            value = http(self.socket, 'GET', '/v1/volumes/' + volume['id'])[1]
            if value['usage']['state'] == 'exceeded' and 'frozen 1' in (group / 'cgroup.events').read_text():
                break
            time.sleep(.05)
        else:
            raise AssertionError('Background growth was not detected and paused')
        data = self.data / 'volumes' / volume['id'] / 'data'
        before = (data / 'growth').stat().st_size
        time.sleep(.25)
        assert (data / 'growth').stat().st_size == before
        denied = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId'], 'command': 'touch must-not-run'}
        status, refusal = http(self.socket, 'POST', '/v1/sessions/' + session['id'] + '/commands', denied)
        assert status == 409 and refusal['error']['code'] == 'STORAGE_LIMIT', refusal
        assert not (data / 'must-not-run').exists()
        self.receipt['accountingObservation'] = {'usage': value['usage'], 'pausedFileSize': before}
        self.done('periodic-overage-pauses-background-writers-and-refuses-new-execution')

        # End the writer before deleting its file; an open unlinked file is not
        # visible to directory accounting and needs hard quotas for a hard bound.
        self.session_close(session)
        self.session_forget(session)
        session = self.session_open(volumeId=volume['id'])
        body = json.dumps({'path': 'keep.txt', 'format': 'raw'}).encode()
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(15)
            connect(stream, self.socket)
            stream.sendall((f"POST /v1/sessions/{session['id']}/snapshot HTTP/1.1\r\nHost: sandcrab\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body)
            response = HTTPResponse(stream)
            response.begin()
            assert response.status == 200 and response.read(128) == b'preserved'
        assert http(self.socket, 'DELETE', f"/v1/sessions/{session['id']}/files?path=growth") == (200, {'deleted': True})
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            value = http(self.socket, 'GET', '/v1/sessions/' + session['id'])[1]
            if value['storageUsage']['state'] == 'complete':
                break
            time.sleep(.05)
        else:
            raise AssertionError('Deleting excess data did not restore admission')
        request, result = self.session_exec(session, 'printf recovered')
        assert result['state'] == 'succeeded', result
        assert (data / 'keep.txt').read_text() == 'preserved'
        self.forget(request)
        self.session_close(session)
        self.session_forget(session)
        self.volume_delete(volume)
        self.volume_forget(volume)
        self.done('overage-retains-read-delete-access-and-resumes-after-measured-recovery')

    def unmount_fixture(self, mount):
        if mount in (self.storage, self.socket.parent):
            assert mount.parent == self.root and mount.name in ('storage', 'runtime') and not mount.is_symlink()
            call('umount', str(mount))
        else:
            Probe.unmount_fixture(self, mount)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'tools', 'report'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and not args.report.exists(), 'Root and a fresh receipt are required'
    def interrupted(signum, frame):
        raise KeyboardInterrupt('Plain storage probe interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    probe = PlainStorageProbe(args.binary.resolve(), args.tools.resolve(), args.report.resolve())
    try:
        probe.setup()
        probe.tests()
        probe.receipt['result'] = 'PASS'
    except BaseException as error:
        probe.receipt.update(result='FAIL', failureType=type(error).__name__)
        args.report.with_suffix('.diagnostic.txt').write_text(traceback.format_exc())
        raise
    finally:
        try:
            probe.cleanup()
        finally:
            probe.save()


if __name__ == '__main__':
    main()
