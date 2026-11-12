#!/usr/bin/env python3
"""Native volume acceptance in one disposable, bounded XFS filesystem."""
import hashlib
import json
import os
import re
from pathlib import Path
import signal
import subprocess
import time
import uuid

from .native import Probe, call, http


class VolumeProbe(Probe):
    def __init__(self, binary, tools, report):
        super().__init__(binary, tools, report)
        self.storage = self.root / 'storage'
        self.storage.mkdir(mode=0o755)
        self.storage.chmod(0o755)
        self.data = self.storage / 'data'
        self.data.mkdir(mode=0o755)
        self.data.chmod(0o755)
        self.image = self.root / 'data.xfs'
        with self.image.open('xb') as image:
            image.truncate(512 * 1024 * 1024)
        original = self.config.read_text()
        alternate = original.split('[profiles.python]\n', 1)[1].replace('exec_user = "nobody"', 'exec_user = "bin"')
        self.config.write_text(original + '\n[profiles.other]\n' + alternate + f'''
[storage]
root = {json.dumps(str(self.storage))}
pool_bytes = 536870912
max_volume_bytes = 8388608
max_volume_inodes = 256
max_volumes = 4
max_records = 12
''')
        self.receipt['scope'] = 'Standalone volume API and CLI on a disposable 512 MiB XFS filesystem; no production data or model'
        self.receipt['volumeProbeSha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    def setup(self):
        call('mkfs.xfs', '-f', '-m', 'reflink=1', str(self.image))
        call('mount', '-o', 'loop,prjquota,nosuid,nodev', str(self.image), str(self.data))
        sentinel = self.data / 'unowned'
        sentinel.write_text('preserve preexisting data')
        try:
            super().setup()
        except AssertionError:
            assert 'Refusing to initialize a nonempty unowned volume store' in call('journalctl', '-u', self.unit, '--no-pager', '-n', '30').stdout
        else:
            raise AssertionError('unowned store was adopted')
        assert sentinel.read_text() == 'preserve preexisting data'
        assert not (self.storage / 'state/owner.json').exists()
        sentinel.unlink()
        call('systemctl', 'reset-failed', self.unit, check=False)
        metadata = self.storage / 'state/unowned'
        metadata.write_text('preserve preexisting metadata')
        try:
            self.start()
        except AssertionError:
            assert 'Refusing to initialize a nonempty unowned volume store' in call('journalctl', '-u', self.unit, '--no-pager', '-n', '30').stdout
        else:
            raise AssertionError('unowned metadata was adopted')
        assert metadata.read_text() == 'preserve preexisting metadata'
        assert not (self.storage / 'state/owner.json').exists()
        metadata.unlink()
        call('systemctl', 'reset-failed', self.unit, check=False)
        self.start()
        self.done('volume-bootstrap-refuses-preexisting-data')
        assert self.info['capabilities'] == ['runs', 'sessions', 'files', 'uploads', 'events', 'calls', 'templates', 'volumes']
        assert self.info['storage']['maxVolumeBytes'] == 8388608

    def volume(self, **options):
        request = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId'], 'profile': 'python', **options}
        status, value = http(self.socket, 'POST', '/v1/volumes', request)
        assert status == 202, value
        return request, self.volume_wait(request)

    def volume_wait(self, request):
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            status, value = http(self.socket, 'GET', '/v1/volumes/' + request['id'])
            assert status == 200, value
            if value['state'] not in ('creating', 'deleting'):
                return value
            time.sleep(.05)
        raise AssertionError('volume operation did not finish')

    def volume_delete(self, request):
        status, value = http(self.socket, 'POST', '/v1/volumes/' + request['id'] + '/delete', {})
        assert status in (200, 202), value
        assert self.volume_wait(request)['state'] == 'deleted'
        assert not (self.data / 'volumes' / request['id']).exists()

    def volume_forget(self, request):
        assert http(self.socket, 'POST', '/v1/volumes/' + request['id'] + '/forget', {}) == (200, {'forgotten': True})

    def write(self, volume, source):
        session = self.session_open(volumeId=volume['id'])
        request, result = self.session_exec(session, source)
        assert result['state'] == 'succeeded', result
        self.forget(request)
        self.session_close(session)
        self.session_forget(session)

    def tests(self):
        for capability in ('runs', 'sessions', 'volumes'):
            status, schema = http(self.socket, 'GET', '/v1/openapi?capability=' + capability)
            assert status == 200 and '/v1/' + capability in schema['paths']
            assert len(json.dumps({'status': status, 'body': schema}, separators=(',', ':'))) < 20000, 'Model tool response would be truncated'
        self.done('volume-capability-discovery-fits-model-tool-output')
        volume, result = self.volume()
        assert result['state'] == 'ready', result
        assert result['byteLimit'] == 8388608 and result['inodeLimit'] == 256
        assert len(result['planDigest']) == 64
        assert http(self.socket, 'POST', '/v1/volumes', volume) == (200, result)
        for changes, expected in [({'byteLimit': 1048576}, 'ID_CONFLICT'),
                                  ({'uid': 0}, 'INVALID_REQUEST'),
                                  ({'id': str(uuid.uuid4()), 'byteLimit': 1048577}, 'VOLUME_LIMIT'),
                                  ({'id': str(uuid.uuid4()), 'byteLimit': 8389632}, 'VOLUME_LIMIT'),
                                  ({'id': str(uuid.uuid4()), 'serverId': str(uuid.uuid4())}, 'SERVER_CHANGED')]:
            assert http(self.socket, 'POST', '/v1/volumes', {**volume, **changes})[1]['error']['code'] == expected
        assert http(self.socket, 'POST', '/v1/volumes/' + volume['id'] + '/forget', {})[1]['error']['code'] == 'VOLUME_ACTIVE'
        self.done('volume-authority-quotas-request-identity-and-explicit-forget')

        self.write(volume, "python3 - <<'PY'\nfrom pathlib import Path\nimport os\np=Path('0x-source.bin')\np.write_bytes(b'A'*(2*1024*1024))\nos.link(p,'same.bin')\nPath('unicode.txt').write_text('hello 世界')\nPath('link').symlink_to('/etc/host-sentinel')\nPY")
        original = self.data / 'volumes' / volume['id'] / 'data'
        assert (original / '0x-source.bin').read_bytes() == b'A' * (2 * 1024 * 1024)
        session = self.session_open(volumeId=volume['id'])
        assert http(self.socket, 'GET', '/v1/volumes/' + volume['id'])[1]['attachedTo'] == session['id']
        denied = {**session, 'id': str(uuid.uuid4())}
        assert http(self.socket, 'POST', '/v1/sessions', denied)[0] == 202
        terminal = self.session_wait(denied, terminal=True)
        assert terminal['state'] == 'failed' and terminal['code'] == 'VOLUME_IN_USE', terminal
        self.session_forget(denied)
        denied = self.session_open(wait=False, profile='other', volumeId=volume['id'])
        assert self.session_wait(denied, terminal=True)['code'] == 'VOLUME_PROFILE_MISMATCH'
        self.session_forget(denied)
        assert http(self.socket, 'POST', '/v1/volumes', {**volume, 'id': str(uuid.uuid4()), 'profile': 'other', 'cloneFrom': volume['id']})[1]['error']['code'] == 'VOLUME_PROFILE_MISMATCH'
        assert http(self.socket, 'POST', '/v1/volumes/' + volume['id'] + '/delete', {})[1]['error']['code'] == 'VOLUME_IN_USE'
        assert http(self.socket, 'POST', '/v1/volumes', {**volume, 'id': str(uuid.uuid4()), 'cloneFrom': volume['id']})[1]['error']['code'] == 'VOLUME_IN_USE'
        self.session_close(session)
        self.session_forget(session)
        self.done('volume-exclusive-attachment-and-closed-session-persistence')

        clone, result = self.volume(cloneFrom=volume['id'])
        assert result['state'] == 'ready', result
        copied = self.data / 'volumes' / clone['id'] / 'data'
        assert (copied / '0x-source.bin').read_bytes() == (original / '0x-source.bin').read_bytes()
        assert (copied / 'unicode.txt').read_text() == 'hello 世界'
        assert os.readlink(copied / 'link') == '/etc/host-sentinel'
        assert (copied / '0x-source.bin').stat().st_ino == (copied / 'same.bin').stat().st_ino
        assert (copied / '0x-source.bin').stat().st_ino != (original / '0x-source.bin').stat().st_ino
        before = call('xfs_io', '-r', '-c', 'fiemap -v', str(original / '0x-source.bin')).stdout
        # The header's filename deliberately contains 0x; only the final flag field is hexadecimal.
        flags = [int(fields[-1], 16) for line in before.splitlines()
                 if (fields := line.split()) and re.fullmatch(r'0x[0-9a-fA-F]+', fields[-1])]
        assert flags and any(flag & 0x2000 for flag in flags), before  # FIEMAP_EXTENT_SHARED.
        self.write(clone, "python3 -c \"from pathlib import Path; f=Path('0x-source.bin').open('r+b'); f.write(b'B')\"")
        assert (copied / '0x-source.bin').read_bytes()[0:1] == b'B'
        assert (original / '0x-source.bin').read_bytes()[0:1] == b'A'
        self.done('volume-reflink-preserves-links-and-independent-copy-on-write')

        small, result = self.volume(cloneFrom=volume['id'], byteLimit=1048576)
        assert result['state'] == 'failed' and result['code'] == 'CLONE_FAILED', result
        assert not (self.data / 'volumes' / small['id']).exists()
        assert (original / '0x-source.bin').read_bytes()[0:1] == b'A'
        assert not http(self.socket, 'GET', '/v1/volumes/' + volume['id'])[1]['busy']
        self.volume_forget(small)
        self.done('volume-clone-quota-failure-removes-only-the-unpublished-target')

        self.quota_tests()
        old_epoch = self.info['serverId']
        session = self.session_open(volumeId=volume['id'])
        call('systemctl', 'kill', '--kill-whom=main', '--signal=KILL', self.unit)
        call('systemctl', 'stop', self.unit, check=False)
        call('systemctl', 'reset-failed', self.unit, check=False)
        self.start()
        assert self.info['serverId'] != old_epoch
        assert http(self.socket, 'POST', '/v1/volumes', volume)[0] == 200
        assert http(self.socket, 'GET', '/v1/sessions/' + session['id'])[0] == 404
        self.write(volume, 'test "$(head -c 1 0x-source.bin)" = A; printf survived > restart.txt')
        assert (original / 'restart.txt').read_text() == 'survived'
        self.done('volume-supervisor-loss-retains-published-data-and-durable-replay')
        self.fault_tests(volume)
        self.shared_quota_mount(volume)
        self.capacity_tests(volume)
        self.pool_exhaustion()

        prefix = ['runuser', '-u', 'daemon', '--', str(self.binary)]
        listing = json.loads(call(*prefix, 'volume', 'list', '--socket', str(self.socket)).stdout)
        assert {v['id'] for v in listing['volumes']} == {volume['id'], clone['id']}
        cli = json.loads(call(*prefix, 'volume', 'create', '--socket', str(self.socket), '--profile', 'python', '--bytes', '1048576').stdout)
        assert cli['state'] == 'ready', cli
        opened = json.loads(call(*prefix, 'session', 'open', '--socket', str(self.socket), '--profile', 'python', '--volume', cli['id'], '--ttl-ms', '3000').stdout)
        call(*prefix, 'session', 'close', '--socket', str(self.socket), opened['id'])
        self.session_forget(opened)
        call(*prefix, 'volume', 'delete', '--socket', str(self.socket), cli['id'])
        call(*prefix, 'volume', 'forget', '--socket', str(self.socket), cli['id'])
        self.done('volume-cli-creates-attaches-lists-deletes-and-forgets')
        session = self.session_open(volumeId=volume['id'])
        self.volume_delete(clone)
        assert http(self.socket, 'POST', '/v1/volumes', clone)[1]['state'] == 'deleted'
        assert http(self.socket, 'GET', '/v1/volumes/' + volume['id'])[1]['attachedTo'] == session['id']
        denied = self.session_open(wait=False, volumeId=volume['id'])
        assert self.session_wait(denied, terminal=True)['code'] == 'VOLUME_IN_USE'
        self.session_forget(denied)
        assert (original / '0x-source.bin').read_bytes()[0:1] == b'A'
        self.session_close(session)
        self.session_forget(session)
        self.volume_forget(clone)
        self.volume_delete(volume)
        self.volume_forget(volume)
        assert http(self.socket, 'GET', '/v1/volumes')[1] == {'volumes': [], 'nextAfter': None}
        self.done('volume-explicit-deletion-tombstone-and-record-release')

    def shared_quota_mount(self, volume):
        assert self.info['storage']['quotaEnforced'] is True
        strict = self.root / 'require-quota.toml'
        strict.write_text(self.config.read_text().replace('[storage]\n', '[storage]\nrequire_quota = true\n'))
        strict.chmod(0o600)
        call(str(self.binary), 'check', '--config', str(strict))
        call('systemctl', 'stop', self.unit)
        shared = self.data / 'shared'
        shared.mkdir(mode=0o755)
        shared.chmod(0o755)
        alternate = self.root / 'alternate'
        target = alternate / 'data'
        target.mkdir(parents=True)
        alternate.chmod(0o755)
        target.chmod(0o755)
        other = self.root / 'alternate-quota.toml'
        other.write_text(strict.read_text().replace(json.dumps(str(self.storage)), json.dumps(str(alternate))))
        other.chmod(0o600)
        call('mount', '--bind', str(shared), str(target))
        try:
            refused = call(str(self.binary), 'check', '--config', str(other), check=False)
            assert refused.returncode != 0 and 'whole XFS filesystem' in refused.stderr, refused
        finally:
            call('umount', str(target))
        call('mount', '--bind', str(shared), str(self.data))
        try:
            mount = json.loads(call('findmnt', '-J', '-T', str(self.data), '-o', 'TARGET,FSTYPE,FSROOT').stdout)
            assert {'target': str(self.data), 'fstype': 'xfs', 'fsroot': '/shared'} in mount['filesystems'], mount
            refused = call(str(self.binary), 'check', '--config', str(strict), check=False)
            assert refused.returncode != 0 and ('whole XFS filesystem' in refused.stderr
                                                or 'exactly one mount' in refused.stderr), refused
            call(str(self.binary), 'check', '--config', str(self.config))
            try:
                self.start()
            except AssertionError:
                log = call('journalctl', '-u', self.unit, '--no-pager', '-n', '10').stdout
                assert 'Restore the quota pool for existing project volumes' in log, log
            else:
                raise AssertionError('An existing quota store started on a subtree bind')
            assert not list(self.data.iterdir()), 'Recovery wrote to the replacement mount'
        finally:
            call('systemctl', 'stop', self.unit, check=False)
            call('umount', str(self.data))
        shared.rmdir()
        self.restart()
        assert self.info['storage']['quotaEnforced'] is True
        assert http(self.socket, 'GET', '/v1/volumes/' + volume['id'])[1]['state'] == 'ready'
        assert (self.data / 'volumes' / volume['id'] / 'data/restart.txt').read_text() == 'survived'
        self.done('whole-xfs-quotas-and-retained-volumes-survive-a-subdirectory-bind-refusal')

    def quota_tests(self):
        volume, result = self.volume(byteLimit=1048576, inodeLimit=32)
        assert result['state'] == 'ready', result
        session = self.session_open(volumeId=volume['id'])
        source = """python3 - <<'PY'
import errno
import fcntl
import os
import re
import struct
from pathlib import Path
fd=os.open('.',os.O_RDONLY|os.O_DIRECTORY)
attrs=bytearray(28)
fcntl.ioctl(fd,0x801c581f,attrs)
assert struct.unpack_from('I',attrs)[0]&0x200 and struct.unpack_from('I',attrs,12)[0]>0
for offset,value in [(0,struct.unpack_from('I',attrs)[0]&~0x200),(12,0)]:
    changed=bytearray(attrs)
    struct.pack_into('I',changed,offset,value)
    try:
        fcntl.ioctl(fd,0x401c5820,changed)
    except OSError as e:
        assert e.errno in (errno.EPERM,errno.EACCES,errno.EINVAL),e
    else:
        raise AssertionError('quota identity or inheritance changed')
os.close(fd)
try:
    Path('full').write_bytes(b'x'*(2*1024*1024))
except OSError as e:
    assert e.errno in (errno.EDQUOT,errno.ENOSPC), e
else:
    raise AssertionError('block quota did not apply')
Path('full').unlink()
count=0
try:
    for i in range(100):
        Path(str(i)).touch()
        count+=1
except OSError as e:
    assert e.errno in (errno.EDQUOT,errno.ENOSPC), e
else:
    raise AssertionError('inode quota did not apply')
print(count)
PY"""
        request, result = self.session_exec(session, source)
        assert result['state'] == 'succeeded' and 0 < int(result['result']['stdout']) < 32, result
        pool = os.statvfs(self.data)
        assert pool.f_bavail * pool.f_frsize > 100 * 1024 * 1024, 'The pool must have space; this test targets the volume quota'
        self.forget(request)
        self.session_close(session)
        self.session_forget(session)
        self.volume_delete(volume)
        self.volume_forget(volume)
        self.done('volume-block-and-inode-quotas-apply-to-untrusted-writes')

    def restart(self):
        call('systemctl', 'stop', self.unit, check=False)
        call('systemctl', 'reset-failed', self.unit, check=False)
        self.start()

    def capacity_tests(self, source):
        retained = [self.volume()[0] for _ in range(2)]
        extra = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId'], 'profile': 'python'}
        assert http(self.socket, 'POST', '/v1/volumes', extra)[1]['error']['code'] == 'VOLUME_CAPACITY'
        for volume in retained:
            self.volume_delete(volume)
        for _ in range(8):
            volume, result = self.volume(cloneFrom=source['id'], byteLimit=1048576)
            assert result['state'] == 'failed' and result['code'] == 'CLONE_FAILED', result
            retained.append(volume)
        assert http(self.socket, 'POST', '/v1/volumes', extra)[1]['error']['code'] == 'VOLUME_RECORD_CAPACITY'
        assert http(self.socket, 'POST', '/v1/volumes', retained[-1])[1]['state'] == 'failed'
        status, listing = http(self.socket, 'GET', '/v1/volumes')
        assert status == 200 and len(listing['volumes']) == 12
        assert [v['id'] for v in listing['volumes']] == sorted(v['id'] for v in listing['volumes'])
        after = listing['volumes'][4]['id']
        assert http(self.socket, 'GET', '/v1/volumes?after=' + after)[1]['volumes'] == listing['volumes'][5:]
        for volume in retained:
            self.volume_forget(volume)
        self.done('volume-live-and-durable-record-capacity-with-ordered-discovery')

    def pool_exhaustion(self):
        volume, result = self.volume()
        assert result['state'] == 'ready', result
        # This file is outside all projects but inside this fixture's 512 MiB image.
        # It simulates the entire data pool filling while control metadata stays writable.
        filler = self.data / 'pool-pressure'
        try:
            import errno
            with filler.open('xb', buffering=0) as stream:
                block = b'x' * (1024 * 1024)
                try:
                    for _ in range(512):
                        stream.write(block)
                except OSError as error:
                    assert error.errno == errno.ENOSPC, error
                else:
                    raise AssertionError('bounded pool accepted more than its size')
            free = os.statvfs(self.data)
            assert free.f_bavail * free.f_frsize < 2 * 1024 * 1024
            self.volume_delete(volume)
            record = json.loads((self.storage / 'state/records' / (volume['id'] + '.json')).read_text())
            assert record['state'] == 'deleted'
            self.volume_forget(volume)
        finally:
            filler.unlink(missing_ok=True)
        self.done('volume-data-pool-exhaustion-leaves-deletion-metadata-writable')

    def fault_tests(self, source):
        helpers = self.root / 'volume-helpers'
        helpers.mkdir(mode=0o755)
        failure = helpers / 'failed-unmount'
        (helpers / 'umount').write_text(f'''#!/usr/bin/python3
import os,sys
from pathlib import Path
flag=Path({str(failure)!r})
if flag.exists() and Path(sys.argv[-1]).name==flag.read_text(): sys.exit(1)
os.execv('/usr/bin/umount',['umount',*sys.argv[1:]])
''')
        (helpers / 'umount').chmod(0o755)
        self.launch_path = str(helpers) + ':/usr/bin:/bin'
        self.restart()
        faults = self.enable_launch_faults(helpers)
        delay = faults.gate

        def delayed_clone():
            faults.arm('copy', 'before')
            request = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId'], 'profile': 'python', 'cloneFrom': source['id']}
            assert http(self.socket, 'POST', '/v1/volumes', request)[0] == 202
            faults.wait()
            return request

        target = delayed_clone()
        assert http(self.socket, 'GET', '/v1/volumes/' + source['id'])[1]['busy']
        assert http(self.socket, 'POST', '/v1/volumes/' + source['id'] + '/delete', {})[1]['error']['code'] == 'VOLUME_IN_USE'
        assert http(self.socket, 'POST', '/v1/volumes', {**target, 'id': str(uuid.uuid4())})[1]['error']['code'] == 'STORAGE_CAPACITY'
        waiting = self.session_open(wait=False, volumeId=source['id'])
        assert self.session_wait(waiting, terminal=True)['code'] == 'VOLUME_IN_USE'
        self.session_forget(waiting)
        delay.unlink()
        assert self.volume_wait(target)['state'] == 'ready'
        self.volume_delete(target)
        self.volume_forget(target)
        self.done('volume-clone-holds-source-and-the-single-storage-slot')

        target = delayed_clone()
        call('systemctl', 'kill', '--kill-whom=main', '--signal=KILL', self.unit)
        delay.unlink()
        call('systemctl', 'stop', self.unit, check=False)
        self.restart()
        recovered = self.volume_wait(target)
        assert recovered['state'] == 'failed' and recovered['code'] == 'INTERRUPTED', recovered
        assert not (self.data / 'volumes' / target['id']).exists()
        assert http(self.socket, 'POST', '/v1/volumes', target) == (200, recovered)
        self.volume_forget(target)
        self.done('volume-interrupted-clone-recovers-only-unpublished-data')

        target = delayed_clone()
        records = self.storage / 'state/records'
        held = self.storage / 'state/records-held'
        records.rename(held)
        records.write_text('injected metadata write failure')
        records.chmod(0o600)
        try:
            delay.unlink()
            assert self.volume_wait(target)['state'] == 'closing'
            assert not http(self.socket, 'GET', '/v1/info')[1]['storage']['available']
            assert http(self.socket, 'POST', '/v1/volumes/' + source['id'] + '/delete', {})[1]['error']['code'] == 'STORAGE_UNCERTAIN'
        finally:
            records.unlink()
            held.rename(records)
        self.restart()
        assert self.volume_wait(target)['state'] == 'failed'
        self.volume_forget(target)
        self.done('volume-publication-failure-fences-mutations-until-recovery')

        session = self.session_open(volumeId=source['id'])
        failure.write_text(session['id'])
        assert http(self.socket, 'POST', '/v1/sessions/' + session['id'] + '/close', {})[0] == 200
        assert self.session_wait(session, terminal=True)['state'] == 'closing'
        assert http(self.socket, 'GET', '/v1/volumes/' + source['id'])[1]['attachedTo'] == session['id']
        assert http(self.socket, 'POST', '/v1/volumes/' + source['id'] + '/delete', {})[1]['error']['code'] == 'VOLUME_IN_USE'
        waiting = self.session_open(wait=False, volumeId=source['id'])
        assert self.session_wait(waiting, terminal=True)['code'] == 'VOLUME_IN_USE'
        self.session_forget(waiting)
        failure.unlink()
        self.restart()
        self.write(source, 'test "$(head -c 1 0x-source.bin)" = A')
        self.done('volume-attachment-survives-unconfirmed-session-cleanup')

        # The protected owner binds the physical delegation; changing it cannot
        # adopt data whose old launchers might still be alive in another tree.
        original = self.config.read_text()
        original_unit = self.unit
        call('systemctl', 'stop', self.unit)
        self.unit = self.name + '-other.service'
        changed_root = self.delegated_root.with_name(self.unit)
        self.config.write_text(original.replace(str(self.delegated_root), str(changed_root)))
        try:
            self.restart()
        except AssertionError:
            assert 'Runtime belongs to another cgroup delegation' in call('journalctl', '-u', self.unit, '--no-pager', '-n', '30').stdout
        else:
            raise AssertionError('changed cleanup namespace adopted existing data')
        finally:
            call('systemctl', 'stop', self.unit, check=False)
            call('systemctl', 'reset-failed', self.unit, check=False)
            self.unit = original_unit
            self.config.write_text(original)
        self.restart()
        assert (self.data / 'volumes' / source['id'] / 'data/0x-source.bin').read_bytes()[0:1] == b'A'
        self.done('volume-namespace-change-preserves-data-and-refuses-startup')
        self.opensandbox_pvc(source)

    def opensandbox_pvc(self, source):
        from http.client import HTTPConnection
        import secrets
        import socket
        original = self.config.read_text()
        with socket.socket() as free:
            free.bind(('127.0.0.1', 0))
            port = free.getsockname()[1]
        token = secrets.token_hex(32)
        key_file = self.root / 'sdk-vol.token'
        key_file.write_text(token + '\n')
        key_file.chmod(0o600)
        endpoint = f'127.0.0.1:{port}'
        self.config.write_text(original.replace('[service]', '[service]\nopensandbox = true', 1)
                               + f'\n[tcp]\nlisten = "{endpoint}"\ntoken_file = {json.dumps(str(key_file))}\n')
        self.restart()
        try:
            def sdk_req(method, path, body=None):
                conn = HTTPConnection(endpoint, timeout=15)
                try:
                    conn.request(method, path, None if body is None else json.dumps(body).encode(),
                                 headers={'OPEN-SANDBOX-API-KEY': token})
                    resp = conn.getresponse()
                    raw = resp.read(65537)
                    return resp.status, json.loads(raw) if raw else None
                finally:
                    conn.close()

            spec = lambda profile, claim: {
                'image': {'uri': profile}, 'entrypoint': ['tail', '-f', '/dev/null'],
                'resourceLimits': {'cpu': '0.25', 'memory': '32Mi'}, 'timeout': 60,
                'volumes': [{'name': 'workspace', 'pvc': {'claimName': claim, 'createIfNotExists': True},
                             'mountPath': '/workspace'}]}
            assert sdk_req('POST', '/v1/sandboxes', spec('python', str(uuid.uuid4())))[0] == 404
            assert sdk_req('POST', '/v1/sandboxes', spec('other', source['id'])) == (
                409, {'code': 'VOLUME_PROFILE_MISMATCH', 'message': 'VOLUME_PROFILE_MISMATCH'})
            status, s1 = sdk_req('POST', '/v1/sandboxes', spec('python', source['id']))
            assert status == 202, s1
            self.session_wait(s1)
            assert http(self.socket, 'GET', '/v1/volumes/' + source['id'])[1]['attachedTo'] == s1['id']
            assert sdk_req('POST', '/v1/sandboxes', spec('python', source['id']))[0] == 409
            run, res = self.session_exec(s1, 'printf xfs-sdk > sdk-vol.txt')
            assert res['state'] == 'succeeded'
            self.forget(run)
            assert sdk_req('DELETE', '/v1/sandboxes/' + s1['id'])[0] == 204
            assert http(self.socket, 'GET', '/v1/volumes/' + source['id'])[1]['attachedTo'] is None
            status, s2 = sdk_req('POST', '/v1/sandboxes', spec('python', source['id']))
            assert status == 202, s2
            self.session_wait(s2)
            run2, res2 = self.session_exec(s2, 'cat sdk-vol.txt')
            assert res2['state'] == 'succeeded' and res2['result']['stdout'] == 'xfs-sdk'
            self.forget(run2)
            assert sdk_req('DELETE', '/v1/sandboxes/' + s2['id'])[0] == 204
            self.done('volume-opensandbox-pvc-attachment-exclusivity-and-persistence')
        finally:
            self.config.write_text(original)
            self.restart()

    def unmount_fixture(self, mount):
        if mount == self.data:
            assert mount == self.root / 'storage/data'
            call('umount', str(mount))
        else:
            super().unmount_fixture(mount)
