#!/usr/bin/env python3
"""Independent shells, shared workspace ownership and real containment failures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

from native_probe import call, http
from resources_probe import ResourcesProbe
from file_probe import binary_http


class ContextsProbe(ResourcesProbe):
    def __init__(self, binary, tools, report):
        super().__init__(binary, tools, report)
        self.receipt['probeSha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    def start(self):
        deadline = time.monotonic() + 8
        while call('systemctl', 'show', self.unit, '-p', 'LoadState', '--value').stdout.strip() != 'not-found':
            assert time.monotonic() < deadline, 'previous transient fixture unit was not collected'
            time.sleep(.05)
        super().start()

    def child(self, parent, wait=True):
        request = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId']}
        status, result = http(self.socket, 'POST', f'/v1/sessions/{parent["id"]}/shells', request)
        assert status == 202, result
        assert result['parentSessionId'] == parent['id'], result
        if wait:
            assert self.session_wait(request)['state'] == 'ready'
        return request

    def execute(self, session, source, expected=None):
        request, result = self.session_exec(session, source)
        assert result['state'] == 'succeeded', result
        if expected is not None:
            assert result['result']['stdout'] == expected, result
        self.forget(request)

    def tests(self):
        status, schema = http(self.socket, 'GET', '/v1/openapi?capability=sessions')
        assert status == 200 and '/v1/sessions/{id}/shells' in schema['paths']
        parent = self.session_open(resources={'memoryBytes': 50331648, 'cpuQuotaPercent': 25})
        first = self.child(parent)
        cli = call('runuser', '-u', 'daemon', '--', str(self.binary), 'session', 'shell',
                   '--socket', str(self.socket), parent['id'])
        second = json.loads(cli.stdout)
        assert second['parentSessionId'] == parent['id'] and second['state'] == 'ready'
        groups = [self.limits(s['id'], memory=50331648, session=True) for s in (parent, first, second)]
        assert groups[0].parent == groups[1].parent == groups[2].parent
        assert len(set(groups)) == 3
        self.done('http-and-cli-shells-share-the-parent-kernel-budget')

        self.execute(parent, 'VALUE=root; printf parent > original')
        self.execute(first, 'VALUE=first; marker() { printf function; }; mkdir project; cd project; '
                     'printf kept > artifact; printf private > /tmp/first')
        self.execute(first, 'printf "%s\\n" "$VALUE"; pwd; marker', 'first\n/workspace/project\nfunction')
        self.execute(second, 'printf "%s\\n" "${VALUE-unset}"; pwd; test ! -e /tmp/first && cat project/artifact',
                     'unset\n/workspace\nkept')
        self.execute(parent, 'printf "%s\\n" "$VALUE"; pwd', 'root\n/workspace\n')
        status, headers, content = binary_http(self.socket, 'POST', f'/v1/sessions/{parent["id"]}/snapshot',
            json.dumps({'path': 'project/artifact', 'format': 'raw', 'freeze': True}).encode())
        assert status == 200 and content == b'kept', (status, content)
        assert headers['ETag'].strip('"') == hashlib.sha256(content).hexdigest()
        assert (groups[0].parent / 'cgroup.freeze').read_text().strip() == '0'
        slow, _ = self.session_exec(first, 'sleep 1; printf concurrent', wait=False)
        self.execute(second, 'cat original', 'parent')
        assert self.wait(slow)['result']['stdout'] == 'concurrent'
        self.forget(slow)
        self.done('shell-state-and-temporary-files-are-independent-with-concurrent-shared-files')

        endpoint = f'/v1/sessions/{parent["id"]}/shells'
        assert http(self.socket, 'POST', endpoint, first)[0] == 200
        for extra, code in [({'serverId': str(uuid.uuid4())}, 'SERVER_CHANGED'),
                            ({'profile': 'python'}, 'INVALID_REQUEST'),
                            ({'resources': {'memoryBytes': 67108864}}, 'INVALID_REQUEST'),
                            ({'id': parent['id']}, 'ID_CONFLICT')]:
            request = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId'], **extra}
            assert http(self.socket, 'POST', endpoint, request)[1]['error']['code'] == code
        assert http(self.socket, 'POST', f'/v1/sessions/{first["id"]}/shells',
                    {'id': str(uuid.uuid4()), 'serverId': self.info['serverId']})[1]['error']['code'] == 'PARENT_SESSION_REQUIRED'
        assert http(self.socket, 'POST', f'/v1/sessions/{first["id"]}/renew',
                    {'ttlMillis': 60000})[1]['error']['code'] == 'RENEW_PARENT_SESSION'
        renewed = http(self.socket, 'POST', f'/v1/sessions/{parent["id"]}/renew', {'ttlMillis': 55000})[1]
        for child in (first, second):
            assert http(self.socket, 'GET', f'/v1/sessions/{child["id"]}')[1]['expiresAtMillis'] == renewed['expiresAtMillis']
        held = [self.session_exec(parent, ':')[0] for _ in range(5)]
        assert http(self.socket, 'POST', endpoint, {'id': str(uuid.uuid4()),
                    'serverId': self.info['serverId']})[1]['error']['code'] == 'RESULT_CAPACITY'
        for run in held:
            self.forget(run)
        self.done('child-identity-inheritance-renewal-and-global-record-bounds')

        timed, _ = self.session_exec(first, 'sleep 30', wait=False, timeoutMillis=100)
        assert self.wait(timed)['state'] == 'timed_out'
        self.forget(timed)
        assert self.session_wait(first, terminal=True)['state'] == 'failed'
        self.session_forget(first)
        self.execute(second, 'cat project/artifact', 'kept')
        self.execute(parent, 'cat original', 'parent')
        self.done('child-timeout-preserves-workspace-and-sibling-shell')

        victim = self.child(parent)
        run, _ = self.session_exec(victim, "python3 -c 'bytearray(128*1024*1024)'", wait=False)
        result = self.wait(run)
        assert result['state'] == 'resource_limit', result
        self.forget(run)
        assert self.session_wait(victim, terminal=True)['state'] == 'failed'
        self.session_forget(victim)
        run, result = self.session_exec(second, '(exit 137)')
        assert result['state'] == 'failed' and result['result']['exitCode'] == 137, result
        self.forget(run)
        self.execute(second, 'cat project/artifact', 'kept')
        self.execute(parent, ':', '')
        self.done('child-oom-does-not-poison-sibling-command-results')

        victim = self.child(parent)
        run, _ = self.session_exec(victim, '(sleep 1; printf escaped > late) & sleep 30', wait=False)
        assert http(self.socket, 'POST', f'/v1/runs/{run["id"]}/cancel', {})[0] == 200
        assert self.wait(run)['state'] == 'cancelled'
        self.forget(run)
        assert self.session_wait(victim, terminal=True)['state'] == 'closed'
        self.session_forget(victim)
        time.sleep(1.1)
        self.execute(parent, 'test ! -e late && cat project/artifact', 'kept')
        self.session_close(second)
        self.session_forget(second)
        self.execute(parent, 'cat project/artifact', 'kept')
        self.session_close(parent)
        self.session_forget(parent)
        self.done('child-cancel-and-close-contain-descendants-without-releasing-parent-storage')

        self.expiry_and_startup()
        self.cleanup_failure()

    def expiry_and_startup(self):
        parent = self.session_open()
        child = self.child(parent)
        run, _ = self.session_exec(child, 'sleep 30', wait=False)
        assert http(self.socket, 'POST', f'/v1/sessions/{parent["id"]}/renew', {'ttlMillis': 300})[0] == 200
        assert self.session_wait(parent, terminal=True)['state'] == 'expired'
        assert self.session_wait(child, terminal=True)['state'] == 'expired'
        assert self.wait(run)['state'] == 'cancelled'
        assert not (self.socket.parent / 'jobs' / parent['id']).exists()
        assert not (self.socket.parent / 'jobs' / child['id']).exists()
        self.forget(run)
        self.session_forget(child)
        self.session_forget(parent)
        self.done('parent-expiry-contains-active-child-before-workspace-release')

        parent = self.session_open()
        child = self.child(parent, wait=False)
        self.session_close(parent)
        assert self.session_wait(child, terminal=True)['state'] == 'closed'
        assert not (self.socket.parent / 'jobs' / child['id']).exists()
        self.session_forget(child)
        self.session_forget(parent)
        self.done('parent-close-during-child-startup-releases-every-owned-root')

    def cleanup_failure(self):
        call('systemctl', 'stop', self.unit)
        helpers = self.root / 'failed-child-cleanup'
        helpers.mkdir(mode=0o755)
        failure = helpers / 'fail-id'
        (helpers / 'umount').write_text(f'''#!/usr/bin/python3
import os, sys
from pathlib import Path
flag = Path({str(failure)!r})
if flag.exists() and Path(sys.argv[-1]).name == flag.read_text():
    raise SystemExit(79)
os.execv('/usr/bin/umount', ['umount', *sys.argv[1:]])
''')
        (helpers / 'umount').chmod(0o755)
        self.launch_path = str(helpers) + ':/usr/bin:/bin'
        self.start()
        parent = self.session_open()
        child = self.child(parent)
        self.execute(parent, 'printf preserved > artifact')
        active, _ = self.session_exec(parent, 'printf running > active; sleep 30; printf escaped > after-fence', wait=False)
        workspace = self.socket.parent / 'jobs' / parent['id'] / 'work'
        deadline = time.monotonic() + 5
        while not (workspace / 'active').exists():
            assert time.monotonic() < deadline, 'parent command did not start'
            time.sleep(.025)
        failure.write_text(child['id'])
        assert http(self.socket, 'POST', f'/v1/sessions/{child["id"]}/close', {})[0] == 200
        assert self.session_wait(child, terminal=True)['state'] == 'closing'
        deadline = time.monotonic() + 5
        while http(self.socket, 'GET', f'/v1/sessions/{parent["id"]}')[1]['state'] != 'closing':
            assert time.monotonic() < deadline, 'workspace fence did not cancel the active parent command'
            time.sleep(.025)
        assert http(self.socket, 'GET', f'/v1/runs/{active["id"]}')[1]['state'] == 'closing'
        assert (workspace / 'artifact').read_text() == 'preserved'
        assert not (workspace / 'after-fence').exists()
        assert http(self.socket, 'POST', f'/v1/sessions/{child["id"]}/forget', {})[1]['error']['code'] == 'SESSION_ACTIVE'
        other = self.session_open()
        assert http(self.socket, 'POST', '/v1/sessions', {**other, 'id': str(uuid.uuid4())})[1]['error']['code'] == 'SESSION_CAPACITY'
        self.session_close(other)
        self.session_forget(other)
        failure.unlink()
        call('systemctl', 'stop', self.unit, check=False)
        call('systemctl', 'reset-failed', self.unit, check=False)
        # Uncertain child units can retain a reference to the stopped transient
        # supervisor. Restart that same unit to exercise the daemon's recovery.
        result = call('systemctl', 'start', self.unit, check=False)
        if result.returncode:
            assert call('systemctl', 'show', self.unit, '-p', 'LoadState', '--value').stdout.strip() == 'not-found', result
            self.start()
        else:
            self.wait_ready()
        assert not list((self.socket.parent / 'jobs').iterdir())
        parents = [self.session_open(), self.session_open()]
        for parent in parents:
            self.session_close(parent)
            self.session_forget(parent)
        self.done('uncertain-child-cleanup-fences-parent-storage-and-admission-until-restart')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0
    assert not args.report.exists(), 'preserve previous evidence'
    probe = ContextsProbe(args.binary.resolve(), args.tools.resolve(), args.report.resolve())
    try:
        probe.setup()
        probe.tests()
        probe.receipt['result'] = 'PASS'
    except BaseException as error:
        probe.receipt['result'] = 'FAIL'
        probe.receipt['failureType'] = type(error).__name__
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
