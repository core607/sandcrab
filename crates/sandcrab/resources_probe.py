#!/usr/bin/env python3
"""Verify caller-lowered resource caps in actual sandbox cgroups."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time
import uuid

from native_probe import Probe, call, http


class ResourcesProbe(Probe):
    def limits(self, identity, memory=33554432, cpu=25, session=False):
        deadline = time.monotonic() + 8
        unit = f'{self.name}-{identity}.service'
        while time.monotonic() < deadline:
            properties = dict(line.split('=', 1) for line in call('systemctl', 'show', unit, '-p',
                              'ControlGroup', '-p', 'ActiveState', check=False).stdout.splitlines() if '=' in line)
            group = properties.get('ControlGroup')
            if group and properties.get('ActiveState') == 'active':
                root = Path('/sys/fs/cgroup') / group.lstrip('/')
                if (root / 'memory.max').is_file() and (root / 'cpu.max').is_file():
                    page = os.sysconf('SC_PAGE_SIZE')
                    assert memory // page * page <= int((root / 'memory.max').read_text()) <= (memory + page - 1) // page * page
                    quota, period = (root / 'cpu.max').read_text().split()
                    assert int(quota) * 100 == cpu * int(period)
                    if session:
                        parent = root.parent
                        assert parent.name.endswith('.slice') and parent.name != self.slice
                        assert int((parent / 'memory.max').read_text()) == memory // page * page
                        assert (parent / 'memory.swap.max').read_text().strip() == '0'
                        assert (root / 'memory.oom.group').read_text().strip() == '1'
                        assert int((parent / 'pids.max').read_text()) == int((root / 'pids.max').read_text())
                        quota, period = (parent / 'cpu.max').read_text().split()
                        assert int(quota) * 100 == cpu * int(period)
                    return root
            time.sleep(.025)
        raise AssertionError('Sandbox did not publish its effective cgroup limits')

    def cancel(self, run):
        assert http(self.socket, 'POST', f'/v1/runs/{run["id"]}/cancel', {})[0] == 200
        assert self.wait(run)['state'] == 'cancelled'
        self.forget(run)

    def tests(self):
        profile = self.info['profiles']['python']
        assert profile['memoryBytes'] == 67108864
        assert profile['minimumMemoryBytes'] == 16777216
        assert profile['cpuQuotaPercent'] == 50
        resources = {'memoryBytes': 33554432, 'cpuQuotaPercent': 25}
        self.done('profile-resource-caps-and-memory-floor-are-discoverable')

        run = self.submit('import time; time.sleep(30)', resources=resources)
        self.limits(run['id'])
        changed = {**run, 'resources': {**resources, 'cpuQuotaPercent': 30}}
        assert http(self.socket, 'POST', '/v1/runs', changed)[1]['error']['code'] == 'ID_CONFLICT'
        self.cancel(run)
        self.done('finite-resource-caps-reach-the-kernel-and-bind-replay-identity')

        session = self.session_open(resources=resources)
        group = self.limits(session['id'], session=True).parent
        run, result = self.session_exec(session, 'printf bounded')
        assert result['state'] == 'succeeded' and result['result']['stdout'] == 'bounded'
        self.forget(run)
        self.session_close(session)
        assert not any(path.read_text().strip() for path in group.rglob('cgroup.procs'))
        assert call('systemctl', 'show', group.name, '-p', 'ActiveState', '--value').stdout.strip() == 'inactive'
        self.session_forget(session)
        self.done('session-resource-caps-reach-the-kernel-for-its-lifetime')

        session = self.session_open(resources={**resources, 'memoryBytes': 33554433})
        self.limits(session['id'], memory=33554433, session=True)
        self.session_close(session)
        self.session_forget(session)
        self.done('session-aggregate-memory-cap-rounds-down-to-a-kernel-page')

        for invalid, code in [({'memoryBytes': 67108865}, 'PROFILE_LIMIT'),
                              ({'memoryBytes': 16777215}, 'PROFILE_LIMIT'),
                              ({'cpuQuotaPercent': 51}, 'PROFILE_LIMIT'),
                              ({'cpuQuotaPercent': 0}, 'PROFILE_LIMIT'),
                              ({'cpuQuotaPercent': 0.5}, 'INVALID_REQUEST'),
                              ({'uid': 0}, 'INVALID_REQUEST')]:
            for endpoint in ['runs', 'sessions']:
                identity = str(uuid.uuid4())
                request = {'id': identity, 'serverId': self.info['serverId'],
                           'profile': 'python', 'resources': invalid}
                if endpoint == 'runs':
                    request['command'] = ['true']
                status, value = http(self.socket, 'POST', '/v1/' + endpoint, request)
                assert status == 400 and value['error']['code'] == code, value
                assert http(self.socket, 'GET', f'/v1/{endpoint}/{identity}')[0] == 404
        self.done('resource-escalation-and-invalid-caps-refuse-before-admission')

        cli = ['runuser', '-u', 'daemon', '--', str(self.binary)]
        flags = ['--socket', str(self.socket), '--profile', 'python',
                 '--memory-bytes', '33554432', '--cpu-percent', '25']
        process = subprocess.Popen([*cli, 'run', *flags, '--keep-result', '--', 'sleep', '30'],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stderr, selectors.EVENT_READ)
                assert selector.select(8), 'CLI did not dispatch the run'
                identity = process.stderr.readline(256).decode().strip().removeprefix('runId=')
            uuid.UUID(identity)
            self.limits(identity)
            assert http(self.socket, 'POST', f'/v1/runs/{identity}/cancel', {})[0] == 200
            out, _ = process.communicate(timeout=15)
            assert process.returncode != 0 and json.loads(out)['state'] == 'cancelled'
            self.forget({'id': identity})
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=10)
        session = json.loads(call(*cli, 'session', 'open', *flags).stdout)
        self.limits(session['id'], session=True)
        self.session_close(session)
        self.session_forget(session)
        self.done('ordinary-cli-run-and-session-options-enforce-lower-kernel-limits')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and not args.report.exists()
    probe = ResourcesProbe(args.binary.resolve(), args.tools.resolve(), args.report.resolve())
    probe.receipt['resourcesProbeSha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    try:
        probe.setup()
        probe.tests()
        probe.receipt['result'] = 'PASS'
    except BaseException as error:
        probe.receipt.update(result='FAIL', failureType=type(error).__name__)
        args.report.with_suffix('.diagnostic.txt').write_text(str(error))
        raise
    finally:
        try:
            probe.cleanup()
        finally:
            probe.save()


if __name__ == '__main__':
    main()
