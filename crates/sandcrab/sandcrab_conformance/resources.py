#!/usr/bin/env python3
"""Verify caller-lowered resource caps in actual sandbox cgroups."""
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time
import uuid

from .native import Probe, call, http


class ResourcesProbe(Probe):
    def limits(self, identity, memory=33554432, cpu=25, session=False):
        deadline = time.monotonic() + 8
        root = self.workloads_group / ('run-' + identity)
        if session:
            status, view = http(self.socket, 'GET', '/v1/sessions/' + identity)
            assert status == 200, view
            parent_identity = view.get('parentSessionId') or identity
            uuid.UUID(parent_identity)
            root = self.workloads_group / ('session-' + parent_identity) / ('run-' + identity)
        while time.monotonic() < deadline:
            if root.is_dir() and 'populated 1' in (root / 'cgroup.events').read_text():
                if (root / 'memory.max').is_file() and (root / 'cpu.max').is_file():
                    page = os.sysconf('SC_PAGE_SIZE')
                    assert memory // page * page <= int((root / 'memory.max').read_text()) <= (memory + page - 1) // page * page
                    quota, period = (root / 'cpu.max').read_text().split()
                    assert int(quota) * 100 == cpu * int(period)
                    if session:
                        parent = root.parent
                        assert parent.name == 'session-' + parent_identity and parent.parent == self.workloads_group
                        assert int((parent / 'memory.max').read_text()) == memory // page * page
                        assert (parent / 'memory.swap.max').read_text().strip() == '0'
                        assert (parent / 'memory.oom.group').read_text().strip() == '0'
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
        assert not group.exists()
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
