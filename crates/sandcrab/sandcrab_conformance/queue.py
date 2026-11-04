#!/usr/bin/env python3
"""Real bounded admission, FIFO, no-execution receipts and queued identity lifecycle."""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import uuid

from .native import Probe, call, http
from .events import Events


class QueueProbe(Probe):
    def __init__(self, binary, tools, report):
        super().__init__(binary, tools, report)
        self.config.write_text(self.config.read_text().replace('max_records = 8',
            'max_records = 24\nmax_queued = 4'))
        config = self.config.read_text()
        self.config.write_text(config + '\n[profiles.calls]\n' + config.split('[profiles.python]', 1)[1]
            + 'host_calls = true\n')
        self.receipt['scope'] = 'Real native FIFO and lifecycle with synthetic commands; no model or density measurement'
        self.receipt['probeSha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    def start(self):
        deadline = time.monotonic() + 8
        while call('systemctl', 'show', self.unit, '-p', 'LoadState', '--value').stdout.strip() != 'not-found':
            assert time.monotonic() < deadline, 'Previous transient service was not collected'
            time.sleep(.05)
        super().start()

    def setup(self):
        if hasattr(self, 'sdk_python'):
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                self.endpoint = '127.0.0.1:' + str(listener.getsockname()[1])
            self.token = self.root / 'sdk-token'
            self.token.write_text(os.urandom(32).hex())
            self.token.chmod(0o600)
            self.config.write_text(self.config.read_text().replace('[service]', '[service]\nopensandbox = true')
                + f'\n[tcp]\nlisten = "{self.endpoint}"\ntoken_file = {json.dumps(str(self.token))}\n')
        super().setup()

    def state(self, request, expected):
        deadline = time.monotonic() + 5
        while True:
            status, value = http(self.socket, 'GET', '/v1/runs/' + request['id'])
            assert status == 200, value
            if value['state'] == expected:
                return value
            assert value['state'] in ('queued', 'running') and time.monotonic() < deadline, value
            time.sleep(.01)

    def cancel(self, run):
        assert http(self.socket, 'POST', f'/v1/runs/{run["id"]}/cancel', {})[0] == 200
        assert self.wait(run)['state'] == 'cancelled'
        self.forget(run)

    def finish_session(self, session):
        self.session_close(session)
        self.session_forget(session)

    def assert_refused(self, run):
        value = self.wait(run)
        assert value['state'] == 'refused' and value['result'] == {'code': 'QUEUE_TIMEOUT', 'executed': False}, value
        assert value['queueWaitMillis'] >= 2000, value
        return value

    def finite_fifo(self):
        holder = self.session_open()
        blocker = self.submit('import time; time.sleep(9)')
        first = self.submit('import time; time.sleep(9)')
        second = self.submit('import time; time.sleep(9)')
        reused = self.submit('print("old-payload")')
        fourth = self.submit('print("fourth")')
        for run in (first, second, reused, fourth):
            self.state(run, 'queued')
            assert not (self.socket.parent / 'jobs' / run['id']).exists()
            assert http(self.socket, 'POST', f'/v1/runs/{run["id"]}/forget', {})[1]['error']['code'] == 'RUN_ACTIVE'
        assert http(self.socket, 'GET', '/v1/info')[1]['admission'] == {'activeSandboxes': 2, 'queuedCommands': 4}
        overflow = {**fourth, 'id': str(uuid.uuid4())}
        assert http(self.socket, 'POST', '/v1/runs', overflow) == (429, {'error': {'code': 'QUEUE_CAPACITY'}})
        assert http(self.socket, 'GET', '/v1/runs/' + overflow['id'])[0] == 404
        assert http(self.socket, 'POST', '/v1/runs', first)[0] == 200
        assert http(self.socket, 'POST', '/v1/runs', {**first, 'command': ['false']})[1]['error']['code'] == 'ID_CONFLICT'
        self.cancel_queued(reused)
        reused['command'] = ['python3', '-c', 'print("new-payload")']
        assert http(self.socket, 'POST', '/v1/runs', reused)[0] == 202
        self.cancel_queued(fourth)
        self.cancel(blocker)
        assert self.state(first, 'running')['queueWaitMillis'] > 0
        self.state(second, 'queued')
        self.state(reused, 'queued')
        self.cancel(first)
        self.state(second, 'running')
        self.state(reused, 'queued')
        self.cancel(second)
        assert self.wait(reused)['result']['stdout'] == 'new-payload\n'
        self.forget(reused)
        self.finish_session(holder)
        self.done('finite-fifo-global-cap-and-cancel-forget-id-reuse-without-stale-dispatch')

    def finite_timeout(self):
        holders = [self.session_open(), self.session_open()]
        run = self.submit('print("must-not-execute")', profile='calls')
        self.state(run, 'queued')
        with Events(self.socket, run) as events:
            value = events.until('result')
            assert value['state'] == 'refused' and value['result']['executed'] is False, value
            assert events.output == [bytearray(), bytearray()]
            events.end()
        receipt = self.assert_refused(run)
        calls = call('runuser', '-u', 'daemon', '--', str(self.binary), 'calls', 'events',
                     '--socket', str(self.socket), run['id'])
        frames = [json.loads(line) for line in calls.stdout.splitlines()]
        assert frames[-1]['event'] == 'result' and frames[-1]['data']['calls']['closed'] is True
        assert frames[-1]['data']['calls']['calls'] == []
        assert frames[-1]['data']['run']['result'] == receipt['result']
        for holder in holders:
            self.finish_session(holder)
        assert http(self.socket, 'POST', '/v1/runs', run) == (200, receipt)
        assert not (self.socket.parent / 'jobs' / run['id']).exists()
        self.forget(run)
        self.done('finite-timeout-streams-no-execution-and-replay-remains-terminal-after-capacity-recovers')

    def session_fifo(self):
        session = self.session_open()
        active, _ = self.session_exec(session, 'sleep .5; printf 0 >> order', wait=False)
        queued = [self.session_exec(session, f'printf {index} >> order', wait=False, timeoutMillis=100)[0]
                  for index in (1, 2, 3)]
        for run in queued:
            self.state(run, 'queued')
            assert http(self.socket, 'POST', f'/v1/sessions/{session["id"]}/commands', run)[0] == 200
        for run in [active, *queued]:
            result = self.wait(run)
            assert result['state'] == 'succeeded', result
            if run in queued:
                assert result['queueWaitMillis'] > 0
            self.forget(run)
        assert (self.session_workspace(session) / 'order').read_text() == '0123'
        self.done('session-fifo-replay-once-and-execution-timeout-starts-after-wait')

        active, _ = self.session_exec(session, 'sleep .5; printf active', wait=False)
        old, _ = self.session_exec(session, 'touch old', wait=False)
        self.cancel_queued(old)
        assert http(self.socket, 'GET', f'/v1/sessions/{session["id"]}')[1]['activeRunId'] == active['id']
        replacement = {**old, 'command': 'touch new; printf replacement'}
        assert http(self.socket, 'POST', f'/v1/sessions/{session["id"]}/commands', replacement)[0] == 202
        assert self.wait(active)['result']['stdout'] == 'active'
        assert self.wait(replacement)['result']['stdout'] == 'replacement'
        workspace = self.session_workspace(session)
        assert not (workspace / 'old').exists() and (workspace / 'new').is_file()
        for run in (active, replacement):
            self.forget(run)
        self.finish_session(session)
        self.done('queued-cancel-preserves-active-shell-and-reused-id-never-executes-old-payload')

    def session_timeout(self):
        session = self.session_open()
        active, _ = self.session_exec(session, 'sleep 5; printf active', wait=False)
        run, _ = self.session_exec(session, 'touch forbidden', wait=False)
        self.assert_refused(run)
        args = ['runuser', '-u', 'daemon', '--', str(self.binary), 'session', 'exec', '--socket',
                str(self.socket), session['id'], '--stream', '--', 'touch cli-forbidden']
        cli = call(*args, check=False)
        assert cli.returncode != 0 and not cli.stdout, (cli.returncode, cli.stdout, cli.stderr)
        assert self.wait(active)['result']['stdout'] == 'active'
        assert not (self.session_workspace(session) / 'forbidden').exists()
        assert not (self.session_workspace(session) / 'cli-forbidden').exists()
        assert http(self.socket, 'POST', f'/v1/sessions/{session["id"]}/commands', run)[1]['state'] == 'refused'
        for record in (active, run):
            self.forget(record)
        self.finish_session(session)
        self.done('queued-timeout-native-and-cli-stream-never-run-workspace-effects')

    def starting_and_expiry(self):
        directory = self.root / 'queued-startup'
        directory.mkdir(mode=0o755)
        faults = self.enable_launch_faults(directory)
        faults.arm('launch', 'before')
        session = self.session_open(wait=False)
        faults.wait()
        run, _ = self.session_exec(session, 'touch forbidden-startup', wait=False)
        self.cancel_queued(run)
        faults.release()
        faults.close()
        assert self.session_wait(session)['state'] == 'ready'
        assert not (self.session_workspace(session) / 'forbidden-startup').exists()
        self.finish_session(session)
        self.done('starting-session-queues-and-cancels-before-shell-setup')

        parent = self.session_open(ttlMillis=800)
        active, _ = self.session_exec(parent, 'sleep 9', wait=False)
        queued, _ = self.session_exec(parent, 'touch expired', wait=False)
        result = self.wait(queued)
        assert result['state'] == 'cancelled' and result['result'] == {'code': 'SESSION_EXPIRED', 'executed': False}, result
        assert self.session_wait(parent, terminal=True)['state'] == 'expired'
        self.wait(active)
        for run in (active, queued):
            self.forget(run)
        self.session_forget(parent)
        self.done('session-expiry-cancels-waiters-without-execution')

    def sdk(self):
        if not hasattr(self, 'sdk_python'):
            return
        result = call(str(self.sdk_python), str(self.sdk_client), '--endpoint', self.endpoint,
                      '--token-file', str(self.token), timeout=45)
        receipt = json.loads(result.stdout)
        assert receipt['result'] == 'PASS'
        for identity in receipt['commandIds']:
            assert http(self.socket, 'GET', '/v1/runs/' + identity)[0] == 404
        assert http(self.socket, 'GET', '/v1/sessions/' + receipt['sandboxId'])[0] == 404
        self.receipt['sdk'] = receipt
        self.done('published-python-sdk-default-and-named-context-queue-outcomes-and-reclamation')

    def parent_close(self):
        parent = self.session_open()
        child = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId']}
        assert http(self.socket, 'POST', f'/v1/sessions/{parent["id"]}/shells', child)[0] == 202
        assert self.session_wait(child)['state'] == 'ready'
        active, _ = self.session_exec(child, 'sleep 9', wait=False)
        queued, _ = self.session_exec(child, 'touch closed-parent', wait=False)
        self.session_close(parent)
        result = self.wait(queued)
        assert result['state'] == 'cancelled' and result['result'] == {'code': 'SESSION_CLOSED', 'executed': False}, result
        assert self.session_wait(child, terminal=True)['state'] == 'closed'
        self.wait(active)
        for run in (active, queued):
            self.forget(run)
        self.session_forget(child)
        self.session_forget(parent)
        self.done('parent-close-cancels-child-queue-before-releasing-shared-admission')

    def restart(self):
        active = [self.submit('import time; time.sleep(9)') for _ in range(2)]
        queued = self.submit('print("never-replay")')
        self.state(queued, 'queued')
        epoch = self.info['serverId']
        call('systemctl', 'stop', self.unit)
        self.start()
        assert self.info['serverId'] != epoch
        assert http(self.socket, 'GET', '/v1/info')[1]['admission'] == {'activeSandboxes': 0, 'queuedCommands': 0}
        for run in [*active, queued]:
            assert http(self.socket, 'GET', '/v1/runs/' + run['id'])[0] == 404
        assert http(self.socket, 'POST', '/v1/runs', queued)[1]['error']['code'] == 'SERVER_CHANGED'
        assert not list((self.socket.parent / 'jobs').iterdir())
        self.done('shutdown-drains-queued-payloads-and-new-epoch-never-replays')

        call('systemctl', 'stop', self.unit)
        self.config.write_text(self.config.read_text().replace('[service]', '[service]\nresult_ttl_millis = 1000'))
        self.start()
        holders = [self.session_open(keepResult=True), self.session_open(keepResult=True)]
        transient = self.submit('print("expired-queue")')
        kept = self.submit('print("kept-queue")', keepResult=True)
        time.sleep(1.1)
        for run in (transient, kept):
            self.state(run, 'queued')
        for run in (transient, kept):
            self.assert_refused(run)
        deadline = time.monotonic() + 5
        while http(self.socket, 'GET', f'/v1/runs/{transient["id"]}')[0] != 404:
            assert time.monotonic() < deadline, 'Terminal queued outcome did not expire'
            time.sleep(.05)
        self.assert_refused(kept)
        self.forget(kept)
        for holder in holders:
            self.finish_session(holder)
        self.done('retention-starts-after-queue-completion-and-kept-refusals-survive')

    def tests(self):
        assert self.info['limits']['maxQueued'] == 4 and self.info['limits']['queueTimeoutMillis'] == 2000
        for test in (self.finite_fifo, self.finite_timeout, self.session_fifo, self.session_timeout,
                     self.starting_and_expiry, self.parent_close, self.sdk, self.restart):
            test()
