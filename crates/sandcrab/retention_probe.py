#!/usr/bin/env python3
"""Result expiry, retained identities and restart cleanup through the real native API."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

from native_probe import Probe, call, http
from file_probe import binary_http


class RetentionProbe(Probe):
    def __init__(self, binary, tools, report):
        super().__init__(binary, tools, report)
        text = self.config.read_text().replace('max_records = 8', 'max_records = 32')
        self.config.write_text(text.replace('[profiles.python]', 'result_ttl_millis = 1000\n[profiles.python]', 1))
        self.receipt['scope'] = 'Native terminal result retention; synthetic data, no capacity measurement'
        self.receipt['probeSha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    def start(self):
        deadline = time.monotonic() + 8
        while call('systemctl', 'show', self.unit, '-p', 'LoadState', '--value').stdout.strip() != 'not-found':
            assert time.monotonic() < deadline, 'Previous transient service was not collected'
            time.sleep(.05)
        super().start()

    def gone(self, collection, record):
        deadline = time.monotonic() + 6
        while http(self.socket, 'GET', f'/v1/{collection}/{record["id"]}')[0] != 404:
            assert time.monotonic() < deadline, f'{collection} result did not expire'
            time.sleep(.05)

    def retained(self, collection, record):
        assert http(self.socket, 'GET', f'/v1/{collection}/{record["id"]}')[0] == 200

    def upload(self, session, name, content, kept=False, send=True):
        plan = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId'], 'sessionId': session['id'],
                'path': name, 'format': 'raw', 'bytes': len(content),
                'sha256': hashlib.sha256(content).hexdigest(), 'keepResult': kept}
        assert http(self.socket, 'POST', '/v1/uploads', plan)[0] == 201
        if send:
            status, _, raw = binary_http(self.socket, 'PUT', f'/v1/uploads/{plan["id"]}/content', content)
            assert status == 200 and json.loads(raw)['state'] == 'succeeded', raw
        return plan

    def tests(self):
        assert self.info['limits']['resultTtlMillis'] == 1000
        parent = self.session_open(keepResult=True)
        run, _ = self.session_exec(parent, 'printf once >> counter', keepResult=False)
        self.gone('runs', run)
        _, result = self.session_exec(parent, 'cat counter')
        assert result['result']['stdout'] == 'once'
        self.done('terminal-command-expires-without-replay-or-closing-its-session')

        cli = call('runuser', '-u', 'daemon', '--', str(self.binary), 'run', '--socket', str(self.socket),
                   '--profile', 'python', '--keep-result', '--', 'python3', '-c', 'print(42)')
        kept = json.loads(cli.stdout)
        discarded = self.submit('print(1)')
        assert self.wait(discarded)['state'] == 'succeeded'
        self.gone('runs', discarded)
        self.retained('runs', kept)
        self.forget(kept)
        self.done('cli-retention-is-honored-and-explicit-forget-releases-it')

        transient = self.session_open()
        time.sleep(1.1)
        self.retained('sessions', transient)
        self.session_close(transient)
        self.gone('sessions', transient)
        self.done('session-result-ttl-begins-after-confirmed-close')

        cli = call('runuser', '-u', 'daemon', '--', str(self.binary), 'session', 'shell', '--socket',
                   str(self.socket), parent['id'], '--keep-result')
        child = json.loads(cli.stdout)
        self.session_close(child)
        discarded = self.submit('print(2)')
        self.wait(discarded)
        self.gone('runs', discarded)
        self.retained('sessions', child)
        self.session_forget(child)
        self.done('retained-child-shell-result-is-independent-of-parent-workspace')

        waiting = self.upload(parent, 'waiting', b'waiting', send=False)
        time.sleep(1.1)
        assert http(self.socket, 'GET', f'/v1/uploads/{waiting["id"]}')[1]['state'] == 'waiting'
        assert http(self.socket, 'POST', f'/v1/uploads/{waiting["id"]}/cancel', {})[0] == 200
        self.gone('uploads', waiting)
        successful = self.upload(parent, 'artifact', b'preserved')
        pinned = self.upload(parent, 'retained', b'retained', kept=True)
        self.gone('uploads', successful)
        assert self.session_exec(parent, 'cat artifact')[1]['result']['stdout'] == 'preserved'
        self.retained('uploads', pinned)
        self.done('upload-expiry-preserves-workspace-data-and-keeps-waiting-or-pinned-records')

        restart = self.upload(parent, 'restart', b'done')
        call('systemctl', 'stop', self.unit)
        time.sleep(1.1)
        self.start()
        self.gone('uploads', restart)
        self.retained('uploads', pinned)
        assert http(self.socket, 'POST', f'/v1/uploads/{pinned["id"]}/forget', {})[0] == 200
        self.done('upload-retention-survives-restart-without-resetting-age')


def main():
    parser = argparse.ArgumentParser()
    for name in ('binary', 'tools', 'report'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and not args.report.exists()
    probe = RetentionProbe(args.binary.resolve(), args.tools.resolve(), args.report.resolve())
    try:
        probe.setup()
        probe.tests()
        probe.receipt['result'] = 'PASS'
    except BaseException as error:
        probe.receipt.update(result='FAIL', failureType=type(error).__name__)
        detail = str(error)
        if isinstance(error, subprocess.CalledProcessError):
            detail += '\n' + (error.stdout or '') + '\n' + (error.stderr or '')
        args.report.with_suffix('.diagnostic.txt').write_text(detail)
        raise
    finally:
        try:
            probe.cleanup()
        finally:
            probe.save()


if __name__ == '__main__':
    main()
