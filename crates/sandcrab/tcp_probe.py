#!/usr/bin/env python3
"""Authenticated native TCP acceptance in a disposable service and XFS fixture."""
import argparse
from contextlib import closing
import hashlib
from http.client import HTTPConnection, HTTPResponse
import json
import os
from pathlib import Path
import secrets
import selectors
import shlex
import signal
import socket
import subprocess
import time
import tomllib
import uuid

from events_probe import Events
from file_probe import FileProbe
import native_probe
from native_probe import call, http


def free_address(ip='127.0.0.1'):
    family = socket.AF_INET6 if ':' in ip else socket.AF_INET
    with socket.socket(family) as stream:
        stream.bind((ip, 0))
        return ip, stream.getsockname()[1]


class TcpProbe(FileProbe):
    def __init__(self, binary, tools, report):
        super().__init__(binary, tools, report)
        self.address = free_address()
        self.key = secrets.token_hex(32)
        self.keys = self.root / 'keys'
        self.keys.mkdir(mode=0o755)
        self.token_file = self.keys / 'server.token'
        self.token_file.write_text(self.key + '\n')
        self.token_file.chmod(0o600)
        self.client_token = self.root / 'client.token'
        self.client_token.write_text(self.key + '\n')
        self.client_token.chmod(0o600)
        os.chown(self.client_token, *native_probe.CLIENT)
        self.base_config = self.config.read_text()
        self.configure()
        self.receipt['scope'] = 'Actual native IPv4/IPv6 loopback HTTP, bearer authentication, CLI, file and event transfers; no model, SDK conformance or production cutover'
        self.receipt['tcpProbeSha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    def configure(self):
        ip, port = self.address
        self.authority = f'[{ip}]:{port}' if ':' in ip else f'{ip}:{port}'
        self.url = 'http://' + self.authority
        self.config.write_text(self.base_config + f'\n[tcp]\nlisten = "{self.authority}"\ntoken_file = {json.dumps(str(self.token_file))}\n')

    def headers(self):
        return {'Authorization': 'Bearer ' + self.key}

    def api(self, method, path, data=None, *, headers=None, raw=False):
        body = data if raw else json.dumps(data).encode() if data is not None else None
        fields = self.headers() if headers is None else headers
        fields = {'Content-Type': 'application/octet-stream' if raw else 'application/json', **fields}
        with closing(HTTPConnection(*self.address, timeout=15)) as connection:
            connection.request(method, path, body=body, headers=fields)
            response = connection.getresponse()
            content = response.read(8 * 1024 * 1024 + 1)
            assert len(content) <= 8 * 1024 * 1024
            assert self.key.encode() not in content
            return response.status, dict(response.getheaders()), json.loads(content)

    def cli(self, *args, check=True):
        return call('runuser', '-u', 'daemon', '--', str(self.binary), '--token-file', str(self.client_token),
                    *args, check=check)

    def upload_tcp(self, session, path, content):
        request = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId'], 'sessionId': session['id'],
                   'path': path, 'format': 'raw', 'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()}
        assert self.api('POST', '/v1/uploads', request)[0] == 201
        assert self.api('PUT', f'/v1/uploads/{request["id"]}/content', content, raw=True)[0] == 200
        assert self.api('POST', f'/v1/uploads/{request["id"]}/forget', {})[0] == 200

    def events(self, run, cursor=None):
        connection = socket.create_connection(self.address, timeout=8)
        return Events(self.socket, run, cursor, connection=connection, headers=self.headers())

    def authentication(self):
        assert self.api('GET', '/v1/info')[2] == self.info
        assert json.loads(self.cli('info', '--endpoint', self.url).stdout) == self.info
        env = call('runuser', '-u', 'daemon', '--', 'env', 'SANDCRAB_TOKEN_FILE=' + str(self.client_token),
                   str(self.binary), 'info', '--endpoint', self.url)
        assert json.loads(env.stdout) == self.info
        run = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId'], 'profile': 'python', 'command': ['true']}
        routes = [('GET', '/v1/info', None), ('GET', '/v1/openapi', None), ('POST', '/v1/runs', run),
                  ('GET', f'/v1/runs/{run["id"]}/events', None), ('POST', '/v1/sessions', run),
                  ('POST', f'/v1/sessions/{run["id"]}/snapshot', {'path': '.', 'format': 'tar'}),
                  ('GET', '/v1/uploads', None),
                  ('POST', '/v1/volumes', run), ('POST', '/v1/uploads', run)]
        for fields in [{}, {'Authorization': 'Bearer ' + secrets.token_hex(32)}]:
            for method, path, body in routes:
                status, headers, value = self.api(method, path, body, headers=fields)
                assert (status, value['error']['code']) == (401, 'AUTH_REQUIRED')
                assert headers['WWW-Authenticate'] == 'Bearer' and headers['Connection'] == 'close'
        assert http(self.socket, 'GET', f'/v1/runs/{run["id"]}')[0] == 404
        # Even root over TCP must authenticate. A previous request grants no connection lease.
        with closing(HTTPConnection(*self.address, timeout=10)) as connection:
            connection.request('GET', '/v1/info', headers=self.headers())
            response = connection.getresponse()
            assert response.status == 200
            response.read()
            connection.request('POST', '/v1/runs', json.dumps(run), headers={'Content-Type': 'application/json'})
            response = connection.getresponse()
            assert response.status == 401 and json.loads(response.read())['error']['code'] == 'AUTH_REQUIRED'
        assert http(self.socket, 'GET', f'/v1/runs/{run["id"]}')[0] == 404
        assert self.api('POST', '/v1/runs', {**run, 'uid': 0})[2]['error']['code'] == 'INVALID_REQUEST'
        for fields in [{'Authorization': 'bEaReR ' + self.key}]:
            assert self.api('GET', '/v1/info', headers=fields)[0] == 200
        self.done('tcp-authenticates-every-request-before-admission-without-uid-bypass')

    def expect_continue(self):
        session = self.session_open()
        content = b'authenticated upload'
        request = self.plan(session, 'continued.txt', content)
        route = f'/v1/uploads/{request["id"]}/content'
        with socket.create_connection(self.address, timeout=8) as stream:
            stream.sendall(f'PUT {route} HTTP/1.1\r\nContent-Length: 1073741824\r\nExpect: 100-continue\r\n\r\n'.encode())
            response = HTTPResponse(stream)
            response.begin()
            assert response.status == 401
            assert json.loads(response.read())['error']['code'] == 'AUTH_REQUIRED'
        assert http(self.socket, 'GET', f'/v1/uploads/{request["id"]}')[1]['state'] == 'waiting'
        with socket.create_connection(self.address, timeout=8) as stream:
            stream.sendall(f'PUT {route} HTTP/1.1\r\nAuthorization: Bearer {self.key}\r\nContent-Length: {len(content)}\r\nExpect: 100-continue\r\n\r\n'.encode())
            head = bytearray()
            while not head.endswith(b'\r\n\r\n'):
                head.extend(stream.recv(1))
                assert len(head) <= 8192
            assert head == b'HTTP/1.1 100 Continue\r\n\r\n'
            stream.sendall(content)
            response = HTTPResponse(stream)
            response.begin()
            assert response.status == 200 and json.loads(response.read())['state'] == 'succeeded'
        assert self.api('POST', f'/v1/uploads/{request["id"]}/forget', {})[0] == 200
        self.session_close(session)
        self.session_forget(session)
        self.done('tcp-refuses-unauthenticated-upload-before-body-or-continue')

    def live_events(self):
        session = self.session_open()
        code = 'import os,time\nfrom pathlib import Path\nos.write(1,b"\\xe4")\nwhile not Path("gate").exists(): time.sleep(.02)\nos.write(1,b"\\xb8\\xad\\x00\\xff")'
        run, _ = self.session_exec(session, 'python3 -c ' + shlex.quote(code), wait=False)
        with self.events(run) as first:
            first.until('stdout')
            before, cursor = bytes(first.output[0]), first.cursor
        assert self.api('GET', f'/v1/runs/{run["id"]}')[2]['state'] == 'running'
        with self.events(run, cursor) as resumed:
            self.upload_tcp(session, 'gate', b'go')
            assert resumed.until('result')['state'] == 'succeeded'
            resumed.end()
            assert before + resumed.output[0] == b'\xe4\xb8\xad\x00\xff'
        observed = self.cli('events', '--endpoint', self.url, run['id'], '--after', cursor)
        assert json.loads(observed.stdout.splitlines()[-1])['event'] == 'result'
        self.forget(run)
        self.session_close(session)
        self.session_forget(session)
        self.done('tcp-live-events-and-cli-resume-preserve-binary-output')

    def cli_and_rotation(self):
        volume = json.loads(self.cli('volume', 'create', '--endpoint', self.url, '--profile', 'python').stdout)
        listed = json.loads(self.cli('volume', 'list', '--endpoint', self.url).stdout)
        assert volume['id'] in json.dumps(listed)
        session = json.loads(self.cli('session', 'open', '--endpoint', self.url, '--profile', 'python', '--volume', volume['id']).stdout)
        source = self.root / 'input.bin'
        expected = b'\x00\xffopaque TCP file\xe4\xb8\xad'
        source.write_bytes(expected)
        source.chmod(0o644)
        self.cli('files', 'put', '--endpoint', self.url, session['id'], str(source), 'input.bin')
        destination = self.root / 'client-output'
        destination.mkdir(mode=0o700)
        os.chown(destination, *native_probe.CLIENT)
        downloaded = destination / 'download.bin'
        self.cli('files', 'get', '--endpoint', self.url, session['id'], 'input.bin', str(downloaded))
        assert downloaded.read_bytes() == expected
        self.cli('session', 'renew', '--endpoint', self.url, session['id'], '--ttl-ms', '60000')
        result = self.cli('session', 'exec', '--endpoint', self.url, session['id'], '--stream', '--',
                          'python3 -c ' + shlex.quote('import os; print(any(k.startswith("SANDCRAB_TOKEN") for k in os.environ))'))
        assert result.stdout == 'False\n' and self.key not in result.stdout + result.stderr
        old_key, old_epoch = self.key, self.info['serverId']
        self.key = secrets.token_hex(32)
        self.token_file.write_text(self.key + '\n')
        assert self.api('GET', '/v1/info')[0] == 401
        assert self.api('GET', '/v1/info', headers={'Authorization': 'Bearer ' + old_key})[0] == 200
        self.restart()
        assert self.info['serverId'] != old_epoch and self.api('GET', '/v1/info')[0] == 200
        assert self.api('GET', '/v1/info', headers={'Authorization': 'Bearer ' + old_key})[0] == 401
        self.client_token.write_text(self.key + '\n')
        session = json.loads(self.cli('session', 'open', '--endpoint', self.url, '--profile', 'python', '--volume', volume['id']).stdout)
        self.cli('files', 'get', '--endpoint', self.url, session['id'], 'input.bin', str(downloaded), '--replace')
        assert downloaded.read_bytes() == expected
        self.cli('session', 'close', '--endpoint', self.url, session['id'])
        self.cli('session', 'forget', '--endpoint', self.url, session['id'])
        self.cli('volume', 'delete', '--endpoint', self.url, volume['id'])
        self.cli('volume', 'forget', '--endpoint', self.url, volume['id'])
        log = call('journalctl', '-u', self.unit, '--no-pager', '-o', 'cat').stdout
        assert self.key not in log and old_key not in log
        self.done('tcp-cli-files-volumes-sessions-and-token-rotation-preserve-data')

    def shared_observers(self):
        run = self.submit('import time; time.sleep(60)')
        observers = []
        try:
            for index in range(self.info['limits']['maxEventStreams']):
                observers.append(self.events(run) if index % 2 else Events(self.socket, run))
            for info in [self.api('GET', '/v1/info')[2], http(self.socket, 'GET', '/v1/info')[1]]:
                assert info['events']['activeStreams'] == len(observers)
            status, _, value = self.api('GET', f'/v1/runs/{run["id"]}/events')
            assert (status, value['error']['code']) == (429, 'EVENT_CAPACITY')
            status, value = http(self.socket, 'GET', f'/v1/runs/{run["id"]}/events')
            assert (status, value['error']['code']) == (429, 'EVENT_CAPACITY')
            assert self.api('POST', f'/v1/runs/{run["id"]}/cancel', {})[0] == 200
            for observer in observers:
                assert observer.until('result')['state'] == 'cancelled'
                observer.end()
        finally:
            for observer in observers:
                observer.close()
        self.forget(run)
        self.done('tcp-and-unix-share-observer-admission-and-preserve-control-capacity')

    def cli_cancel(self):
        command = ['runuser', '-u', 'daemon', '--', str(self.binary), '--token-file', str(self.client_token),
                   'run', '--endpoint', self.url, '--profile', 'python', '--stream', '--',
                   'python3', '-c', 'import os,time; os.write(1,b"\\x00\\xffready"); time.sleep(60)']
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                assert selector.select(8), 'TCP CLI did not receive live output'
                assert os.read(process.stdout.fileno(), 7) == b'\x00\xffready'
            os.killpg(process.pid, signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=15)
            assert process.returncode != 0 and stdout == b'' and b'cancelled' in stderr
            assert self.key.encode() not in stderr
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        self.done('tcp-cli-live-output-and-cancellation-use-authenticated-control')

    def protected_credentials(self):
        bad = self.root / 'bad-config.toml'
        def rejected(text, expected):
            bad.write_text(text)
            bad.chmod(0o600)
            result = call(str(self.binary), 'check', '--config', str(bad), check=False)
            assert result.returncode != 0 and expected in result.stderr
            assert self.key not in result.stdout + result.stderr
        for address in ['0.0.0.0:9011', '[::]:9011', 'localhost:9011', '192.0.2.1:9011']:
            rejected(self.config.read_text().replace(self.authority, address), 'loopback')
        rejected(self.config.read_text().replace('"/usr"', json.dumps(str(self.keys))), 'exposes the TCP token')
        alias = self.root / 'key-alias'
        alias.symlink_to(self.keys, target_is_directory=True)
        text = self.config.read_text().replace(str(self.token_file), str(alias / self.token_file.name))
        rejected(text.replace('"/usr"', json.dumps(str(self.keys))), 'Token file ancestors')
        tools = Path(tomllib.loads(self.config.read_text())['profiles']['python']['tools'])
        rejected(self.config.read_text().replace(str(self.token_file), str(tools / 'token')), 'exposes the TCP token')
        self.token_file.chmod(0o644)
        try:
            rejected(self.config.read_text(), 'private')
        finally:
            self.token_file.chmod(0o600)
        self.token_file.chmod(0o700)
        try:
            rejected(self.config.read_text(), 'mode 0400 or 0600')
        finally:
            self.token_file.chmod(0o600)
        self.client_token.chmod(0o644)
        try:
            result = self.cli('info', '--endpoint', self.url, check=False)
            assert result.returncode != 0 and 'private' in result.stderr and self.key not in result.stderr
        finally:
            self.client_token.chmod(0o600)
        link = self.root / 'linked-token'
        link.symlink_to(self.token_file)
        rejected(self.config.read_text().replace(str(self.token_file), str(link)), 'os error 40')
        hard = self.root / 'hard-token'
        os.link(self.token_file, hard)
        try:
            rejected(self.config.read_text(), 'singly linked')
        finally:
            hard.unlink()
        client_alias = self.root / 'client-alias'
        client_alias.symlink_to(self.root, target_is_directory=True)
        result = call('runuser', '-u', 'daemon', '--', str(self.binary), '--token-file', str(client_alias / self.client_token.name),
                      'info', '--endpoint', self.url, check=False)
        assert result.returncode != 0 and 'Token file ancestors' in result.stderr
        self.done('tcp-credentials-reject-insecure-files-mount-aliases-and-nonlocal-listeners')

    def listener_lifecycle(self):
        call('systemctl', 'stop', self.unit)
        with socket.socket() as occupied:
            occupied.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            occupied.bind(self.address)
            occupied.listen()
            try:
                self.start()
            except AssertionError:
                assert not self.socket.exists(), 'TCP bind failure silently left Unix service available'
            else:
                raise AssertionError('Occupied TCP address was accepted')
        self.restart()
        assert self.api('GET', '/v1/info')[0] == 200
        call('systemctl', 'stop', self.unit)
        self.address = free_address('::1')
        self.configure()
        self.restart()
        assert self.api('GET', '/v1/info')[0] == 200
        assert json.loads(self.cli('run', '--endpoint', self.url, '--profile', 'python', '--', 'printf', 'ipv6').stdout)['result']['stdout'] == 'ipv6'
        call('systemctl', 'stop', self.unit)
        self.config.write_text(self.base_config)
        self.restart()
        try:
            socket.create_connection(self.address, timeout=1).close()
        except OSError:
            pass
        else:
            raise AssertionError('TCP stayed enabled without its configuration')
        assert json.loads(self.cli('info', '--socket', str(self.socket)).stdout)['serverId'] == self.info['serverId']
        self.done('tcp-listener-failure-ipv6-and-disabled-default')

    def tests(self):
        self.authentication()
        self.expect_continue()
        self.live_events()
        self.shared_observers()
        self.cli_and_rotation()
        self.cli_cancel()
        self.protected_credentials()
        self.listener_lifecycle()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and not args.report.exists()
    probe = TcpProbe(args.binary.resolve(), args.tools.resolve(), args.report.resolve())
    try:
        probe.setup()
        probe.tests()
        probe.receipt['result'] = 'PASS'
    except BaseException as error:
        probe.receipt.update(result='FAIL', failureType=type(error).__name__)
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
