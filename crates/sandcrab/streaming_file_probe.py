#!/usr/bin/env python3
"""Ordinary streaming uploads through the real authenticated native API and CLI."""
import argparse
import hashlib
from http.client import HTTPResponse
import json
import os
from pathlib import Path
import socket
import subprocess
import uuid

from native_probe import Probe, call, connect, http
from file_probe import binary_http


def header(stream):
    data = bytearray()
    while not data.endswith(b'\r\n\r\n'):
        part = stream.recv(1)
        assert part and len(data) < 16384, 'Missing bounded response header'
        data.extend(part)
    return bytes(data)


class StreamingProbe(Probe):
    def __init__(self, binary, tools, report):
        super().__init__(binary, tools, report)
        with socket.socket() as port:
            port.bind(('127.0.0.1', 0))
            self.port = port.getsockname()[1]
        token = self.root / 'token'
        token.write_text(uuid.uuid4().hex + uuid.uuid4().hex)
        token.chmod(0o600)
        self.config.write_text(self.config.read_text().replace('[profiles.python]',
            'max_file_transfers = 1\n[profiles.python]\ntransfer_bytes = 1048576', 1)
            + f'\n[tcp]\nlisten = "127.0.0.1:{self.port}"\ntoken_file = "{token}"\n')
        self.receipt['scope'] = 'Native streaming file safety and CLI; synthetic data, no capacity measurement'
        self.receipt['probeSha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    def request(self, route, content, expected=200):
        status, _, raw = binary_http(self.socket, 'PUT', route, content)
        value = json.loads(raw)
        assert status == expected, (status, value)
        if status == 200:
            assert value['bytes'] == len(content)
            assert value['sha256'] == hashlib.sha256(content).hexdigest()
        return value

    def custom(self, route, framing, payload, method='PUT'):
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(15)
            connect(stream, self.socket)
            stream.sendall(f'{method} {route} HTTP/1.1\r\nHost: sandcrab\r\nConnection: close\r\n{framing}\r\n\r\n'.encode() + payload)
            stream.shutdown(socket.SHUT_WR)
            response = HTTPResponse(stream)
            response.begin()
            return response.status, json.loads(response.read(65537))

    def tests(self):
        parent = self.session_open()
        route = f'/v1/sessions/{parent["id"]}/files?path=artifact'
        workspace = self.session_workspace(parent)
        self.request(route, b'original')
        self.request(route+'&replace=false', b'refused', 409)
        assert (workspace / 'artifact').read_bytes() == b'original'
        self.request(route, b'')
        assert (workspace / 'artifact').read_bytes() == b''
        self.done('single-put-installs-replaces-and-preserves-on-refusal')

        content = 'streamed snow: 雪\n'.encode() * 4096
        chunks = b''.join(f'{len(part):x}\r\n'.encode()+part+b'\r\n'
                          for part in (content[:123], content[123:4096], content[4096:])) + b'0\r\n\r\n'
        status, value = self.custom(route, 'Transfer-Encoding: chunked', chunks)
        assert status == 200 and value['sha256'] == hashlib.sha256(content).hexdigest(), value
        assert (workspace / 'artifact').read_bytes() == content
        assert http(self.socket, 'GET', '/v1/uploads')[1]['uploads'] == []
        self.done('chunked-content-streams-without-a-retained-upload-record')

        for framing, payload in [('Content-Length: 20', b'partial'),
                                 ('Transfer-Encoding: chunked', b'4\r\npart\r\n')]:
            status, value = self.custom(route, framing, payload)
            assert status == 400 and value['error']['code'] == 'CONTENT_INCOMPLETE', value
            assert (workspace / 'artifact').read_bytes() == content
        assert self.custom(route, 'Transfer-Encoding: chunked', b'0\r\n\r\n', method='GET')[0] == 400
        self.done('incomplete-bodies-and-unexpected-chunked-methods-cannot-publish')

        with socket.create_connection(('127.0.0.1', self.port), timeout=10) as stream:
            stream.sendall(f'PUT {route} HTTP/1.1\r\nContent-Length: 10\r\nExpect: 100-continue\r\n\r\n'.encode())
            assert header(stream).startswith(b'HTTP/1.1 401 ')
        for query in ('../outside', '%2Fetc%2Fpasswd', 'link/file'):
            if query == 'link/file':
                (workspace / 'link').symlink_to('/etc')
            self.request(f'/v1/sessions/{parent["id"]}/files?path={query}', b'blocked', 400)
        status, value = self.custom(route, 'Content-Length: 1048577\r\nExpect: 100-continue', b'')
        assert status == 413 and value['error']['code'] == 'FILE_LIMIT', value
        oversized = b'100001\r\n' + b'x' * 1048577 + b'\r\n0\r\n\r\n'
        assert self.custom(route, 'Transfer-Encoding: chunked', oversized)[0] == 413
        assert (workspace / 'artifact').read_bytes() == content
        self.done('authentication-paths-and-fixed-or-chunked-size-limits-are-enforced')

        source = self.root / 'source.bin'
        source.write_bytes(b'CLI raw bytes')
        source.chmod(0o644)
        cli = call('runuser', '-u', 'daemon', '--', str(self.binary), 'files', 'put', '--socket',
                   str(self.socket), parent['id'], str(source), 'cli 雪+name.bin', '--mode', '640')
        result = json.loads(cli.stdout)
        assert result['sha256'] == hashlib.sha256(source.read_bytes()).hexdigest()
        assert 'uploadId=' not in cli.stderr
        target = workspace / 'cli 雪+name.bin'
        assert target.read_bytes() == source.read_bytes() and target.stat().st_mode & 0o777 == 0o640
        assert http(self.socket, 'GET', '/v1/uploads')[1]['uploads'] == []
        self.done('ordinary-cli-upload-uses-one-request-and-preserves-unicode-and-mode')

        child = self.session_open()
        child_route = f'/v1/sessions/{child["id"]}/files?path=partial'
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(15)
            connect(stream, self.socket)
            stream.sendall(f'PUT {child_route} HTTP/1.1\r\nContent-Length: 4096\r\nExpect: 100-continue\r\n\r\n'.encode())
            assert header(stream).startswith(b'HTTP/1.1 100 ')
            busy = self.request(route, b'busy', 429)
            assert busy['error']['code'] == 'FILE_CAPACITY'
            assert http(self.socket, 'POST', f'/v1/sessions/{child["id"]}/close', {})[0] == 200
            response = HTTPResponse(stream)
            response.begin()
            assert response.status == 409, response.read()
        assert self.session_wait(child, terminal=True)['state'] == 'closed'
        self.session_forget(child)
        self.request(route, b'recovered')
        assert not list(self.socket.parent.rglob('.transfer-*'))
        self.done('session-close-cancels-a-stalled-body-and-releases-transfer-admission')
        self.session_close(parent)
        self.session_forget(parent)


def main():
    parser = argparse.ArgumentParser()
    for name in ('binary', 'tools', 'report'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and not args.report.exists()
    probe = StreamingProbe(args.binary.resolve(), args.tools.resolve(), args.report.resolve())
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
