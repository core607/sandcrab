#!/usr/bin/env python3
"""Ordinary streaming uploads through the real authenticated native API and CLI."""
import hashlib
from http.client import HTTPResponse
import json
import os
from pathlib import Path
import socket
import subprocess
import uuid

from . import native as native_probe
from .native import Probe, call, connect, http
from .file import binary_http


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

    def raw_get(self, route, extra=''):
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(15)
            connect(stream, self.socket)
            headers = f'{extra}\r\n' if extra else ''
            stream.sendall(f'GET {route} HTTP/1.1\r\nHost: sandcrab\r\nConnection: close\r\n{headers}\r\n'.encode())
            response = HTTPResponse(stream)
            response.begin()
            data = response.read(1048577)
            assert len(data) <= 1048576
            return response.status, {k.lower(): v for k, v in response.getheaders()}, data

    def workspace_operations(self, parent, workspace):
        status, schema = http(self.socket, 'GET', '/v1/openapi?capability=files')
        assert status == 200 and len(json.dumps({'status': status, 'body': schema}, separators=(',', ':'))) < 20000
        for route in ('/v1/sessions/{id}/files', '/v1/sessions/{id}/files/mkdir',
                      '/v1/sessions/{id}/files/list', '/v1/sessions/{id}/files/search'):
            assert route in schema['paths'], route
        assert 'get' in schema['paths']['/v1/sessions/{id}/files']

        missing = self.request(f'/v1/sessions/{parent["id"]}/files?path=missing-parent/item.txt', b'blocked', 404)
        assert missing['error']['code'] == 'FILE_NOT_FOUND' and not (workspace / 'missing-parent').exists()
        lines = b'one\r\ntwo\r\nthree\r\n'
        self.request(f'/v1/sessions/{parent["id"]}/files?path=created-parent/nested/item.txt&parents=true&mode=416', lines)
        assert (workspace / 'created-parent').stat().st_mode & 0o777 == 0o755
        assert (workspace / 'created-parent/nested/item.txt').stat().st_mode & 0o777 == 0o640
        before = (workspace / 'artifact').read_bytes()
        for bad in ('artifact/under-file', 'link/under-link'):
            refused = self.request(f'/v1/sessions/{parent["id"]}/files?path={bad}&parents=true', b'blocked', 400)
            assert refused['error']['code'] == 'INVALID_PATH'
        assert (workspace / 'artifact').read_bytes() == before
        self.done('streaming-parents-create-missing-directories-and-refuse-file-or-symlink-ancestors')

        status, created = http(self.socket, 'POST', f'/v1/sessions/{parent["id"]}/files/mkdir',
                               {'path': 'inspected/sub', 'mode': 488})
        assert status == 200 and created == {'path': 'inspected/sub', 'created': True}
        status, listed = http(self.socket, 'GET', f'/v1/sessions/{parent["id"]}/files/list?path=.&depth=2')
        assert status == 200
        by_path = {entry['path']: entry for entry in listed['entries']}
        assert all(not path.startswith('/') for path in by_path)
        assert by_path['created-parent']['type'] == 'directory' and by_path['created-parent']['mode'] == 493
        assert by_path['inspected/sub']['type'] == 'directory' and by_path['inspected/sub']['mode'] == 488
        assert by_path['link']['type'] == 'symlink'
        status, matched = http(self.socket, 'GET', f'/v1/sessions/{parent["id"]}/files/search?path=.&pattern=*.txt')
        assert status == 200 and [entry['path'] for entry in matched['entries']] == ['created-parent/nested/item.txt']
        self.done('native-mkdir-list-and-search-report-relative-paths-and-decimal-modes')

        read_route = f'/v1/sessions/{parent["id"]}/files?path=created-parent/nested/item.txt'
        status, headers, full = self.raw_get(read_route)
        assert status == 200 and full == lines
        assert headers['x-sandcrab-server-id'] == parent['serverId']
        assert headers['etag'] == '"' + hashlib.sha256(lines).hexdigest() + '"'
        assert headers['accept-ranges'] == 'bytes'
        status, headers, part = self.raw_get(read_route, 'Range: bytes=0-2')
        assert status == 206 and part == b'one' and headers['content-range'] == f'bytes 0-2/{len(lines)}'
        assert 'etag' not in headers
        assert self.raw_get(read_route, 'Range: bytes=99-')[0] == 416
        assert self.raw_get(read_route, 'Range: bytes=0-2\r\nIf-Range: "0"')[0] == 400
        status, headers, selected = self.raw_get(read_route + '&offset=2&limit=2')
        assert status == 200 and selected == b'two\nthree' and headers['content-type'].startswith('text/plain')
        assert 'etag' not in headers
        for invalid_query in ('%2Fworkspace%2Fartifact', 'link', 'created-parent/nested/item.txt&offset=1'):
            extra = 'Range: bytes=0-1' if 'offset=' in invalid_query else ''
            assert self.raw_get(f'/v1/sessions/{parent["id"]}/files?path={invalid_query}', extra)[0] == 400
        self.done('native-file-read-supports-full-etag-byte-ranges-and-normalized-lines')

        local = self.root / 'cli-local'
        local.mkdir(mode=0o750)
        os.chown(local, *native_probe.CLIENT)
        src = local / 'lines.txt'
        src.write_bytes(lines)
        src.chmod(0o644)
        dest = local / 'downloaded.txt'
        cli = ['runuser', '-u', 'daemon', '--', str(self.binary), 'files']
        assert json.loads(call(*cli, 'mkdir', '--socket', str(self.socket), parent['id'], 'cli-dir/sub', '--mode', '750').stdout)['created'] is True
        assert json.loads(call(*cli, 'put', '--socket', str(self.socket), parent['id'], str(src), 'cli-parents/a/b.txt', '--parents', '--mode', '640').stdout)['bytes'] == len(lines)
        entries = json.loads(call(*cli, 'ls', '--socket', str(self.socket), parent['id'], 'cli-parents', '--depth', '2').stdout)['entries']
        assert [entry['path'] for entry in entries] == ['cli-parents/a', 'cli-parents/a/b.txt']
        found = json.loads(call(*cli, 'search', '--socket', str(self.socket), parent['id'], '*.txt', '--path', 'cli-parents').stdout)['entries']
        assert [entry['path'] for entry in found] == ['cli-parents/a/b.txt']
        assert subprocess.run([*cli, 'read', '--socket', str(self.socket), parent['id'], 'cli-parents/a/b.txt'],
                              check=True, capture_output=True, timeout=30).stdout == lines
        assert call(*cli, 'read', '--socket', str(self.socket), parent['id'], 'cli-parents/a/b.txt', '--bytes', '0-2').stdout == 'one'
        assert call(*cli, 'read', '--socket', str(self.socket), parent['id'], 'cli-parents/a/b.txt', '--offset', '2', '--limit', '1').stdout == 'two'
        assert json.loads(call(*cli, 'read', '--socket', str(self.socket), parent['id'], 'cli-parents/a/b.txt', str(dest)).stdout)['sha256'] == hashlib.sha256(lines).hexdigest()
        assert dest.read_bytes() == lines
        dest.write_bytes(b'keep')
        assert call(*cli, 'read', '--socket', str(self.socket), parent['id'], 'cli-parents/a/b.txt', str(dest), check=False).returncode != 0
        assert dest.read_bytes() == b'keep'
        call(*cli, 'read', '--socket', str(self.socket), parent['id'], 'cli-parents/a/b.txt', str(dest), '--replace')
        assert dest.read_bytes() == lines
        assert json.loads(call(*cli, 'rm', '--socket', str(self.socket), parent['id'], 'cli-parents', '--recursive').stdout)['deleted'] is True
        assert not (workspace / 'cli-parents').exists()
        self.done('cli-files-mkdir-ls-search-read-parents-and-rm-roundtrip')

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
        self.workspace_operations(parent, workspace)

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
