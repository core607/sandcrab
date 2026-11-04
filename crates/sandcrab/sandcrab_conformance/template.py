#!/usr/bin/env python3
"""Template import, deduplication and restart through the real native API and CLI."""
import hashlib
from http.client import HTTPResponse
import json
import os
from pathlib import Path
import socket
import subprocess
import tarfile

from .native import call, connect, http
from .file import FileProbe, archive, binary_http
from .streaming_file import StreamingProbe, header


class TemplateProbe(StreamingProbe):
    restart = FileProbe.restart

    def __init__(self, binary, tools, report):
        super().__init__(binary, tools, report)
        self.config.write_text(self.config.read_text().replace('[profiles.python]',
            'max_templates = 2\ntemplate_pool_bytes = 1048576\n[profiles.python]', 1))
        self.receipt['scope'] = 'Native template import and durable object lifecycle; no overlay or capacity claim'
        self.receipt['probeSha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    def put(self, data, expected=200):
        status, _, content = binary_http(self.socket, 'POST', '/v1/templates?profile=python', data)
        value = json.loads(content)
        assert status == expected, (status, value)
        return value

    def no_stages(self):
        assert not list((self.socket.parent / 'templates/incoming').iterdir())

    def tests(self):
        entries = [('z', tarfile.REGTYPE, b'same', 0o644),
                   ('a', tarfile.REGTYPE, b'same', 0o644),
                   ('script', tarfile.REGTYPE, b'#!/bin/sh\necho template\n', 0o755),
                   ('link', tarfile.SYMTYPE, 'a', 0o777)]
        first = self.put(archive(entries))
        assert len(first['id']) == 64 and first['entries'] == 4 and first['uid'] != 0
        assert self.put(archive(list(reversed(entries)))) == first
        assert http(self.socket, 'GET', '/v1/templates')[1]['templates'] == [first]
        base = self.socket.parent / 'templates/objects' / first['id'] / 'lower/data/a'
        assert call('runuser', '-u', 'nobody', '--', 'python3', '-c',
                    'from pathlib import Path; import sys; Path(sys.argv[1]).write_bytes(b"changed")',
                    str(base), check=False).returncode != 0
        assert base.read_bytes() == b'same'
        self.no_stages()
        self.done('template-tree-id-deduplicates-equivalent-tar-orderings')

        changed = entries.copy()
        changed[0] = ('z', tarfile.LNKTYPE, 'a', 0o644)
        linked = self.put(archive([changed[1], changed[0], *changed[2:]]))
        assert linked['id'] != first['id'] and linked['bytes'] == first['bytes'] - 4
        self.put(archive([('third', tarfile.REGTYPE, b'extra', 0o644)]), 507)
        assert self.put(archive(entries)) == first
        assert http(self.socket, 'DELETE', '/v1/templates/'+linked['id'])[0] == 200
        changed = entries.copy()
        changed[0] = ('z', tarfile.REGTYPE, b'same', 0o755)
        mode = self.put(archive(changed))
        assert mode['id'] != first['id']
        assert http(self.socket, 'DELETE', '/v1/templates/'+mode['id'])[0] == 200
        self.no_stages()
        self.done('template-identity-preserves-mode-and-hardlink-semantics-with-bounded-count')

        for entries_bad in [
            [('../outside', tarfile.REGTYPE, b'escape', 0o644)],
            [('a', tarfile.REGTYPE, b'one', 0o644), ('a', tarfile.REGTYPE, b'two', 0o644)],
            [('escape', tarfile.SYMTYPE, '/tmp', 0o777), ('escape/file', tarfile.REGTYPE, b'escape', 0o644)],
            [('device', tarfile.CHRTYPE, b'', 0o644)],
        ]:
            status, _, _ = binary_http(self.socket, 'POST', '/v1/templates?profile=python', archive(entries_bad))
            assert status >= 400, status
            self.no_stages()
        assert http(self.socket, 'GET', '/v1/templates')[1]['templates'] == [first]
        self.done('invalid-archive-authority-leaves-no-object-or-stage')

        route = '/v1/templates?profile=python'
        with socket.create_connection(('127.0.0.1', self.port), timeout=10) as stream:
            stream.sendall(f'POST {route} HTTP/1.1\r\nHost: local\r\nContent-Length: 100\r\nExpect: 100-continue\r\n\r\n'.encode())
            assert header(stream).startswith(b'HTTP/1.1 401 ')
        assert self.custom(route, 'Content-Length: 1048577\r\nExpect: 100-continue', b'', method='POST')[0] == 413
        assert self.custom(route, 'Content-Length: 10240', b'partial', method='POST')[0] >= 400
        assert self.custom('/v1/templates?profile=python&profile=python', 'Content-Length: 100\r\nExpect: 100-continue', b'', method='POST')[0] == 400
        self.no_stages()
        self.done('template-authentication-admission-and-framing-precede-publication')

        source = self.root / 'template.tar'
        source.write_bytes(archive(entries))
        source.chmod(0o644)
        cli = call('runuser', '-u', 'daemon', '--', str(self.binary), 'template', 'import',
                   '--socket', str(self.socket), '--profile', 'python', str(source))
        assert json.loads(cli.stdout) == first
        directory = self.root / 'unpacked-rootfs'
        directory.mkdir(mode=0o755)
        for name, kind, content, mode in entries:
            if kind == tarfile.SYMTYPE:
                (directory / name).symlink_to(content)
            else:
                (directory / name).write_bytes(content)
                (directory / name).chmod(mode)
        cli = call('runuser', '-u', 'daemon', '--', str(self.binary), 'template', 'import',
                   '--socket', str(self.socket), '--profile', 'python', '--directory', str(directory))
        assert json.loads(cli.stdout) == first
        self.done('cli-streams-tar-and-an-unpacked-image-tree-to-the-same-object')

        (directory / 'z').unlink()
        os.link(directory / 'a', directory / 'z')
        cli = call('runuser', '-u', 'daemon', '--', str(self.binary), 'template', 'import',
                   '--socket', str(self.socket), '--profile', 'python', '--directory', str(directory))
        assert json.loads(cli.stdout)['id'] == linked['id']
        assert http(self.socket, 'DELETE', '/v1/templates/'+linked['id'])[0] == 200
        self.done('unpacked-image-import-preserves-hardlink-topology')

        with socket.socket(socket.AF_UNIX) as pending:
            pending.settimeout(15)
            connect(pending, self.socket)
            pending.sendall(f'POST {route} HTTP/1.1\r\nHost: local\r\nContent-Length: 102400\r\nExpect: 100-continue\r\n\r\n'.encode())
            assert header(pending) == b'HTTP/1.1 100 Continue\r\n\r\n'
            pending.sendall(archive(entries)[:512])
            assert list((self.socket.parent / 'templates/incoming').glob('.transfer-*'))
            call('systemctl', 'kill', '--kill-who=all', '--signal=SIGKILL', self.unit)
        self.restart()
        self.no_stages()
        assert http(self.socket, 'GET', '/v1/templates/'+first['id']) == (200, first)
        assert self.put(archive(entries)) == first
        assert http(self.socket, 'DELETE', '/v1/templates/'+first['id']) == (200, {'deleted': True})
        assert http(self.socket, 'GET', '/v1/templates/'+first['id'])[0] == 404
        self.done('restart-contains-interrupted-imports-and-preserves-published-objects')
        self.failed_import_admission()

    def failed_import_admission(self):
        content = archive([('artifact', tarfile.REGTYPE, b'fault fixture', 0o644)])
        for uncertain_cleanup in (False, True):
            parent = self.session_open()
            with socket.socket(socket.AF_UNIX) as stream:
                stream.settimeout(75)
                connect(stream, self.socket)
                stream.sendall((f'POST /v1/templates?profile=python HTTP/1.1\r\nHost: local\r\n'
                                f'Content-Length: {len(content)}\r\nExpect: 100-continue\r\n\r\n').encode())
                assert header(stream) == b'HTTP/1.1 100 Continue\r\n\r\n'
                stages = list((self.socket.parent / 'templates/incoming').glob('.transfer-*'))
                assert len(stages) == 1
                stage = stages[0]
                if uncertain_cleanup:
                    stage.chmod(0o777)
                else:
                    (stage / 'lower').mkdir(mode=0o700)
                stream.sendall(content)
                response = HTTPResponse(stream)
                response.begin()
                value = json.loads(response.read())
                assert response.status == 503 and value['error']['code'] == 'TEMPLATE_STATE_UNCERTAIN', value
            pool = http(self.socket, 'GET', '/v1/templates')[1]['pool']
            assert not pool['available']
            status, _, raw = binary_http(self.socket, 'PUT', f'/v1/sessions/{parent["id"]}/files?path=ordinary', b'available')
            if uncertain_cleanup:
                assert status >= 400 and json.loads(raw)['error']['code'] == 'FILE_CAPACITY', (status, raw)
                assert stage.exists()
                stage.chmod(0o700)
            else:
                assert status == 200, raw
                self.no_stages()
            self.session_close(parent)
            self.session_forget(parent)
            call('systemctl', 'kill', '--kill-who=all', '--signal=SIGKILL', self.unit)
            self.restart()
            self.no_stages()
            assert http(self.socket, 'GET', '/v1/templates')[1]['pool']['available']
            self.done('template-cleanup-uncertainty-retains-admission-until-recovery' if uncertain_cleanup
                      else 'template-publication-fence-releases-a-fully-cleaned-transfer-slot')
