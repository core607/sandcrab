"""Exercise SDK authority and stream lifecycle against the disposable native service."""
from http.client import HTTPConnection
import json
from pathlib import Path
import socket
import time

from native_probe import call, http


class Contract:
    def __init__(self, probe):
        self.probe = probe
        self.master = {'OPEN-SANDBOX-API-KEY': probe.token}

    def request(self, method, path, body=None, headers=None):
        connection = HTTPConnection(self.probe.endpoint, timeout=15)
        try:
            data = None if body is None else json.dumps(body).encode()
            connection.request(method, path, data, headers=self.master if headers is None else headers)
            response = connection.getresponse()
            content = response.read(65537)
            assert len(content) <= 65536
            return response.status, json.loads(content) if content else None
        finally:
            connection.close()

    def create(self):
        status, sandbox = self.request('POST', '/v1/sandboxes', self.spec())
        assert status == 202, (status, sandbox.get('code'))
        self.probe.session_wait(sandbox)
        status, endpoint = self.request('GET', '/v1/sandboxes/' + sandbox['id'] + '/endpoints/44772',
                                        headers={**self.master, 'Host': 'untrusted.invalid'})
        assert status == 200
        assert endpoint['endpoint'] == self.probe.endpoint + '/opensandbox/' + sandbox['id']
        return sandbox['id'], endpoint['headers']

    @staticmethod
    def spec():
        return {'image': {'uri': 'python'}, 'entrypoint': ['tail', '-f', '/dev/null'],
                'resourceLimits': {'cpu': '0.25', 'memory': '32Mi'}, 'timeout': 60}

    def delete(self, identity, reaped=False):
        assert self.request('DELETE', '/v1/sandboxes/' + identity)[0] in ((204, 404) if reaped else (204,))
        assert http(self.probe.socket, 'GET', '/v1/sessions/' + identity)[0] == 404

    def native_terminal(self, identity, expected):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            status, result = http(self.probe.socket, 'GET', '/v1/sessions/' + identity)
            if status == 404 or (status == 200 and result['state'] == expected):
                return
            time.sleep(.025)
        raise AssertionError('SDK session did not reach its expected native terminal state')

    def authorization(self):
        for headers in [{}, {'OPEN-SANDBOX-API-KEY': 'invalid'},
                        {'Authorization': 'Bearer ' + self.probe.token}]:
            assert self.request('GET', '/v1/sandboxes', headers=headers)[0] == 401
        assert self.request('GET', '/v1/info', headers=self.master)[0] == 401
        connection = HTTPConnection(self.probe.endpoint, timeout=3)
        try:
            connection.putrequest('POST', '/v1/sandboxes')
            connection.putheader('Content-Length', '65536')
            connection.endheaders()
            response = connection.getresponse()
            assert response.status == 401
            assert json.loads(response.read())['code'] == 'AUTH_REQUIRED'
        finally:
            connection.close()
        self.probe.done('sdk-authentication-precedes-body-and-distinguishes-native-bearer')

    def refusal(self):
        baseline = self.request('GET', '/v1/sandboxes')[1]['items']
        for field, value, code in [('volumes', [], 'UNSUPPORTED_CREATE_OPTION'),
                                  ('networkPolicy', {'defaultAction': 'allow'}, 'UNSUPPORTED_CREATE_OPTION'),
                                  ('secureAccess', True, 'UNSUPPORTED_CREATE_OPTION'),
                                  ('entrypoint', ['touch', '/workspace/refused'], 'UNSUPPORTED_CREATE_OPTION'),
                                  ('resourceLimits', {'cpu': '1', 'memory': '32Mi'}, 'PROFILE_LIMIT'),
                                  ('unrecognized', None, 'INVALID_REQUEST')]:
            status, result = self.request('POST', '/v1/sandboxes', {**self.spec(), field: value})
            assert status == 400 and result['code'] == code, (field, status, result)
            assert self.request('GET', '/v1/sandboxes')[1]['items'] == baseline
        self.probe.done('sdk-unsupported-options-and-resource-escalation-refuse-before-creation')

    def scope(self):
        first, first_key = self.create()
        second, second_key = self.create()
        route = '/opensandbox/' + first + '/ping'
        assert self.request('GET', route, headers=first_key)[0] == 200
        assert self.request('GET', route, headers=second_key)[0] == 401
        assert self.request('GET', route, headers={'X-EXECD-ACCESS-TOKEN': self.probe.token})[0] == 401
        assert self.request('GET', '/v1/sandboxes', headers=first_key)[0] == 401
        self.delete(second)
        assert self.request('GET', '/opensandbox/' + second + '/ping', headers=second_key)[0] == 401
        self.probe.done('sdk-endpoint-credentials-are-sandbox-scoped-and-revoked-on-delete')

        # Reuse the native public ID to prove an old SDK credential cannot follow it.
        assert http(self.probe.socket, 'POST', '/v1/sessions/' + first + '/close', {})[0] == 200
        self.native_terminal(first, 'closed')
        assert http(self.probe.socket, 'POST', '/v1/sessions/' + first + '/forget', {})[0] in (200, 404)
        replacement = self.probe.session_open(id=first)
        status, _ = self.request('POST', '/opensandbox/' + first + '/command',
                                  {'command': 'touch /workspace/stale-sdk'}, headers=first_key)
        assert status == 401
        assert self.request('DELETE', '/v1/sandboxes/' + first)[0] in (204, 404)
        run, result = self.probe.session_exec(replacement, 'test ! -e /workspace/stale-sdk; printf alive')
        assert result['state'] == 'succeeded' and result['result']['stdout'] == 'alive'
        self.probe.forget(run)
        self.probe.session_close(replacement)
        self.probe.session_forget(replacement)
        self.probe.done('sdk-stale-credentials-and-delete-do-not-follow-a-reused-native-id')

    def stream(self, identity, headers, command, timeout=None, context=None):
        connection = HTTPConnection(self.probe.endpoint, timeout=15)
        body = {'command': command}
        if timeout is not None:
            body['timeout'] = timeout
        try:
            action = 'command' if context is None else 'session/' + context + '/run'
            connection.request('POST', '/opensandbox/' + identity + '/' + action,
                               json.dumps(body).encode(), headers=headers)
            response = connection.getresponse()
            assert response.status == 200
            initial = self.frame(response)
            assert initial['type'] == 'init'
            return connection, response, initial['text']
        except BaseException:
            connection.close()
            raise

    @staticmethod
    def frame(response):
        while True:
            line = response.readline(32769)
            assert len(line) <= 32768
            if not line:
                return None
            if line.startswith(b'data: '):
                return json.loads(line[6:])

    def terminal(self, response, expected):
        events = []
        while True:
            event = self.frame(response)
            if event is None:
                break
            events.append(event)
            assert len(events) <= 16
        assert any(e['type'] == 'error' and e['error']['ename'] == expected for e in events)
        assert events[-1]['type'] == 'execution_complete'

    def cleanup_run(self, command):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if http(self.probe.socket, 'GET', '/v1/runs/' + command)[0] == 404:
                return
            time.sleep(.025)
        raise AssertionError('Disconnected SDK command retained its native run record')

    def lifecycle(self):
        identity, headers = self.create()
        connection, response, command = self.stream(identity, headers, 'sleep 0.2; printf complete')
        response.close()
        connection.close()
        self.cleanup_run(command)
        status, result = self.request('GET', '/opensandbox/' + identity + '/command/status/' + command,
                                      headers=headers)
        assert status == 200 and result['running'] is False and result['exit_code'] == 0
        self.delete(identity)
        self.probe.done('sdk-disconnect-releases-observation-and-terminal-native-records')

        for cancel in (False, True):
            identity, headers = self.create()
            group = call('systemctl', 'show', self.probe.name + '-' + identity + '.service',
                         '-p', 'ControlGroup', '--value').stdout.strip()
            assert group.startswith('/') and group != '/'
            parent_cgroup = Path('/sys/fs/cgroup') / group.lstrip('/')
            connection, response, command = self.stream(identity, headers, 'sleep 30', None if cancel else 100)
            status, native = http(self.probe.socket, 'GET', '/v1/runs/' + command)
            assert status == 200 and native['sessionId'] != identity
            cgroup = parent_cgroup.parent / (self.probe.name + '-' + native['sessionId'] + '.service')
            try:
                if cancel:
                    assert self.request('DELETE', '/opensandbox/' + identity + '/command?id=' + command,
                                        headers=headers)[0] == 200
                self.terminal(response, 'COMMAND_CANCELLED' if cancel else 'COMMAND_TIMEOUT')
            finally:
                response.close()
                connection.close()
            self.cleanup_run(command)
            assert not any(path.read_text().strip() for path in cgroup.rglob('cgroup.procs'))
            assert http(self.probe.socket, 'GET', '/v1/sessions/' + identity)[1]['state'] == 'ready'
            connection, response, command = self.stream(identity, headers, 'printf recovered')
            events = []
            while (event := self.frame(response)) is not None:
                events.append(event)
            response.close()
            connection.close()
            assert events[-1]['type'] == 'execution_complete'
            assert not any(event['type'] == 'error' for event in events)
            assert ''.join(event.get('text', '') for event in events if event['type'] == 'stdout') == 'recovered'
            self.cleanup_run(command)
            self.delete(identity)
        self.probe.done('sdk-command-timeout-and-cancellation-contain-the-child-and-preserve-the-sandbox')

    @staticmethod
    def multipart(entries):
        parts = []
        for metadata, data in entries:
            for name, content in [('metadata', json.dumps(metadata).encode()), ('file', data)]:
                parts.extend([b'--sdk-probe\r\n',
                              ('Content-Disposition: form-data; name="' + name + '"; filename="ignored"\r\n\r\n').encode(),
                              content, b'\r\n'])
        return b''.join(parts) + b'--sdk-probe--\r\n'

    def upload(self, identity, headers, body, chunked=False):
        connection = HTTPConnection(self.probe.endpoint, timeout=15)
        try:
            content = (body[index:index + 16001] for index in range(0, len(body), 16001)) if chunked else body
            connection.request('POST', '/opensandbox/' + identity + '/files/upload', content,
                               headers={**headers, 'Content-Type': 'multipart/form-data; boundary=sdk-probe'},
                               encode_chunked=chunked)
            response = connection.getresponse()
            data = response.read()
            return response.status, json.loads(data) if data else None
        finally:
            connection.close()

    def interrupted_upload(self, identity, headers):
        changed = self.multipart([({'path': '/workspace/guard'}, b'changed')])
        stage_root = self.probe.socket.parent / 'jobs' / identity
        wire = ('POST /opensandbox/' + identity + '/files/upload HTTP/1.1\r\n'
                'Host: sandbox\r\nContent-Length: 65536\r\n'
                'Content-Type: multipart/form-data; boundary=sdk-probe\r\n' +
                ''.join(key + ': ' + value + '\r\n' for key, value in headers.items()) + '\r\n').encode()
        with socket.create_connection(('127.0.0.1', self.probe.port), timeout=5) as stream:
            stream.sendall(wire + changed[:-8])
            deadline = time.monotonic() + 5
            while not list(stage_root.glob('.transfer-*')):
                assert time.monotonic() < deadline, 'Incomplete upload was not admitted'
                time.sleep(.025)
        deadline = time.monotonic() + 5
        while list(stage_root.glob('.transfer-*')):
            assert time.monotonic() < deadline, 'Disconnected upload staging was not reclaimed'
            time.sleep(.025)

    def files(self):
        identity, headers = self.create()
        original = self.multipart([({'path': '/workspace/guard', 'mode': 640}, b'original')])
        assert self.upload(identity, headers, original, True)[0] == 200
        for options in [{'path': '../outside'}, {'path': '/etc/passwd'},
                        {'path': '/workspace/guard', 'owner': 'root'},
                        {'path': '/workspace/guard', 'mode': 888}]:
            body = self.multipart([({'path': '/workspace/guard'}, b'changed'), (options, b'escape')])
            assert self.upload(identity, headers, body)[0] == 400
        assert self.upload(identity, headers, original[:-4], True)[0] == 400
        assert self.upload(identity, headers, original + b'extra')[0] == 400
        oversized = self.multipart([({'path': '/workspace/guard'}, b'x' * 1048577)])
        assert self.upload(identity, headers, oversized)[0] == 413
        self.interrupted_upload(identity, headers)
        status, _ = self.request('GET', '/opensandbox/' + identity + '/files/download?path=%2Fworkspace%2Fguard&offset=1',
                                 headers={**headers, 'Range': 'bytes=0-1'})
        assert status == 400
        run, result = self.probe.session_exec({'id': identity},
            "test \"$(cat /workspace/guard)\" = original && test ! -e /workspace/outside && "
            "ln -s /etc /workspace/link && printf checked")
        assert result['state'] == 'succeeded' and result['result']['stdout'] == 'checked'
        self.probe.forget(run)
        assert self.request('POST', '/opensandbox/' + identity + '/directories',
                            {'/workspace/directory': {'mode': 700}}, headers)[0] == 200
        for path, expected, code in [('missing/child', 404, 'FILE_NOT_FOUND'),
                                     ('guard/child', 400, 'INVALID_PATH'),
                                     ('directory', 400, 'INVALID_PATH'),
                                     ('link/escape', 400, 'INVALID_PATH')]:
            body = self.multipart([({'path': '/workspace/guard'}, b'changed'),
                                   ({'path': '/workspace/' + path}, b'refused')])
            status, failure = self.upload(identity, headers, body)
            assert status == expected and failure['code'] == code, (path, status, failure)
            run, result = self.probe.session_exec({'id': identity},
                "test \"$(cat /workspace/guard)\" = original && test ! -e /workspace/missing && printf intact")
            assert result['state'] == 'succeeded' and result['result']['stdout'] == 'intact'
            self.probe.forget(run)
        assert self.request('POST', '/opensandbox/' + identity + '/directories',
                            {'/workspace/missing': {'mode': 700}}, headers)[0] == 200
        body = self.multipart([({'path': '/workspace/guard'}, b'changed'),
                               ({'path': '/workspace/missing/child'}, b'recovered')])
        assert self.upload(identity, headers, body)[0] == 200
        run, result = self.probe.session_exec({'id': identity},
            "test \"$(cat /workspace/guard)\" = changed && cat /workspace/missing/child")
        assert result['state'] == 'succeeded' and result['result']['stdout'] == 'recovered'
        self.probe.forget(run)
        self.probe.done('sdk-upload-prepublication-refusals-preserve-the-whole-batch-and-allow-explicit-recovery')
        assert self.request('GET', '/opensandbox/' + identity + '/files/download?path=%2Fworkspace%2Flink%2Fpasswd',
                            headers=headers)[0] >= 400
        self.probe.upload_reply_fault.touch()
        body = self.multipart([({'path': '/workspace/guard'}, b'published-without-receipt')])
        status, failure = self.upload(identity, headers, body)
        assert status == 503 and failure['code'] == 'PUBLICATION_UNKNOWN', (status, failure)
        assert not self.probe.upload_reply_fault.exists(), 'Helper record loss was not injected'
        run, result = self.probe.session_exec({'id': identity}, 'cat /workspace/guard')
        assert result['state'] == 'succeeded' and result['result']['stdout'] == 'published-without-receipt'
        self.probe.forget(run)
        self.probe.done('sdk-upload-helper-record-loss-after-publication-remains-unknown')
        self.delete(identity)
        self.probe.done('sdk-file-limits-disconnect-framing-traversal-and-ownership-refusals-preserve-existing-content')

    def filesystem(self):
        identity, headers = self.create()
        base = '/opensandbox/' + identity
        request = lambda method, path, body=None: self.request(method, base + path, body, headers)
        assert request('POST', '/directories', {'/workspace/safe/nested': {'mode': 750},
                                               '/workspace/keep': {'mode': 700}})[0] == 200
        content = self.multipart([({'path': '/workspace/keep/guard', 'mode': 640}, b'original')])
        assert self.upload(identity, headers, content)[0] == 200
        run, result = self.probe.session_exec({'id': identity}, 'ln -s ../keep /workspace/safe/link')
        assert result['state'] == 'succeeded'
        self.probe.forget(run)
        assert request('POST', '/directories', {'/workspace/aaa': {'mode': 700},
                                               '/workspace/safe/link/escape': {'mode': 700}})[0] == 400
        assert request('POST', '/files/permissions', {'keep/guard': {'mode': 600},
                                                     'safe/link': {'mode': 600}})[0] == 400
        assert request('POST', '/files/permissions', {'keep/guard': {'mode': 600},
                                                     '/workspace/keep/guard': {'mode': 600}})[0] == 400
        assert request('POST', '/files/mv', [{'src': 'keep/guard', 'dest': 'keep/moved'},
                                            {'src': 'missing', 'dest': 'keep/other'}])[0] == 404
        assert request('DELETE', '/files?path=keep/guard&path=missing')[0] == 404
        assert request('DELETE', '/directories?path=safe&path=missing')[0] == 404
        for query in ['path=/workspace', 'path=safe&path=safe/nested']:
            assert request('DELETE', '/directories?' + query)[0] == 400
        assert request('GET', '/directories/list?path=safe/link')[0] == 400
        assert request('GET', '/directories/list?path=safe&depth=65')[0] == 400
        assert request('GET', '/files/info?path=safe/link')[1]['safe/link']['type'] == 'symlink'
        assert request('POST', '/files/replace', {'keep/guard': {'old': '', 'new': 'changed'}})[0] == 400
        assert request('POST', '/files/replace', {'keep/guard': {'old': 'original', 'new': 'changed'},
                                                 'missing': {'old': 'x', 'new': 'y'}})[0] == 404
        run, result = self.probe.session_exec({'id': identity},
            "python3 -c \"from pathlib import Path; Path('keep/big').write_bytes(b'x'*600000)\"")
        assert result['state'] == 'succeeded'
        self.probe.forget(run)
        assert request('POST', '/files/replace', {'keep/big': {'old': 'x', 'new': 'xx'}})[0] == 413
        run, result = self.probe.session_exec({'id': identity},
            "test ! -e /workspace/aaa && test ! -e /workspace/keep/escape && "
            "test ! -e /workspace/keep/moved && test -d /workspace/safe/nested && "
            "test \"$(cat /workspace/keep/guard)\" = original && "
            "test \"$(stat -c '%a' /workspace/keep/guard)\" = 640 && "
            "test \"$(stat -c '%s' /workspace/keep/big)\" = 600000 && printf preserved")
        assert result['state'] == 'succeeded' and result['result']['stdout'] == 'preserved'
        self.probe.forget(run)
        assert request('POST', '/files/mv', [{'src': 'safe/link', 'dest': 'safe/moved-link'}])[0] == 200
        run, result = self.probe.session_exec({'id': identity},
            "python3 -c \"from pathlib import Path; [Path('safe/'+str(i)).write_text('x') for i in range(500)]\"")
        assert result['state'] == 'succeeded'
        self.probe.forget(run)
        assert request('GET', '/directories/list?path=safe&depth=1')[0] == 413
        assert request('GET', '/files/search?path=safe&pattern=**')[0] == 413
        assert request('GET', '/files/search?path=safe&pattern=*.absent') == (200, [])
        assert request('DELETE', '/directories?path=safe')[0] == 200
        assert request('GET', '/files/info?path=keep/guard')[1]['keep/guard']['size'] == 8
        run, result = self.probe.session_exec({'id': identity},
            "test ! -e /workspace/safe && test \"$(cat /workspace/keep/guard)\" = original")
        assert result['state'] == 'succeeded'
        self.probe.forget(run)
        self.delete(identity)
        self.probe.done('sdk-filesystem-preflight-batches-metadata-bounds-and-link-safe-recursive-removal')

    def download(self, identity, headers, query, extra=None):
        connection = HTTPConnection(self.probe.endpoint, timeout=15)
        try:
            connection.request('GET', '/opensandbox/' + identity + '/files/download?' + query,
                               headers={**headers, **(extra or {})})
            response = connection.getresponse()
            content = response.read(1048577)
            assert len(content) <= 1048576
            return response.status, {key.lower(): value for key, value in response.getheaders()}, content
        finally:
            connection.close()

    def selections(self):
        identity, headers = self.create()
        data = bytes(range(16))
        content = self.multipart([({'path': 'range.bin'}, data),
                                  ({'path': 'lines.log'}, b'A' * 70000 + b'\r\nmiddle\r\nlast\r\r\n')])
        assert self.upload(identity, headers, content)[0] == 200
        status, fields, result = self.download(identity, headers, 'path=range.bin', {'Range': 'bytes=3-7'})
        assert status == 206 and result == data[3:8]
        assert fields['content-range'] == 'bytes 3-7/16' and fields['content-length'] == '5'
        assert fields['accept-ranges'] == 'bytes' and 'etag' not in fields
        status, fields, result = self.download(identity, headers, 'path=lines.log&offset=2&limit=1')
        assert status == 200 and result == b'middle' and fields['content-length'] == '6'
        assert fields['content-type'].startswith('text/plain') and 'etag' not in fields
        assert self.download(identity, headers, 'path=lines.log&offset=99')[2] == b''
        for query, extra, expected in [('path=range.bin', {'Range': 'bytes=16-'}, 416),
                                       ('path=range.bin', {'Range': 'bytes=-0'}, 416),
                                       ('path=range.bin', {'Range': 'bytes=0-1,3-4'}, 400),
                                       ('path=range.bin&offset=1', {'Range': 'bytes=0-1'}, 400),
                                       ('path=range.bin&limit=0', {}, 400),
                                       ('path=range.bin', {'Range': 'bytes=0-1', 'If-Range': 'old'}, 400)]:
            assert self.download(identity, headers, query, extra)[0] == expected
        run, result = self.probe.session_exec({'id': identity},
            "python3 -c \"f=open('sparse.bin','wb'); f.seek(1048576); f.write(b'tail'); f.close()\"")
        assert result['state'] == 'succeeded'
        self.probe.forget(run)
        assert self.download(identity, headers, 'path=sparse.bin', {'Range': 'bytes=-4'})[2] == b'tail'
        assert self.download(identity, headers, 'path=sparse.bin')[0] == 413
        assert self.download(identity, headers, 'path=sparse.bin&offset=2')[0] == 413
        assert self.download(identity, headers, 'path=sparse.bin', {'Range': 'bytes=0-1048576'})[0] == 413
        for query, expected in [('path=/workspace&pattern=[', 400), ('path=/etc&pattern=**', 400),
                                ('path=/workspace&pattern=/etc/*', 200)]:
            status, result = self.request('GET', '/opensandbox/' + identity + '/files/search?' + query, headers=headers)
            assert status == expected
            if status == 200:
                assert result == []
        self.delete(identity)
        self.probe.done('sdk-partial-download-headers-long-lines-sparse-files-and-selection-limits')

    def tests(self):
        self.authorization()
        self.refusal()
        self.scope()
        self.lifecycle()
        self.files()
        self.filesystem()
        self.selections()
