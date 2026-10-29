"""An ordinary native consumer: owned volumes/sessions, bounded files and explicit shell recovery."""
from contextlib import contextmanager
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import tarfile
import threading
import time
import uuid

import native_http
from workspace_cases import MAX_ARTIFACT, MAX_FILE, content, path, same_json, strict_json, submitted


class Rejected(Exception):
    """A caller can correct this input or inspect the returned operation state."""


class Workspace:
    def __init__(self, endpoint: str, directory: Path, state: dict):
        self.endpoint, self.directory, self.state = endpoint, directory, state
        self.lock = threading.RLock()
        self.agent_closed = threading.Event()
        self.epoch = None
        self.volume = None
        self.session = None
        self.phase = 'setup'
        self.state.update(sessions=[], runs=[], uploads=[], volumes=[], finished=[], artifact=None, grading=[], commands=0, writes=0, restarts=0)

    @contextmanager
    def exclusive(self, phase):
        # Cleanup and grading join outstanding synchronous HTTP work before releasing
        # its resources. A cancelled asyncio.to_thread waiter does not stop its thread.
        if not self.lock.acquire(timeout=120):
            raise RuntimeError('Native client work did not quiesce; containment is unconfirmed')
        try:
            if phase == 'agent' and self.agent_closed.is_set():
                raise Rejected('The workspace is closed for agent operations')
            self.phase = phase
            yield
        finally:
            self.lock.release()

    def observe(self, method, route, action):
        started = time.monotonic()
        row = {'phase': self.phase, 'method': method, 'path': route, 'status': None}
        self.state['observations'].append(row)
        try:
            status, value = action()
            row.update(status=status, response=value)
            return status, value
        except native_http.ResponseTooLarge:
            row['error'] = 'response_limit'
            raise Rejected('Transfer exceeds the evaluation client byte limit') from None
        except Exception as error:
            row['error'] = type(error).__name__
            # Never expose the host socket path or an echoed transport exception.
            raise RuntimeError('Native transport failed; operation identities are retained for cleanup') from None
        finally:
            row['seconds'] = round(time.monotonic() - started, 6)

    def api(self, method, route, body=None):
        return self.observe(method, route, lambda: native_http.request(self.endpoint, method, route, body))

    def require(self, status, value, accepted=(200,)):
        if status not in accepted:
            message = f'HTTP {status}: ' + str(value.get('error', {}).get('code', 'INVALID_RESPONSE'))
            if self.phase == 'agent' and status < 500:
                raise Rejected(message)
            raise RuntimeError('Native operation refused: ' + message)
        return value

    def poll(self, collection, identity, active, timeout=45):
        deadline = time.monotonic() + timeout
        while True:
            status, value = self.api('GET', f'/v1/{collection}/{identity}')
            self.require(status, value)
            if value.get('state') not in active:
                return value
            if time.monotonic() >= deadline:
                raise RuntimeError('Native operation did not reach a terminal state')
            time.sleep(.05)

    def create(self, collection, identity, route, body, accepted):
        # A 404 after an unanswered create is not proof that a queued request cannot
        # still admit it. Retain that identity and fail cleanup if it stays unresolved.
        self.state[collection].append(identity)
        status, value = self.api('POST', route, body)
        if status < 500 and status not in accepted:
            self.state[collection].remove(identity)
        return self.require(status, value, accepted)

    def finished(self, collection, identity):
        key = collection + '/' + identity
        if key not in self.state['finished']:
            self.state['finished'].append(key)

    def missing(self, collection, identity):
        if collection + '/' + identity not in self.state['finished']:
            raise RuntimeError('An operation identity disappeared before containment was confirmed')
        self.state[collection].remove(identity)

    def refresh(self):
        info = self.require(*self.api('GET', '/v1/info'))
        profile = info['profiles']['python']
        if not {'sessions', 'files', 'volumes'} <= set(info['capabilities']) or profile['sessionTtlMillis'] < 300000:
            raise RuntimeError('Workspace evaluations require files, volumes and a five-minute session profile')
        self.epoch = info['serverId']

    def open_session(self, volume=None):
        identity = str(uuid.uuid4())
        # Register before dispatch: a lost response must not hide a possibly admitted object.
        request = {'id': identity, 'serverId': self.epoch, 'profile': 'python', 'ttlMillis': 300000}
        if volume:
            request['volumeId'] = volume
        self.create('sessions', identity, '/v1/sessions', request, (202,))
        result = self.poll('sessions', identity, {'starting'})
        if result['state'] != 'ready':
            raise RuntimeError('Native session did not become ready: ' + str(result.get('code')))
        return identity

    def forget(self, collection, identity, strict=False):
        status, _ = self.api('POST', f'/v1/{collection}/{identity}/forget', {})
        if status == 404:
            self.missing(collection, identity)
            return True
        if status == 200:
            self.state[collection].remove(identity)
            return True
        if strict:
            raise RuntimeError('Native record cleanup was not confirmed')
        return False

    def close_session(self, identity):
        if identity not in self.state['sessions']:
            return
        status, value = self.api('GET', f'/v1/sessions/{identity}')
        if status == 404:
            self.missing('sessions', identity)
            return
        self.require(status, value)
        self.require(*self.api('POST', f'/v1/sessions/{identity}/close', {}))
        final = self.poll('sessions', identity, {'starting', 'ready', 'busy', 'stopping'}, timeout=75)
        if final['state'] not in {'closed', 'expired', 'failed'}:
            raise RuntimeError('Session containment was not confirmed')
        self.finished('sessions', identity)
        self.forget('sessions', identity, strict=True)

    def execute(self, session, command):
        identity = str(uuid.uuid4())
        self.create('runs', identity, f'/v1/sessions/{session}/commands', {
            'id': identity, 'serverId': self.epoch, 'command': command, 'timeoutMillis': 10000, 'outputLimitBytes': 4096}, (202,))
        result = self.poll('runs', identity, {'running'})
        if result['state'] == 'closing':
            raise RuntimeError('Command containment was not confirmed')
        self.finished('runs', identity)
        # A failed housekeeping call must not turn an acknowledged write into a retry.
        try:
            forgotten = self.forget('runs', identity)
        except RuntimeError:
            forgotten = False
        return result | ({} if forgotten else {'retainedRecord': identity})

    def put(self, session, name, data, replace=False):
        identity = str(uuid.uuid4())
        plan = {'id': identity, 'serverId': self.epoch, 'sessionId': session, 'path': name, 'format': 'raw',
                'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'replace': replace}
        result = self.create('uploads', identity, '/v1/uploads', plan, (201,))
        route = f'/v1/uploads/{identity}/content'
        def send():
            status, _, body = native_http.exchange(self.endpoint, 'PUT', route, data, content_type='application/octet-stream',
                                                   response_limit=65536, timeout=75)
            return status, json.loads(body)
        try:
            result = self.require(*self.observe('PUT', route, send))
        except RuntimeError:
            # Query the original receipt after transport loss; never resend the write.
            result = self.require(*self.api('GET', f'/v1/uploads/{identity}'))
            result = result | {'transportRecovery': 'queried original upload identity'}
        if result['state'] in {'succeeded', 'failed'}:
            self.finished('uploads', identity)
            try:
                forgotten = self.forget('uploads', identity)
            except RuntimeError:
                forgotten = False
            if not forgotten:
                result = result | {'retainedRecord': identity}
        return result

    def capture(self, session, name, format='raw', limit=MAX_FILE):
        route = f'/v1/sessions/{session}/snapshot'
        response_bytes = b''
        def receive():
            nonlocal response_bytes
            status, headers, response_bytes = native_http.exchange(self.endpoint, 'POST', route,
                json.dumps({'path': name, 'format': format}).encode(), response_limit=limit, timeout=75)
            if status != 200:
                return status, json.loads(response_bytes)
            digest = hashlib.sha256(response_bytes).hexdigest()
            if headers.get('etag') != '"' + digest + '"':
                raise ValueError('Snapshot digest did not match')
            return status, {'bytes': len(response_bytes), 'sha256': digest, 'format': format, 'path': name}
        status, value = self.observe('POST', route, receive)
        return status, value, response_bytes

    def populate(self, session, values):
        parents = sorted({name.rsplit('/', 1)[0] for name in values if '/' in name})
        if parents:
            result = self.execute(session, 'mkdir -p -- ' + ' '.join(shlex.quote(p) for p in parents))
            if result['state'] != 'succeeded':
                raise RuntimeError('Fixture directories could not be created')
        for name, value in values.items():
            result = self.put(session, name, content(value), replace=True)
            if result['state'] != 'succeeded':
                raise RuntimeError('Fixture file was not installed: ' + str(result.get('code')))

    def prepare(self, case):
        with self.exclusive('setup'):
            self.directory.mkdir(parents=True, mode=0o700)  # Each sample/epoch directory is new.
            self.refresh()
            self.volume = str(uuid.uuid4())
            self.create('volumes', self.volume, '/v1/volumes', {'id': self.volume, 'serverId': self.epoch, 'profile': 'python',
                                                             'byteLimit': 8388608, 'inodeLimit': 256}, (202,))
            if self.poll('volumes', self.volume, {'creating'})['state'] != 'ready':
                raise RuntimeError('Workspace volume could not be created')
            self.session = self.open_session(self.volume)
            runtime = self.execute(self.session, 'python3 --version')
            if runtime['state'] != 'succeeded':
                raise RuntimeError('Sandbox Python is unavailable')
            self.state['sandboxPython'] = runtime['result']['stdout'].strip()
            self.populate(self.session, case['fixture']['files'])

    def shell(self, command):
        with self.exclusive('agent'):
            if not isinstance(command, str) or not command or len(command.encode()) > 16384:
                raise Rejected('Use a nonempty command of at most 16 KiB')
            if self.state['commands'] >= 20:
                raise Rejected('The sample command limit is 20')
            self.state['commands'] += 1
            return self.execute(self.session, command)

    def write_file(self, name, text, replace=False):
        with self.exclusive('agent'):
            if not path(name) or not isinstance(text, str) or len(text.encode()) > MAX_FILE:
                raise Rejected('Use a relative workspace path and at most 64 KiB of UTF-8 text')
            if self.state['writes'] >= 16:
                raise Rejected('The sample file-write limit is 16')
            self.state['writes'] += 1
            return self.put(self.session, name, text.encode(), replace)

    def restart(self):
        with self.exclusive('agent'):
            if self.state['restarts'] >= 3:
                raise Rejected('The sample session-restart limit is three')
            self.state['restarts'] += 1
            for identity in self.state['sessions'][:]:
                self.close_session(identity)
            self.refresh()
            self.session = self.open_session(self.volume)
            return {'state': 'ready', 'files': 'retained', 'shell': 'fresh', 'cwd': '/workspace'}

    def status(self):
        with self.exclusive('agent'):
            result = {}
            for collection in ('sessions', 'runs', 'uploads'):
                rows = []
                for identity in self.state[collection]:
                    status, value = self.api('GET', f'/v1/{collection}/{identity}')
                    rows.append({'status': status, **{k: value[k] for k in ('id', 'state', 'code', 'publication', 'path') if k in value}})
                result[collection] = rows
            return result

    def export(self):
        with self.exclusive('agent'):
            if self.state.get('exports', 0) >= 4:
                raise Rejected('The sample artifact-export limit is four')
            self.state['exports'] = self.state.get('exports', 0) + 1
            status, info, raw = self.capture(self.session, '.', 'tar', MAX_ARTIFACT)
            self.require(status, info)
            name = str(uuid.uuid4()) + '.tar'
            with (self.directory / name).open('xb') as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            self.state['artifact'] = {'name': name, **info}
            return {'exported': True, 'bytes': len(raw), 'sha256': info['sha256']}

    def grade(self, case):
        self.agent_closed.set()
        with self.exclusive('grading'):
            # Close the producing processes before testing a sealed submission elsewhere.
            for identity in self.state['sessions'][:]:
                self.close_session(identity)
            artifact = self.state.get('artifact')
            if not artifact:
                return ['No artifact was exported']
            raw = (self.directory / artifact['name']).read_bytes()
            if hashlib.sha256(raw).hexdigest() != artifact['sha256'] or len(raw) != artifact['bytes']:
                raise RuntimeError('The retained artifact changed outside the sandbox')
            try:
                sources = submitted(raw, case)
            except (ValueError, OSError, tarfile.TarError) as error:
                return ['Invalid artifact: ' + str(error)]
            grader = self.open_session()
            self.populate(grader, {name: {'base64': base64.b64encode(data).decode()} for name, data in sources.items()})
            for index, step in enumerate(case['expected']['steps'], 1):
                reset = step.get('reset', [])
                if reset:
                    result = self.execute(grader, 'rm -rf -- ' + ' '.join(shlex.quote(p) for p in reset))
                    if result['state'] != 'succeeded':
                        raise RuntimeError('Verification input reset failed')
                self.populate(grader, step.get('files', {}))
                for name, target in step.get('links', {}).items():
                    parent = name.rsplit('/', 1)[0] if '/' in name else '.'
                    result = self.execute(grader, 'mkdir -p -- ' + shlex.quote(parent) + '\nln -s -- ' + shlex.quote(target) + ' ' + shlex.quote(name))
                    if result['state'] != 'succeeded':
                        raise RuntimeError('Verification symlink setup failed')
                before = {}
                for name in step.get('unchangedFiles', []):
                    try:
                        status, info, data = self.capture(grader, name)
                    except Rejected:
                        return [f'Check {index}: stored file exceeds its byte limit: {name}']
                    if status not in (200, 404):
                        self.require(status, info)
                    before[name] = (status, data)
                command = 'printf %s ' + shlex.quote(step['stdin']) + ' | ' + shlex.join(step['argv'])
                result = self.execute(grader, command)
                readback = {'step': index, 'run': result, 'files': {}}
                self.state['grading'].append(readback)
                outcome = result.get('result') or {}
                exit_code = outcome.get('exitCode')
                if result['state'] not in {'succeeded', 'failed'} or type(exit_code) is not int or not 0 <= exit_code <= 255 or outcome.get('truncated'):
                    return [f'Check {index}: submitted program did not complete normally']
                if step.get('exitCode', 0) is not None and exit_code != step.get('exitCode', 0):
                    return [f'Check {index}: program exit code differs']
                try:
                    actual = strict_json(result['result']['stdout'])
                    if not same_json(actual, step['stdoutJson']):
                        return [f'Check {index}: stdout JSON differs']
                except ValueError:
                    return [f'Check {index}: stdout is not one strict JSON value']
                for name in sorted(set(step.get('filesJson', {})) | set(step.get('absentFiles', [])) | set(before)):
                    try:
                        status, info, data = self.capture(grader, name)
                    except Rejected:
                        return [f'Check {index}: stored file exceeds its byte limit: {name}']
                    if status not in (200, 404):
                        self.require(status, info)
                    readback['files'][name] = {'status': status, 'sha256': info.get('sha256')}
                    if name in before and (status, data) != before[name]:
                        return [f'Check {index}: file changed on a refused operation: {name}']
                    if name in step.get('absentFiles', []) and status != 404:
                        return [f'Check {index}: unexpected file: {name}']
                    if name in step.get('filesJson', {}):
                        try:
                            if status != 200 or not same_json(strict_json(data), step['filesJson'][name]):
                                return [f'Check {index}: stored JSON differs: {name}']
                        except ValueError:
                            return [f'Check {index}: stored file is not JSON: {name}']
            return []

    def cleanup(self):
        self.agent_closed.set()
        with self.exclusive('cleanup'):
            for identity in self.state['sessions'][:]:
                self.close_session(identity)
            for collection, active in [('runs', {'running'}), ('uploads', {'waiting', 'receiving', 'publishing', 'published'})]:
                for identity in self.state[collection][:]:
                    status, result = self.api('GET', f'/v1/{collection}/{identity}')
                    if status == 404:
                        self.missing(collection, identity)
                        continue
                    self.require(status, result)
                    if result['state'] in active:
                        self.require(*self.api('POST', f'/v1/{collection}/{identity}/cancel', {}))
                        result = self.poll(collection, identity, active)
                    if result['state'] == 'closing':
                        raise RuntimeError('File or command containment was not confirmed')
                    if result['state'] != 'unknown':
                        self.finished(collection, identity)
                    self.forget(collection, identity, strict=True)
            for identity in self.state['volumes'][:]:
                status, result = self.api('GET', f'/v1/volumes/{identity}')
                if status == 404:
                    self.missing('volumes', identity)
                    continue
                self.require(status, result)
                if result['state'] == 'creating':
                    result = self.poll('volumes', identity, {'creating'})
                if result['state'] not in {'failed', 'deleted'}:
                    self.require(*self.api('POST', f'/v1/volumes/{identity}/delete', {}), accepted=(200, 202))
                    if self.poll('volumes', identity, {'deleting'})['state'] != 'deleted':
                        raise RuntimeError('Workspace volume deletion was not confirmed')
                self.finished('volumes', identity)
                self.forget('volumes', identity, strict=True)
