"""Public-API resource ownership and one-shot command execution for the benchmark."""
import base64
import asyncio
import hashlib
import io
import json
from pathlib import Path
import shlex
import tarfile
import tempfile
import time
import uuid

from client import Client, ProtocolError


class NativeFailure(RuntimeError):
    def __init__(self, status, value):
        self.status = status
        self.code = value.get('error', {}).get('code') or value.get('code') or value.get('state') or 'INVALID_RESPONSE'
        super().__init__(f'Native API returned {status}: {self.code}')


class Engine:
    def __init__(self, socket, server_id, emit=None):
        self.client, self.server_id = Client(socket), server_id
        self.sessions, self.volumes, self.runs = set(), set(), set()
        self.templates, self.uses_templates = set(), False
        self.executing = {}
        self.requests = 0
        self.emit = emit or (lambda phase, row: None)

    async def call(self, method, route, body=None, allowed=(200,)):
        self.requests += 1
        status, value = await self.client.request(method, route, body)
        if status not in allowed:
            raise NativeFailure(status, value)
        return status, value

    async def observe(self, route, transient, timeout=60, callback=None):
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Native observation did not complete')
            _, value = await asyncio.wait_for(self.call('GET', route), remaining)
            if callback:
                callback(value)
            if value.get('state') not in transient:
                return value
            await asyncio.sleep(self.client.poll_seconds)

    async def volume(self, clone=None):
        identity = str(uuid.uuid4())
        self.volumes.add(identity)
        body = {'id': identity, 'serverId': self.server_id, 'profile': 'python',
                'byteLimit': 268435456, 'inodeLimit': 65536}
        if clone is not None:
            body['cloneFrom'] = clone
        await self.call('POST', '/v1/volumes', body, (202,))
        value = await self.observe('/v1/volumes/' + identity, ('creating', 'deleting'), timeout=180)
        if value['state'] != 'ready':
            raise NativeFailure(200, value)
        return identity

    async def session(self, volume=None, *, template=None):
        if volume is not None and template is not None:
            raise ValueError('Select one workspace source')
        identity = str(uuid.uuid4())
        self.sessions.add(identity)
        body = {'id': identity, 'serverId': self.server_id, 'profile': 'python'}
        if volume is not None:
            body['volumeId'] = volume
        if template is not None:
            body['templateId'] = template
        started = time.monotonic_ns()
        await self.call('POST', '/v1/sessions', body, (202,))
        value = await self.observe('/v1/sessions/' + identity, ('starting',), timeout=60)
        elapsed = time.monotonic_ns() - started
        if value['state'] != 'ready':
            raise NativeFailure(200, value)
        if template is not None and value.get('templateId') != template:
            raise ProtocolError('Session did not attach the requested template')
        return identity, elapsed

    async def template(self, source=None):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            if source is not None:
                for path in sorted(Path(source).rglob('*')):
                    if path.is_symlink() or not (path.is_dir() or path.is_file()):
                        raise RuntimeError('Unexpected synthetic template node')
                    entry = archive.gettarinfo(str(path), arcname=path.relative_to(source).as_posix())
                    entry.uid, entry.gid, entry.uname, entry.gname, entry.mtime = 0, 0, '', '', 0
                    if entry.size + output.tell() + 10240 > 67108864:
                        raise RuntimeError('Synthetic template exceeds the fixture transfer bound')
                    if entry.isfile():
                        with path.open('rb') as data:
                            archive.addfile(entry, data)
                    else:
                        archive.addfile(entry)
        data = output.getvalue()
        self.uses_templates = True
        self.requests += 1
        self.emit('template-import-created', {'archiveBytes': len(data), 'archiveSha256': hashlib.sha256(data).hexdigest()})
        status, value = await self.client.import_template(data)
        if status != 200:
            raise NativeFailure(status, value)
        identity = value.get('id')
        if not isinstance(identity, str) or len(identity) != 64 or any(c not in '0123456789abcdef' for c in identity):
            raise ProtocolError('Invalid template identity')
        self.templates.add(identity)
        self.emit('template-import-completed', value)
        return identity

    async def seed_template(self, seed, files, fixture_root):
        from workload import create
        with tempfile.TemporaryDirectory(prefix='template-source-', dir=fixture_root) as directory:
            source = Path(directory)
            manifest = create(source, seed, files)
            identity = await self.template(source)
        session, _ = await self.session(template=identity)
        verified = await self.execute(session, "cat .density-corpus.json; git -C small-repo rev-parse HEAD; find corpus -type f -name '*.md' | wc -l")
        lines = verified.get('stdout', '').splitlines()
        if (verified['outcome'] != 'OK' or verified.get('fatal') or len(lines) != 3
                or json.loads(lines[0]) != manifest or lines[1:] != [manifest['gitCommit'], str(files)]):
            raise RuntimeError('Imported corpus readback failed')
        await self.close(session)
        return identity, manifest

    async def close(self, identity):
        status, _ = await self.call('GET', '/v1/sessions/' + identity, allowed=(200, 404))
        if status != 404:
            await self.call('POST', '/v1/sessions/' + identity + '/close', {})
            value = await self.observe('/v1/sessions/' + identity, ('starting', 'ready', 'busy', 'stopping'))
            if value['state'] not in ('closed', 'expired', 'failed'):
                raise NativeFailure(200, value)
            await self.call('POST', '/v1/sessions/' + identity + '/forget', {})
        self.sessions.remove(identity)

    async def delete(self, identity):
        status, value = await self.call('GET', '/v1/volumes/' + identity, allowed=(200, 404))
        if status != 404:
            if value['state'] != 'deleted':
                await self.call('POST', '/v1/volumes/' + identity + '/delete', {}, (200, 202))
                value = await self.observe('/v1/volumes/' + identity, ('creating', 'deleting'), timeout=180)
            if value['state'] != 'deleted':
                raise NativeFailure(200, value)
            await self.call('POST', '/v1/volumes/' + identity + '/forget', {})
        self.volumes.remove(identity)

    async def execute(self, session, command, *, timeout_ms=30000, kind='setup', on_start=None):
        identity = str(uuid.uuid4())
        self.runs.add(identity)
        self.executing[identity] = 'unknown'
        row = {'id': identity, 'session': session, 'kind': kind, 'createdAbsoluteNs': time.monotonic_ns(),
               'outcome': 'PENDING', 'elapsedNs': None}
        self.emit('created', row)
        started = time.monotonic_ns()
        row['startedAbsoluteNs'] = started
        if on_start:
            on_start(row)
        accepted = False
        try:
            route = '/v1/runs' if session is None else '/v1/sessions/' + session + '/commands'
            body = {'id': identity, 'serverId': self.server_id, 'command': command,
                    'timeoutMillis': timeout_ms, 'outputLimitBytes': 65536}
            if session is None:
                body['profile'] = 'python'
            _, initial = await self.call('POST', route, body, (202,))
            accepted = True
            self.executing[identity] = initial.get('state', 'unknown')
            value = await self.observe('/v1/runs/' + identity, ('running', 'closing'), timeout=timeout_ms / 1000 + 15,
                                       callback=lambda value: self.executing.__setitem__(identity, value.get('state', 'unknown')))
            row['elapsedNs'] = time.monotonic_ns() - started
            result = value.get('result') or {}
            if value.get('state') not in ('succeeded', 'failed', 'cancelled', 'timed_out', 'output_limit', 'resource_limit'):
                raise ProtocolError('Unknown terminal run state')
            output = {}
            if 'exitCode' in result:
                if type(result['exitCode']) is not int or not all(isinstance(result.get(key), str) for key in ('stdout', 'stderr')):
                    raise ProtocolError('Invalid terminal run output')
                output = {key: result[key] for key in ('stdout', 'stderr')}
            elif not isinstance(result.get('code'), str) or value['state'] == 'succeeded':
                raise ProtocolError('Missing terminal run result')
            row.update(state=value.get('state'), exitCode=result.get('exitCode'),
                       outcome='OK' if value.get('state') == 'succeeded' and result.get('exitCode') == 0 else 'COMMAND_FAILED',
                       code=result.get('code'), **output)
        except NativeFailure as error:
            refused = not accepted and 400 <= error.status < 500
            row.update(elapsedNs=time.monotonic_ns() - started, outcome='REFUSED' if refused else 'ERROR',
                       code=error.code, fatal=not refused or error.code in ('SERVER_CHANGED', 'AUTH_REQUIRED', 'ID_CONFLICT'))
            if refused:
                self.executing.pop(identity, None)
            self.emit('completed', row)
            return row
        except Exception as error:
            row.update(elapsedNs=time.monotonic_ns() - started, outcome='TRANSPORT', code=type(error).__name__, fatal=True)
            self.emit('completed', row)
            return row
        # Record cleanup is separate from the command result and its observed latency.
        self.executing.pop(identity, None)
        try:
            await self.call('POST', '/v1/runs/' + identity + '/forget', {})
            self.runs.remove(identity)
        except Exception as error:
            row.update(cleanupFailure=getattr(error, 'code', type(error).__name__), fatal=True)
        self.emit('completed', row)
        return row

    async def seed(self, seed, files):
        base = await self.volume()
        session, _ = await self.session(base)
        encoded = base64.b64encode(Path(__file__).with_name('workload.py').read_bytes()).decode()
        program = ("import base64,json; namespace={'__name__':'density_corpus'}; "
                   f"exec(base64.b64decode({encoded!r}),namespace); "
                   f"print(json.dumps(namespace['create']('/workspace',{seed},{files})))")
        result = await self.execute(session, 'python3 -c ' + shlex.quote(program), timeout_ms=60000)
        if result['outcome'] != 'OK' or result.get('fatal'):
            raise RuntimeError('Corpus creation failed: ' + str(result.get('code') or result.get('state')))
        manifest = json.loads(result['stdout'])
        verified = await self.execute(session, "find corpus -type f -name '*.md' | wc -l; git -C small-repo ls-files | wc -l")
        if verified['outcome'] != 'OK' or verified.get('fatal') or verified['stdout'].split() != [str(files), '32']:
            raise RuntimeError('Independent corpus file-count readback failed')
        await self.close(session)
        return base, manifest

    async def cleanup(self, keep_volumes=(), keep_templates=()):
        keep_volumes = set(keep_volumes)
        keep_templates = set(keep_templates)
        failures = []
        for identity in list(self.runs):
            try:
                status, value = await self.call('GET', '/v1/runs/' + identity, allowed=(200, 404))
                if status != 404:
                    if value['state'] in ('running', 'closing'):
                        await self.call('POST', '/v1/runs/' + identity + '/cancel', {})
                        value = await self.observe('/v1/runs/' + identity, ('running', 'closing'))
                    await self.call('POST', '/v1/runs/' + identity + '/forget', {})
                self.runs.remove(identity)
                self.executing.pop(identity, None)
            except Exception as error:
                failures.append(type(error).__name__)
        for identity in list(self.sessions):
            try:
                await self.close(identity)
            except Exception as error:
                failures.append(type(error).__name__)
        for identity in list(self.volumes - keep_volumes):
            try:
                await self.delete(identity)
            except Exception as error:
                failures.append(type(error).__name__)
        for identity in list(self.templates - keep_templates):
            try:
                await self.call('DELETE', '/v1/templates/' + identity, allowed=(200, 404))
                self.templates.remove(identity)
            except Exception as error:
                failures.append(type(error).__name__)
        inventories = [('/v1/runs', 'ids', set()), ('/v1/sessions', 'ids', set()), ('/v1/volumes', 'volumes', keep_volumes)]
        if self.uses_templates:
            inventories.append(('/v1/templates', 'templates', keep_templates))
        for route, key, expected in inventories:
            try:
                _, value = await self.call('GET', route)
                remaining = {item['id'] for item in value[key]} if key != 'ids' else set(value[key])
                if remaining != expected or value.get('nextAfter'):
                    failures.append('INVENTORY_NOT_EMPTY')
            except Exception as error:
                failures.append(type(error).__name__)
        return {'result': 'FAIL' if failures else 'PASS', 'failures': failures}
