"""Public-API resource ownership and one-shot command execution for the benchmark."""
import base64
import asyncio
import json
from pathlib import Path
import shlex
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

    async def session(self, volume=None):
        identity = str(uuid.uuid4())
        self.sessions.add(identity)
        body = {'id': identity, 'serverId': self.server_id, 'profile': 'python'}
        if volume is not None:
            body['volumeId'] = volume
        started = time.monotonic_ns()
        await self.call('POST', '/v1/sessions', body, (202,))
        value = await self.observe('/v1/sessions/' + identity, ('starting',), timeout=60)
        elapsed = time.monotonic_ns() - started
        if value['state'] != 'ready':
            raise NativeFailure(200, value)
        return identity, elapsed

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
            _, initial = await self.call('POST', '/v1/sessions/' + session + '/commands',
                                        {'id': identity, 'serverId': self.server_id, 'command': command,
                                         'timeoutMillis': timeout_ms, 'outputLimitBytes': 65536}, (202,))
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

    async def cleanup(self, keep_volumes=()):
        keep_volumes = set(keep_volumes)
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
        for route, key in (('/v1/runs', 'ids'), ('/v1/sessions', 'ids'), ('/v1/volumes', 'volumes')):
            try:
                _, value = await self.call('GET', route)
                remaining = {item['id'] for item in value[key]} if key == 'volumes' else set(value[key])
                expected = keep_volumes if key == 'volumes' else set()
                if remaining != expected or value.get('nextAfter'):
                    failures.append('INVENTORY_NOT_EMPTY')
            except Exception as error:
                failures.append(type(error).__name__)
        return {'result': 'FAIL' if failures else 'PASS', 'failures': failures}
