"""Bounded authenticated template operations; a lost publication is never reposted."""
import asyncio
from dataclasses import dataclass
from contextlib import asynccontextmanager
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import time
from urllib.parse import urlsplit
import uuid

import httpx

_DIGEST = re.compile(r'[0-9a-f]{64}')
_PROFILE = re.compile(r'[a-z][a-z0-9-]{0,47}')
_LIMIT = 1 << 30


class TemplateError(RuntimeError):
    def __init__(self, status, code):
        self.status, self.code = status, code
        super().__init__(f'Template API: HTTP {status} {code}')


class PublicationUncertain(RuntimeError):
    def __init__(self, template_id):
        self.template_id = template_id
        super().__init__(f'Publication outcome is unknown; reconcile template {template_id}')


@dataclass(frozen=True)
class Checkpoint:
    path: Path
    bytes: int
    sha256: str
    template_id: str
    profile: str
    rootfs: bool

    def __post_init__(self):
        object.__setattr__(self, 'path', Path(self.path))
        if (type(self.bytes) is not int or not 0 <= self.bytes <= _LIMIT
                or not _DIGEST.fullmatch(self.sha256) or not _DIGEST.fullmatch(self.template_id)
                or not _PROFILE.fullmatch(self.profile) or type(self.rootfs) is not bool):
            raise ValueError('Invalid checkpoint metadata')

    @property
    def image(self):
        if not self.rootfs:
            raise ValueError('OpenSandbox images require a rootfs checkpoint')
        return f'{self.profile}@sha256:{self.template_id}'

    def to_dict(self):
        return {'destination': str(self.path), 'bytes': self.bytes, 'sha256': self.sha256,
                'template': {'id': self.template_id, 'profile': self.profile, 'rootfs': self.rootfs}}

    @classmethod
    def from_dict(cls, value):
        """Load a trusted local capture receipt; its archive is verified before upload."""
        return cls(Path(value['destination']), value['bytes'], value['sha256'],
                   value['template']['id'], value['template']['profile'], value['template']['rootfs'])


def _endpoint(value):
    address = urlsplit(value)
    if (address.scheme != 'http' or address.username is not None or address.password is not None
            or address.path not in ('', '/') or address.query or address.fragment
            or address.port is None or not 1 <= address.port <= 65535
            or not ipaddress.ip_address(address.hostname or '').is_loopback):
        raise ValueError('Use an HTTP endpoint with a literal loopback address and port')
    return value.rstrip('/')


def _sync_directory(path):
    if os.name != 'nt':
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


@asynccontextmanager
async def _checked_archive(checkpoint):
    descriptor = os.open(checkpoint.path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
                         | getattr(os, 'O_NONBLOCK', 0))
    source = os.fdopen(descriptor, 'rb')
    try:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size != checkpoint.bytes:
            raise ValueError('Checkpoint archive is not the captured regular file')
        digest, total, deadline = hashlib.sha256(), 0, time.monotonic() + 75
        while chunk := source.read(65536):
            total += len(chunk)
            if total > checkpoint.bytes or time.monotonic() >= deadline:
                raise ValueError('Checkpoint archive changed or exceeded its read deadline')
            digest.update(chunk)
            await asyncio.sleep(0)
        if total != checkpoint.bytes or digest.hexdigest() != checkpoint.sha256:
            raise ValueError('Checkpoint archive checksum changed')
        source.seek(0)
        yield source
    finally:
        source.close()


class TemplateClient:
    def __init__(self, endpoint, token, *, transport=None):
        endpoint = _endpoint(endpoint)
        if not _DIGEST.fullmatch(token):
            raise ValueError('Use the service token without surrounding whitespace')
        self._http = httpx.AsyncClient(base_url=endpoint, headers={'Authorization': 'Bearer ' + token},
            timeout=httpx.Timeout(75, connect=10), follow_redirects=False, trust_env=False, transport=transport)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exception):
        await self.close()

    async def close(self):
        await self._http.aclose()

    async def _json(self, method, route, **kwargs):
        async with asyncio.timeout(75), self._http.stream(method, route, **kwargs) as response:
            content = bytearray()
            async for chunk in response.aiter_bytes():
                content.extend(chunk)
                if len(content) > 65536:
                    raise ValueError('Template JSON response exceeds its bound')
            value = json.loads(content)
            if not isinstance(value, dict):
                raise ValueError('Template JSON response is not an object')
            if response.status_code != 200:
                code = value.get('error', {}).get('code', 'INVALID_RESPONSE')
                if not isinstance(code, str) or not re.fullmatch(r'[A-Z_]{1,64}', code):
                    code = 'INVALID_RESPONSE'
                raise TemplateError(response.status_code, code)
            return value

    async def get(self, template_id):
        if not _DIGEST.fullmatch(template_id):
            raise ValueError('Invalid template ID')
        try:
            value = await self._json('GET', '/v1/templates/' + template_id)
        except TemplateError as error:
            if error.status == 404 and error.code == 'TEMPLATE_NOT_FOUND':
                return None
            raise
        if value.get('id') != template_id:
            raise ValueError('Template response identity changed')
        return value

    async def reconcile(self, checkpoint):
        """Read only. None means no published object is visible yet, including an import still running."""
        return await self.get(checkpoint.template_id)

    async def capture(self, session_id, destination):
        if str(uuid.UUID(session_id)) != session_id:
            raise ValueError('Invalid session ID')
        session = await self._json('GET', '/v1/sessions/' + session_id)
        destination = Path(destination).absolute()
        temporary = destination.with_name('.sandcrab-' + uuid.uuid4().hex + '.part')
        try:
            async with asyncio.timeout(75), self._http.stream('POST', '/v1/sessions/' + session_id + '/snapshot',
                    json={'path': '.', 'format': 'tar', 'frozen': True, 'scope': 'filesystem'}) as response:
                if response.status_code != 200:
                    raise TemplateError(response.status_code, 'CAPTURE_FAILED')
                headers = response.headers
                if headers.get('x-sandcrab-server-id') != session.get('serverId') or not session.get('serverId'):
                    raise ValueError('Session epoch changed before capture')
                raw_length = headers.get('content-length', '')
                etag = headers.get('etag', '')
                if (not re.fullmatch(r'[0-9]{1,10}', raw_length) or int(raw_length) > _LIMIT
                        or not re.fullmatch(r'"[0-9a-f]{64}"', etag)):
                    raise ValueError('Capture has no bounded length and SHA-256')
                rootfs = headers.get('x-sandcrab-rootfs')
                if rootfs not in ('true', 'false'):
                    raise ValueError('Capture has no filesystem kind')
                checkpoint = Checkpoint(destination, int(raw_length), etag[1:-1],
                    headers.get('x-sandcrab-template-id', ''), headers.get('x-sandcrab-profile', ''), rootfs == 'true')
                if checkpoint.profile != session.get('profile') or checkpoint.rootfs != session.get('rootfs'):
                    raise ValueError('Capture profile or filesystem kind changed')
                digest, total = hashlib.sha256(), 0
                descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, 'wb') as output:
                    async for chunk in response.aiter_bytes():
                        total += len(chunk)
                        if total > checkpoint.bytes:
                            raise ValueError('Capture exceeded its declared length')
                        digest.update(chunk)
                        output.write(chunk)
                    if total != checkpoint.bytes or digest.hexdigest() != checkpoint.sha256:
                        raise ValueError('Capture length or checksum changed')
                    output.flush()
                    os.fsync(output.fileno())
                # Atomic no-replacement installation on the same filesystem.
                os.link(temporary, destination, follow_symlinks=False)
                temporary.unlink()
                _sync_directory(destination.parent)
                return checkpoint
        finally:
            temporary.unlink(missing_ok=True)

    async def publish(self, checkpoint):
        existing = await self.reconcile(checkpoint)
        if existing is not None:
            return existing
        async with _checked_archive(checkpoint) as source:
            async def chunks():
                while chunk := source.read(65536):
                    yield chunk
            try:
                value = await self._json('POST', '/v1/templates',
                    params={'profile': checkpoint.profile, 'expectedId': checkpoint.template_id},
                    headers={'Content-Type': 'application/x-tar', 'Content-Length': str(checkpoint.bytes)},
                    content=chunks())
            except (httpx.TransportError, TimeoutError):
                value = await self.reconcile(checkpoint)
                if value is None:
                    raise PublicationUncertain(checkpoint.template_id) from None
            if value.get('id') != checkpoint.template_id:
                raise ValueError('Published template differs from the captured identity')
            return value
