"""Bounded asynchronous native HTTP client. Requests are sent once, never replayed."""
import asyncio
import json
import socket
import struct

from protocol import load


class ProtocolError(RuntimeError):
    pass


class Client:
    def __init__(self, path, timeout=None, maximum=1_048_576, peer_uid=0):
        settings = load()
        self.path, self.maximum, self.peer_uid = str(path), maximum, peer_uid
        self.timeout = settings['httpTimeoutSeconds'] if timeout is None else timeout
        self.poll_seconds = settings['observationPollSeconds']

    async def request(self, method, route, value=None):
        if method not in ('GET', 'POST', 'DELETE') or not route.startswith('/v1/') or any(c in route for c in '\r\n '):
            raise ValueError('Invalid native request')
        body = json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode() if value is not None else b''
        if len(body) > 65536 or (method in ('GET', 'DELETE') and body):
            raise ValueError('Native JSON request exceeds its contract')
        # Deliberately use one connection per request. Thinking agents must not send a
        # command on a connection that may have crossed the server's idle deadline.
        return await asyncio.wait_for(self._exchange(method, route, body), self.timeout)

    async def import_template(self, body):
        if not isinstance(body, bytes) or not 0 < len(body) <= 67108864:
            raise ValueError('Template tar exceeds the fixture transfer bound')
        return await asyncio.wait_for(self._exchange('POST', '/v1/templates?profile=python', body,
                                                    content_type='application/x-tar'), 75)

    async def _exchange(self, method, route, body, content_type='application/json'):
        writer = None
        try:
            reader, writer = await asyncio.open_unix_connection(self.path, limit=8192)
            transport = writer.get_extra_info('socket')
            _, uid, _ = struct.unpack('3i', transport.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != self.peer_uid:
                raise ProtocolError('Unexpected service peer')
            headers = (f'{method} {route} HTTP/1.1\r\nHost: sandcrab\r\nContent-Type: {content_type}\r\n'
                       f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()
            writer.write(headers + body)
            await writer.drain()
            raw = await reader.readuntil(b'\r\n\r\n')
            if len(raw) > 8192:
                raise ProtocolError('Response headers exceed their bound')
            lines = raw[:-4].split(b'\r\n')
            first = lines[0].split(b' ', 2)
            if len(first) != 3 or first[0] != b'HTTP/1.1' or len(first[1]) != 3 or not first[1].isdigit():
                raise ProtocolError('Invalid response status')
            fields = {}
            for line in lines[1:]:
                key, colon, data = line.partition(b':')
                key = key.lower()
                if not colon or key in fields:
                    raise ProtocolError('Ambiguous response headers')
                fields[key] = data.strip()
            length = fields.get(b'content-length', b'')
            if b'transfer-encoding' in fields or not length.isdigit() or int(length) > self.maximum:
                raise ProtocolError('Unsupported or oversized response framing')
            data = await reader.readexactly(int(length))
            value = json.loads(data)
            if not isinstance(value, dict):
                raise ProtocolError('Expected a JSON object')
            return int(first[1]), value
        finally:
            if writer is not None:
                # Aborting also bounds cleanup when a peer stops consuming request bytes.
                writer.transport.abort()
                try:
                    await asyncio.wait_for(writer.wait_closed(), .2)
                except (OSError, RuntimeError, asyncio.TimeoutError):
                    pass

    async def observe(self, route, transient, timeout):
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError('Native operation observation deadline expired')
            status, value = await asyncio.wait_for(self.request('GET', route), remaining)
            if status != 200 or value.get('state') not in transient:
                return status, value
            if asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError('Native operation observation deadline expired')
            await asyncio.sleep(self.poll_seconds)
