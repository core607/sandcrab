"""A bounded Unix HTTP client. It never executes a model-supplied command on the host."""
from http.client import HTTPResponse
from contextlib import contextmanager
import json
from pathlib import Path
import socket
import stat
import struct
import time


class ResponseTooLarge(ValueError):
    pass


@contextmanager
def connect(path: str, timeout: float):
    endpoint = Path(path)
    for parent in endpoint.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Socket ancestors must be protected root-owned directories')
    info = endpoint.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o007:
        raise ValueError('Socket must be root-owned and private')
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(timeout)
        stream.connect(path)
        _, uid, _ = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != 0:
            raise ValueError('Daemon peer must be root')
        yield stream


def exchange(path: str, method: str, route: str, data: bytes, *, content_type: str = 'application/json',
             response_limit: int = 8 * 1024 * 1024, timeout: float = 15) -> tuple[int, dict, bytes]:
    if method not in {'GET', 'POST', 'PUT'} or not route.startswith('/v1/') or any(c.isspace() or ord(c) < 32 for c in route):
        raise ValueError('Invalid native HTTP request')
    if method != 'PUT' and len(data) > 65536:
        raise ValueError('Request exceeds 64 KiB')
    if len(data) > 2 * 1024 * 1024 or not 0 <= response_limit <= 8 * 1024 * 1024:
        raise ValueError('Transfer exceeds the evaluation client bound')
    if any(ord(c) < 32 or ord(c) == 127 for c in content_type):
        raise ValueError('Invalid content type')
    # One exchange per connection, no automatic replay after a partial send/read.
    with connect(path, timeout) as stream:
        stream.sendall((f'{method} {route} HTTP/1.1\r\nHost: sandcrab\r\n'
                        f'Content-Type: {content_type}\r\nContent-Length: {len(data)}\r\nConnection: close\r\n\r\n').encode() + data)
        response = HTTPResponse(stream)
        response.begin()
        fields = response.getheaders()
        headers = {name.lower(): value for name, value in fields}
        if len(fields) > 32 or len(headers) != len(fields) or sum(len(k) + len(v) + 4 for k, v in fields) > 8192:
            raise ValueError('Invalid response headers')
        length = headers.get('content-length', '')
        if 'transfer-encoding' in headers or 'upgrade' in headers or not length.isascii() or not length.isdigit():
            raise ValueError('Response requires one fixed content length')
        size = int(length)
        if size > response_limit:
            raise ResponseTooLarge('Response exceeds its byte bound')
        raw = response.read(size + 1)
        if len(raw) != size:
            raise ValueError('Incomplete response body; inspect the existing operation ID')
        return response.status, headers, raw


def request(path: str, method: str, route: str, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body, allow_nan=False).encode() if body is not None else b''
    status, _, raw = exchange(path, method, route, data)
    return status, json.loads(raw)


def wait(path: str, run_id: str, timeout: float = 25) -> tuple[int, dict]:
    deadline = time.monotonic() + timeout
    while True:
        status, value = request(path, 'GET', '/v1/runs/' + run_id)
        if status != 200 or value.get('state') != 'running':
            return status, value
        if time.monotonic() >= deadline:
            raise TimeoutError('Run did not reach a terminal state')
        time.sleep(.05)
