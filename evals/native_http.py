"""A bounded Unix HTTP client. It never executes a model-supplied command on the host."""
from http.client import HTTPResponse
import json
from pathlib import Path
import socket
import stat
import struct
import time


def request(path: str, method: str, route: str, body: dict | None = None) -> tuple[int, dict]:
    if method not in {'GET', 'POST'} or not route.startswith('/v1/') or any(c in route for c in '\r\n '):
        raise ValueError('Invalid native HTTP request')
    endpoint = Path(path)
    for parent in endpoint.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Socket ancestors must be protected root-owned directories')
    info = endpoint.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o007:
        raise ValueError('Socket must be root-owned and private')
    data = json.dumps(body).encode() if body is not None else b''
    if len(data) > 65536:
        raise ValueError('Request exceeds 64 KiB')
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(15)
        stream.connect(path)
        _, uid, _ = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != 0:
            raise ValueError('Daemon peer must be root')
        stream.sendall((f'{method} {route} HTTP/1.1\r\nHost: sandcrab\r\n'
                        f'Content-Type: application/json\r\nContent-Length: {len(data)}\r\n\r\n').encode() + data)
        response = HTTPResponse(stream)
        response.begin()
        raw = response.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError('Response exceeds 8 MiB')
        return response.status, json.loads(raw)


def wait(path: str, run_id: str, timeout: float = 25) -> tuple[int, dict]:
    deadline = time.monotonic() + timeout
    while True:
        status, value = request(path, 'GET', '/v1/runs/' + run_id)
        if status != 200 or value.get('state') != 'running':
            return status, value
        if time.monotonic() >= deadline:
            raise TimeoutError('Run did not reach a terminal state')
        time.sleep(.05)
