"""Connection resolution, wire bounds, SSE parsing and bounded gzip tar helpers."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from typing import AsyncIterator, Iterator, Mapping
from urllib.parse import urlsplit
import uuid
import zlib

from .errors import ProtocolError, SandcrabError

DIGEST_RE = re.compile(r"[0-9a-f]{64}")
PROFILE_RE = re.compile(r"[a-z][a-z0-9-]{0,47}")
CODE_RE = re.compile(r"[A-Z0-9_]{1,64}")
JSON_BOUND = 16 * 1024 * 1024
TRANSFER_BOUND = 1 << 30
TEMPLATE_STREAM_BOUND = 1 << 30


def check_uuid(value: str, label: str = "ID") -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError(f"Invalid {label}: {value!r}") from error
    if str(parsed) != value:
        raise ValueError(f"Invalid canonical {label}: {value!r}")
    return value


def check_digest(value: str, label: str = "SHA-256") -> str:
    if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
        raise ValueError(f"Invalid {label}")
    return value


def check_profile(value: str) -> str:
    if not isinstance(value, str) or not PROFILE_RE.fullmatch(value):
        raise ValueError(f"Invalid profile name: {value!r}")
    return value


def check_relative_path(value: str, *, allow_root: bool = False) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value or "\\" in value:
        raise ValueError("Invalid workspace path")
    if value == ".":
        if allow_root:
            return value
        raise ValueError("Workspace root '.' is not valid for this operation")
    if value.startswith("/"):
        raise ValueError("Workspace path must be relative")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("Workspace path must be normalized and relative")
    return value


def normalize_endpoint(value: str) -> str:
    address = urlsplit(value)
    try:
        loopback = ipaddress.ip_address(address.hostname or "").is_loopback
    except ValueError:
        loopback = False
    if (
        address.scheme != "http"
        or address.username is not None
        or address.password is not None
        or address.path not in ("", "/")
        or address.query
        or address.fragment
        or address.port is None
        or not 1 <= address.port <= 65535
        or not loopback
    ):
        raise ValueError("Use an HTTP endpoint with a literal loopback address and port")
    return value.rstrip("/")


def read_token_file(path: str | Path) -> str:
    resolved = Path(path)
    if os.name != "nt":
        info = resolved.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in (0, os.geteuid())
            or (stat.S_IMODE(info.st_mode) & 0o077) != 0
        ):
            raise ValueError(
                "Service token file must be a private regular file (mode 0400/0600) owned by root or the caller"
            )
    raw = resolved.read_bytes()
    if len(raw) > 256:
        raise ValueError("Service token file exceeds 256 bytes")
    text = raw.decode("utf-8").rstrip("\r\n")
    if not DIGEST_RE.fullmatch(text):
        raise ValueError("Service token must be 64 lowercase hexadecimal characters")
    return text


def check_unix_socket(path: str | Path) -> str:
    resolved = Path(path)
    if not resolved.is_absolute():
        raise ValueError("Unix socket path must be absolute")
    if os.name == "nt":
        raise ValueError("Unix domain socket transport requires a POSIX host")
    info = os.lstat(resolved)
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
        raise ValueError(f"Unix control socket must be a root-owned socket: {resolved}")
    return str(resolved)


def resolve_connection(
    *,
    socket_path: str | Path | None = None,
    endpoint: str | None = None,
    token: str | None = None,
    token_file: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    require_socket_stat: bool = True,
) -> tuple[str | None, str, dict[str, str]]:
    """Return `(uds_path, base_url, headers)` after checking transport and credential boundaries."""
    environ = os.environ if env is None else env
    if socket_path is not None and endpoint is not None:
        raise ValueError("Pass either socket_path or endpoint, not both")
    if socket_path is None and endpoint is None:
        env_socket = environ.get("SANDCRAB_SOCKET") or None
        env_endpoint = environ.get("SANDCRAB_ENDPOINT") or None
        if env_socket and env_endpoint:
            raise ValueError(
                "Both SANDCRAB_SOCKET and SANDCRAB_ENDPOINT are set; pass socket_path or endpoint explicitly"
            )
        socket_path = env_socket
        endpoint = env_endpoint
    if socket_path is not None:
        uds = check_unix_socket(socket_path) if require_socket_stat else str(Path(socket_path))
        return uds, "http://sandcrab", {}
    if endpoint is not None:
        base_url = normalize_endpoint(endpoint)
        if token is not None and token_file is not None:
            raise ValueError("Pass either token or token_file, not both")
        if token is None:
            chosen_file = token_file if token_file is not None else environ.get("SANDCRAB_TOKEN_FILE")
            if not chosen_file:
                raise ValueError("Loopback HTTP transport requires token, token_file or SANDCRAB_TOKEN_FILE")
            token = read_token_file(chosen_file)
        elif not DIGEST_RE.fullmatch(token):
            raise ValueError("Service token must be 64 lowercase hexadecimal characters")
        return None, base_url, {"Authorization": "Bearer " + token}
    raise ValueError("Configure socket_path, endpoint, SANDCRAB_SOCKET or SANDCRAB_ENDPOINT")


def format_byte_range(spec: tuple[int | None, int | None] | str) -> str:
    if isinstance(spec, str):
        text = spec.removeprefix("bytes=")
        if "," in text or "-" not in text:
            raise ValueError("Byte range must be START-END, START- or -SUFFIX")
        start, end = text.split("-", 1)
        if (not start and not end) or (start and not start.isdigit()) or (end and not end.isdigit()):
            raise ValueError("Invalid byte range bounds")
        return f"bytes={start}-{end}"
    start, end = spec
    if start is None and end is None:
        raise ValueError("Byte range requires at least start or suffix length")
    if start is not None and (type(start) is not int or start < 0):
        raise ValueError("Range start must be a non-negative integer")
    if end is not None and (type(end) is not int or end < 0):
        raise ValueError("Range end must be a non-negative integer")
    if start is None:
        if end == 0:
            raise ValueError("Suffix byte range must be positive")
        return f"bytes=-{end}"
    if end is not None and end < start:
        raise ValueError("Range end must be >= start")
    return f"bytes={start}-{'' if end is None else end}"


def parse_json_response(status: int, raw: bytes | bytearray, *, recovery_id: str | None = None) -> dict:
    try:
        value = json.loads(raw)
    except ValueError as error:
        raise ProtocolError(f"Daemon returned non-JSON body (HTTP {status})") from error
    if not isinstance(value, dict):
        raise ProtocolError("Daemon JSON response must be an object")
    if status >= 400:
        err = value.get("error")
        code = err.get("code") if isinstance(err, dict) else value.get("code")
        if not isinstance(code, str) or not CODE_RE.fullmatch(code):
            code = "API_ERROR"
        raise SandcrabError(status, code, recovery_id=recovery_id)
    return value


def parse_sse_lines(lines: Iterator[str]) -> Iterator[dict]:
    event_id: str | None = None
    event_type = "message"
    data_lines: list[str] = []
    for raw_line in lines:
        line = raw_line.rstrip("\r\n")
        if not line:
            if data_lines:
                payload = "\n".join(data_lines)
                data_lines.clear()
                yield {"id": event_id, "event": event_type, "data": json.loads(payload)}
                event_type = "message"
            continue
        if line.startswith(":"):
            continue
        field, _, rest = line.partition(":")
        if rest.startswith(" "):
            rest = rest[1:]
        if field == "id":
            event_id = rest
        elif field == "event":
            event_type = rest
        elif field == "data":
            data_lines.append(rest)
    if data_lines:
        raise ProtocolError("Incomplete SSE frame before stream EOF")


async def parse_sse_lines_async(lines: AsyncIterator[str]) -> AsyncIterator[dict]:
    event_id: str | None = None
    event_type = "message"
    data_lines: list[str] = []
    async for raw_line in lines:
        line = raw_line.rstrip("\r\n")
        if not line:
            if data_lines:
                payload = "\n".join(data_lines)
                data_lines.clear()
                yield {"id": event_id, "event": event_type, "data": json.loads(payload)}
                event_type = "message"
            continue
        if line.startswith(":"):
            continue
        field, _, rest = line.partition(":")
        if rest.startswith(" "):
            rest = rest[1:]
        if field == "id":
            event_id = rest
        elif field == "event":
            event_type = rest
        elif field == "data":
            data_lines.append(rest)
    if data_lines:
        raise ProtocolError("Incomplete SSE frame before stream EOF")


def is_gzip_tar(source: bytes | Path) -> bool:
    if isinstance(source, (bytes, bytearray)):
        return len(source) >= 2 and source[0] == 0x1F and source[1] == 0x8B
    name = Path(source).name.lower()
    if name.endswith((".tar.gz", ".tgz")):
        return True
    with Path(source).open("rb") as handle:
        head = handle.read(2)
    return len(head) == 2 and head[0] == 0x1F and head[1] == 0x8B


def iter_tar_chunks(source: bytes | Path, *, limit: int = TEMPLATE_STREAM_BOUND) -> Iterator[bytes]:
    """Yield plain tar chunks, streaming gunzip on the client when `source` is gzip-compressed."""
    import io

    gzipped = is_gzip_tar(source)
    total = 0

    def emit(chunk: bytes) -> bytes:
        nonlocal total
        total += len(chunk)
        if total > limit:
            raise ValueError(f"Uncompressed template tar exceeds {limit} bytes")
        return chunk

    if isinstance(source, (bytes, bytearray)) and not gzipped:
        yield emit(bytes(source))
        return

    stream = io.BytesIO(source) if isinstance(source, (bytes, bytearray)) else Path(source).open("rb")
    with stream as handle:
        if not gzipped:
            while chunk := handle.read(65536):
                yield emit(chunk)
            return
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        saw_input = False
        while raw := handle.read(65536):
            saw_input = True
            pending = raw
            while pending:
                out = decoder.decompress(pending, 65536)
                if out:
                    yield emit(out)
                if decoder.unconsumed_tail:
                    pending = decoder.unconsumed_tail
                elif decoder.eof and decoder.unused_data:
                    pending = decoder.unused_data
                    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                else:
                    pending = b""
        tail = decoder.flush()
        if tail:
            yield emit(tail)
        if not saw_input or not decoder.eof:
            raise ValueError("Truncated gzip archive")
