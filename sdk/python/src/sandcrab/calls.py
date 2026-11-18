"""Caller-owned Host Call dispatchers and idempotency ledgers."""
from __future__ import annotations

import asyncio
import base64
from concurrent.futures import Future
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import inspect
import json
import threading
from typing import Any, Awaitable, Callable, Iterator, Protocol

from .errors import ProtocolError

CALL_PAYLOAD_LIMIT = 65536


class ReplyLedger(Protocol):
    """Idempotency ledger mapping `(run_id, call_id)` to `(request_sha256, reply_bytes)`.

    In-memory ledgers cover one caller process only. Applications with durable outside
    effects should supply a persistent ledger tied to their business store.
    """

    def get(self, run_id: str, call_id: str) -> tuple[str, bytes] | None: ...
    def put(self, run_id: str, call_id: str, request_sha256: str, reply: bytes) -> None: ...


class _PendingCalls:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending: dict[tuple[str, str], tuple[str, Future[bytes]]] = {}

    @contextmanager
    def claim(self, context: CallContext) -> Iterator[tuple[Future[bytes], bool]]:
        key = (context.run_id, context.call_id)
        with self._lock:
            entry = self._pending.get(key)
            if entry is None:
                reply: Future[bytes] = Future()
                self._pending[key] = context.request_sha256, reply
            else:
                digest, reply = entry
                if digest != context.request_sha256:
                    raise ProtocolError(f"Call {context.call_id} changed its request bytes")
        try:
            yield reply, entry is None
        except BaseException as error:
            if entry is None:
                reply.set_exception(error)
            raise
        finally:
            if entry is None:
                with self._lock:
                    del self._pending[key]


class InMemoryReplyLedger:
    """Thread-safe in-process reply ledger for one caller lifetime."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[tuple[str, str], tuple[str, bytes]] = {}
        self._pending = _PendingCalls()

    def get(self, run_id: str, call_id: str) -> tuple[str, bytes] | None:
        with self._lock:
            return self._entries.get((run_id, call_id))

    def put(self, run_id: str, call_id: str, request_sha256: str, reply: bytes) -> None:
        with self._lock:
            existing = self._entries.get((run_id, call_id))
            if existing is not None and existing != (request_sha256, reply):
                raise ProtocolError(f"Conflicting reply recorded for call {call_id}")
            self._entries[(run_id, call_id)] = (request_sha256, bytes(reply))

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


@dataclass(frozen=True)
class CallContext:
    run_id: str
    server_id: str
    call_id: str
    guest_request_id: str
    sequence: int
    request_sha256: str
    cursor: str | None


def _encode_reply(result: bytes | bytearray | memoryview | str | dict | list) -> bytes:
    if isinstance(result, (bytes, bytearray, memoryview)):
        data = bytes(result)
    elif isinstance(result, str):
        data = result.encode("utf-8")
    else:
        data = json.dumps(result, separators=(",", ":")).encode("utf-8")
    if len(data) > CALL_PAYLOAD_LIMIT:
        raise ValueError(f"Host-call reply exceeds {CALL_PAYLOAD_LIMIT} bytes")
    return data


def _decode_call_event(run_id: str, server_id: str, frame: dict) -> tuple[CallContext, bytes]:
    data = frame.get("data")
    if not isinstance(data, dict):
        raise ProtocolError("Malformed host-call event frame")
    raw_b64 = data.get("base64")
    if not isinstance(raw_b64, str):
        raise ProtocolError("Host-call event is missing base64 payload")
    payload = base64.b64decode(raw_b64, validate=True)
    if len(payload) > CALL_PAYLOAD_LIMIT:
        raise ProtocolError("Host-call request exceeds payload bound")
    digest = hashlib.sha256(payload).hexdigest()
    declared = data.get("requestSha256")
    if declared is not None and declared != digest:
        raise ProtocolError("Host-call payload digest mismatch")
    call_id = data.get("id")
    guest_id = data.get("requestId", "")
    sequence = data.get("sequence", 0)
    if not isinstance(call_id, str) or not call_id or call_id == guest_id:
        raise ProtocolError("Invalid daemon host-call handle")
    ctx = CallContext(
        run_id=run_id,
        server_id=server_id,
        call_id=call_id,
        guest_request_id=str(guest_id),
        sequence=int(sequence),
        request_sha256=digest,
        cursor=frame.get("id"),
    )
    return ctx, payload


class HostCallDispatcher:
    """Declarative caller-side dispatcher for synchronous Host Calls.

    Handlers execute solely in the caller's process; Sandcrab relays opaque bytes.
    Any unhandled exception in a handler cancels the sandbox command before reraising.
    """

    def __init__(
        self,
        *,
        ledger: ReplyLedger | None = None,
        operation_field: str = "operation",
    ) -> None:
        self.ledger: ReplyLedger = ledger if ledger is not None else InMemoryReplyLedger()
        self._pending = self.ledger._pending if isinstance(self.ledger, InMemoryReplyLedger) else _PendingCalls()
        self._operation_field = operation_field
        self._raw_handler: Callable[[bytes, CallContext], Any] | None = None
        self._json_handlers: dict[str, Callable[[dict[str, Any], CallContext], Any]] = {}

    def on_call(self, fn: Callable[[bytes, CallContext], Any]) -> Callable[[bytes, CallContext], Any]:
        """Register a handler receiving `(payload_bytes, CallContext)`."""
        self._raw_handler = fn
        return fn

    def on_json(
        self, operation: str | None = None
    ) -> Callable[[Callable[[dict[str, Any], CallContext], Any]], Callable[[dict[str, Any], CallContext], Any]]:
        """Register a handler for JSON object requests matching `request[operation_field] == operation`."""

        def decorator(
            fn: Callable[[dict[str, Any], CallContext], Any],
        ) -> Callable[[dict[str, Any], CallContext], Any]:
            key = operation if operation is not None else fn.__name__
            self._json_handlers[key] = fn
            return fn

        return decorator

    def handle_payload(self, payload: bytes, context: CallContext) -> bytes:
        with self._pending.claim(context) as (reply, owner):
            if owner:
                reply.set_result(self._dispatch(payload, context))
            return reply.result()

    def _dispatch(self, payload: bytes, context: CallContext) -> bytes:
        cached = self.ledger.get(context.run_id, context.call_id)
        if cached is not None:
            prior_sha, prior_reply = cached
            if prior_sha != context.request_sha256:
                raise ProtocolError(f"Call {context.call_id} changed its request bytes")
            return prior_reply

        if self._json_handlers:
            parsed = json.loads(payload.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise PermissionError("Host-call JSON payload must be an object")
            op = parsed.get(self._operation_field)
            if isinstance(op, str) and op in self._json_handlers:
                reply = _encode_reply(self._json_handlers[op](parsed, context))
                self.ledger.put(context.run_id, context.call_id, context.request_sha256, reply)
                return reply
            if self._raw_handler is None:
                raise PermissionError(f"Unauthorized or unknown host-call operation: {op!r}")

        if self._raw_handler is None:
            raise PermissionError("No host-call handler registered")
        reply = _encode_reply(self._raw_handler(payload, context))
        self.ledger.put(context.run_id, context.call_id, context.request_sha256, reply)
        return reply

    def drive(self, client: Any, run_id: str, *, expected_server_id: str | None = None, after: str | None = None) -> dict:
        """Observe `/v1/runs/{id}/calls/events`, invoke handlers, post replies and return terminal run summary."""
        cursor = after
        verified_epoch = expected_server_id
        try:
            for _ in range(64):
                reconnect = False
                for frame in client.stream_call_events(run_id, after=cursor):
                    if frame.get("id"):
                        cursor = frame["id"]
                    kind = frame.get("event")
                    if kind == "state":
                        state = frame.get("data") or {}
                        if state.get("runId") != run_id:
                            raise ProtocolError("Host-call stream runId mismatch")
                        epoch = state.get("serverId")
                        if not isinstance(epoch, str) or (verified_epoch and epoch != verified_epoch):
                            raise ProtocolError("Host-call stream serverId mismatch")
                        verified_epoch = epoch
                    elif kind == "call":
                        if not verified_epoch:
                            raise ProtocolError("Host-call event preceded initial state frame")
                        ctx, payload = _decode_call_event(run_id, verified_epoch, frame)
                        reply = self.handle_payload(payload, ctx)
                        client.reply_call(run_id, ctx.call_id, reply)
                    elif kind == "result":
                        data = frame.get("data") or {}
                        return data.get("run") or data
                    elif kind == "error":
                        code = (frame.get("data") or {}).get("code", "CALL_STREAM_ERROR")
                        if code == "OBSERVATION_TIMEOUT" and cursor:
                            reconnect = True
                            break
                        raise ProtocolError(f"Host-call stream ended with error: {code}")
                if not reconnect:
                    break
        except BaseException:
            try:
                client.cancel_run(run_id)
            except BaseException:
                pass
            raise
        raise ProtocolError("Host-call stream closed before terminal result frame")


class AsyncHostCallDispatcher:
    """Declarative caller-side dispatcher for async Host Calls."""

    def __init__(
        self,
        *,
        ledger: ReplyLedger | None = None,
        operation_field: str = "operation",
    ) -> None:
        self.ledger: ReplyLedger = ledger if ledger is not None else InMemoryReplyLedger()
        self._pending = self.ledger._pending if isinstance(self.ledger, InMemoryReplyLedger) else _PendingCalls()
        self._operation_field = operation_field
        self._raw_handler: Callable[[bytes, CallContext], Any] | None = None
        self._json_handlers: dict[str, Callable[[dict[str, Any], CallContext], Any]] = {}

    def on_call(self, fn: Callable[[bytes, CallContext], Any]) -> Callable[[bytes, CallContext], Any]:
        self._raw_handler = fn
        return fn

    def on_json(
        self, operation: str | None = None
    ) -> Callable[[Callable[[dict[str, Any], CallContext], Any]], Callable[[dict[str, Any], CallContext], Any]]:
        def decorator(
            fn: Callable[[dict[str, Any], CallContext], Any],
        ) -> Callable[[dict[str, Any], CallContext], Any]:
            key = operation if operation is not None else fn.__name__
            self._json_handlers[key] = fn
            return fn

        return decorator

    async def handle_payload(self, payload: bytes, context: CallContext) -> bytes:
        with self._pending.claim(context) as (reply, owner):
            if owner:
                value = await self._dispatch(payload, context)
                reply.set_result(value)
                return value
            return await asyncio.shield(asyncio.wrap_future(reply))

    async def _dispatch(self, payload: bytes, context: CallContext) -> bytes:
        cached = self.ledger.get(context.run_id, context.call_id)
        if cached is not None:
            prior_sha, prior_reply = cached
            if prior_sha != context.request_sha256:
                raise ProtocolError(f"Call {context.call_id} changed its request bytes")
            return prior_reply

        async def _maybe_await(value: Any | Awaitable[Any]) -> Any:
            return await value if inspect.isawaitable(value) else value

        if self._json_handlers:
            parsed = json.loads(payload.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise PermissionError("Host-call JSON payload must be an object")
            op = parsed.get(self._operation_field)
            if isinstance(op, str) and op in self._json_handlers:
                result = await _maybe_await(self._json_handlers[op](parsed, context))
                reply = _encode_reply(result)
                self.ledger.put(context.run_id, context.call_id, context.request_sha256, reply)
                return reply
            if self._raw_handler is None:
                raise PermissionError(f"Unauthorized or unknown host-call operation: {op!r}")

        if self._raw_handler is None:
            raise PermissionError("No host-call handler registered")
        result = await _maybe_await(self._raw_handler(payload, context))
        reply = _encode_reply(result)
        self.ledger.put(context.run_id, context.call_id, context.request_sha256, reply)
        return reply

    async def drive(
        self, client: Any, run_id: str, *, expected_server_id: str | None = None, after: str | None = None
    ) -> dict:
        cursor = after
        verified_epoch = expected_server_id
        try:
            for _ in range(64):
                reconnect = False
                async for frame in client.stream_call_events(run_id, after=cursor):
                    if frame.get("id"):
                        cursor = frame["id"]
                    kind = frame.get("event")
                    if kind == "state":
                        state = frame.get("data") or {}
                        if state.get("runId") != run_id:
                            raise ProtocolError("Host-call stream runId mismatch")
                        epoch = state.get("serverId")
                        if not isinstance(epoch, str) or (verified_epoch and epoch != verified_epoch):
                            raise ProtocolError("Host-call stream serverId mismatch")
                        verified_epoch = epoch
                    elif kind == "call":
                        if not verified_epoch:
                            raise ProtocolError("Host-call event preceded initial state frame")
                        ctx, payload = _decode_call_event(run_id, verified_epoch, frame)
                        reply = await self.handle_payload(payload, ctx)
                        await client.reply_call(run_id, ctx.call_id, reply)
                    elif kind == "result":
                        data = frame.get("data") or {}
                        return data.get("run") or data
                    elif kind == "error":
                        code = (frame.get("data") or {}).get("code", "CALL_STREAM_ERROR")
                        if code == "OBSERVATION_TIMEOUT" and cursor:
                            reconnect = True
                            break
                        raise ProtocolError(f"Host-call stream ended with error: {code}")
                if not reconnect:
                    break
        except BaseException:
            try:
                await client.cancel_run(run_id)
            except BaseException:
                pass
            raise
        raise ProtocolError("Host-call stream closed before terminal result frame")
