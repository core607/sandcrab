"""Synchronous and asynchronous native clients for Sandcrab."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import os
from pathlib import Path
import threading
import time
from typing import Any, AsyncIterator, Callable, Iterator, Mapping, Sequence
from urllib.parse import urlencode
import uuid
import warnings

import httpx

from sandcrab_templates.client import PublicationUncertain, recipe_id
from ._version import __version__

from ._wire import (
    JSON_BOUND,
    TRANSFER_BOUND,
    check_digest,
    check_profile,
    check_relative_path,
    check_uuid,
    format_byte_range,
    iter_tar_chunks,
    parse_json_response,
    parse_sse_lines,
    parse_sse_lines_async,
    resolve_connection,
)
from .calls import AsyncHostCallDispatcher, HostCallDispatcher
from .errors import CommandFailedError, ProtocolError, SandcrabError, TransportUncertainError


def _report_release(info: dict[str, Any], previous: str | None) -> str | None:
    advertised = info.get("releaseVersion")
    if isinstance(advertised, str) and advertised != __version__ and advertised != previous:
        warnings.warn(f"Sandcrab SDK {__version__} connected to service {advertised}",
                      RuntimeWarning, stacklevel=3)
        return advertised
    return previous


def _resources(memory_bytes: int | None, cpu_quota_percent: int | None) -> dict[str, int] | None:
    if memory_bytes is None and cpu_quota_percent is None:
        return None
    out: dict[str, int] = {}
    if memory_bytes is not None:
        out["memoryBytes"] = int(memory_bytes)
    if cpu_quota_percent is not None:
        out["cpuQuotaPercent"] = int(cpu_quota_percent)
    return out


def _reply_payload(reply: bytes | bytearray | memoryview | str) -> dict[str, str]:
    raw = reply.encode("utf-8") if isinstance(reply, str) else bytes(reply)
    if len(raw) > 65536:
        raise ValueError("Host-call reply exceeds 65536 bytes")
    return {"base64": base64.b64encode(raw).decode("ascii")}


def _verify_download(
    status: int,
    headers: httpx.Headers,
    body: bytes,
    *,
    expect_partial: bool,
    expect_etag: bool,
    expected_server_id: str | None,
) -> bytes:
    if expected_server_id:
        served_epoch = headers.get("x-sandcrab-server-id")
        if served_epoch and served_epoch != expected_server_id:
            raise ProtocolError("Daemon serverId changed during file read")
    expected_status = 206 if expect_partial else 200
    if status != expected_status:
        raise ProtocolError(f"Unexpected HTTP status {status} (expected {expected_status})")
    if expect_etag:
        etag = headers.get("etag", "")
        expected = '"' + hashlib.sha256(body).hexdigest() + '"'
        if etag != expected:
            raise ProtocolError("Downloaded file checksum did not match ETag")
    return body


class Session:
    """Context-managed handle to an isolated persistent Sandcrab session."""

    def __init__(
        self,
        client: SandcrabClient,
        data: dict[str, Any],
        *,
        auto_close: bool = True,
        keep_result: bool = False,
    ) -> None:
        self.client = client
        self.data = data
        self.id: str = data["id"]
        self.server_id: str = data["serverId"]
        self.profile: str = data["profile"]
        self._auto_close = auto_close
        self._keep_result = keep_result
        self._closed = False

    def __enter__(self) -> Session:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if not self._auto_close:
            return
        try:
            self.close(forget=not self._keep_result)
        except BaseException:
            if exc_type is None:
                raise

    def refresh(self) -> dict[str, Any]:
        self.data = self.client.get_session(self.id)
        return self.data

    def renew(self, ttl_ms: int) -> dict[str, Any]:
        self.data = self.client.renew_session(self.id, ttl_ms)
        return self.data

    def exec(
        self,
        command: str,
        *,
        timeout_ms: int | None = None,
        output_limit_bytes: int | None = None,
        on_output: Callable[[str, bytes], Any] | None = None,
        dispatcher: HostCallDispatcher | None = None,
        keep_result: bool = False,
        check: bool = False,
    ) -> dict[str, Any]:
        return self.client.session_exec(
            self.id,
            command,
            timeout_ms=timeout_ms,
            output_limit_bytes=output_limit_bytes,
            on_output=on_output,
            dispatcher=dispatcher,
            keep_result=keep_result,
            check=check,
        )

    def open_shell(self, *, keep_result: bool = False, auto_close: bool = True) -> Session:
        return self.client.open_shell(self.id, keep_result=keep_result, auto_close=auto_close)

    def write_file(
        self,
        path: str,
        data: bytes | bytearray | memoryview | str,
        *,
        parents: bool = False,
        replace: bool = True,
        mode: int | None = None,
    ) -> dict[str, Any]:
        return self.client.write_file(
            self.id, path, data, parents=parents, replace=replace, mode=mode
        )

    def read_file(
        self,
        path: str,
        *,
        byte_range: tuple[int | None, int | None] | str | None = None,
        offset: int | None = None,
        limit: int | None = None,
    ) -> bytes:
        return self.client.read_file(
            self.id, path, byte_range=byte_range, offset=offset, limit=limit
        )

    def read_text(
        self,
        path: str,
        *,
        offset: int | None = None,
        limit: int | None = None,
        encoding: str = "utf-8",
    ) -> str:
        return self.read_file(path, offset=offset, limit=limit).decode(encoding)

    def mkdir(self, path: str, *, mode: int | None = None) -> dict[str, Any]:
        return self.client.mkdir(self.id, path, mode=mode)

    def list_files(self, path: str = ".", *, depth: int = 1) -> list[dict[str, Any]]:
        return self.client.list_files(self.id, path, depth=depth)

    def search_files(self, pattern: str, *, path: str = ".") -> list[dict[str, Any]]:
        return self.client.search_files(self.id, pattern, path=path)

    def remove_file(self, path: str, *, recursive: bool = False) -> dict[str, Any]:
        return self.client.remove_file(self.id, path, recursive=recursive)

    def diff(self) -> bytes:
        return self.client.session_diff(self.id)

    def snapshot(
        self,
        path: str = ".",
        *,
        format: str = "tar",
        frozen: bool = False,
        scope: str | None = None,
    ) -> bytes:
        return self.client.session_snapshot(
            self.id, path=path, format=format, frozen=frozen, scope=scope
        )

    def close(self, *, forget: bool = False) -> dict[str, Any]:
        if not self._closed:
            self.data = self.client.close_session(self.id, forget=forget)
            self._closed = True
        elif forget:
            self.client.forget_session(self.id)
        return self.data

    def forget(self) -> dict[str, Any]:
        return self.client.forget_session(self.id)


class SandcrabClient:
    """Synchronous client for Sandcrab's native Unix-socket and loopback-HTTP control API."""

    def __init__(
        self,
        *,
        socket_path: str | Path | None = None,
        endpoint: str | None = None,
        token: str | None = None,
        token_file: str | Path | None = None,
        default_profile: str | None = None,
        timeout: float = 75.0,
        transport: httpx.BaseTransport | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        environ = os.environ if env is None else env
        if transport is not None and socket_path is None and endpoint is None and not environ.get("SANDCRAB_SOCKET") and not environ.get("SANDCRAB_ENDPOINT"):
            uds, base_url, headers = None, "http://sandcrab", {}
        else:
            uds, base_url, headers = resolve_connection(
                socket_path=socket_path,
                endpoint=endpoint,
                token=token,
                token_file=token_file,
                env=environ,
                require_socket_stat=transport is None,
            )
        profile = default_profile if default_profile is not None else environ.get("SANDCRAB_PROFILE")
        self.default_profile: str | None = check_profile(profile) if profile else None
        chosen_transport = transport if transport is not None else (httpx.HTTPTransport(uds=uds) if uds else None)
        self._http = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=httpx.Timeout(timeout, connect=min(10.0, timeout)),
            follow_redirects=False,
            trust_env=False,
            transport=chosen_transport,
            event_hooks={"request": [self._discover_before_request]},
        )
        self._server_id: str | None = None
        self._warned_release: str | None = None
        self._discovery_lock = threading.Lock()

    def __enter__(self) -> SandcrabClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        self._http.close()

    def _resolve_profile(self, profile: str | None) -> str:
        chosen = profile if profile is not None else self.default_profile
        if not chosen:
            raise ValueError("Pass profile or set default_profile / SANDCRAB_PROFILE")
        return check_profile(chosen)

    def _discover_before_request(self, request: httpx.Request) -> None:
        if self._server_id is None and request.url.path != "/v1/info":
            self._ensure_server_id()

    def _ensure_server_id(self) -> str:
        if self._server_id is None:
            with self._discovery_lock:
                if self._server_id is None:
                    self.info()
        if self._server_id is None:
            raise ProtocolError("Discovery returned no serverId")
        return self._server_id

    def _request_json(
        self,
        method: str,
        route: str,
        *,
        json_body: dict[str, Any] | None = None,
        content: Any = None,
        headers: Mapping[str, str] | None = None,
        recovery_id: str | None = None,
        uncertain_op: str | None = None,
    ) -> dict[str, Any]:
        if uncertain_op and self._server_id is None:
            self._ensure_server_id()
        kwargs: dict[str, Any] = {}
        if headers:
            kwargs["headers"] = dict(headers)
        if content is not None:
            kwargs["content"] = content
        elif json_body is not None:
            kwargs["json"] = json_body
        elif method == "POST":
            kwargs["json"] = {}
        try:
            with self._http.stream(method, route, **kwargs) as response:
                buf = bytearray()
                for chunk in response.iter_bytes():
                    buf.extend(chunk)
                    if len(buf) > JSON_BOUND:
                        raise ProtocolError("JSON response exceeded client bound")
                status = response.status_code
        except (httpx.TransportError, TimeoutError) as error:
            if uncertain_op and recovery_id:
                raise TransportUncertainError(uncertain_op, recovery_id, error) from error
            raise
        return parse_json_response(status, buf, recovery_id=recovery_id)

    def _request_bytes(
        self,
        method: str,
        route: str,
        *,
        json_body: dict[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        expect_partial: bool = False,
        expect_etag: bool = False,
    ) -> bytes:
        kwargs: dict[str, Any] = {}
        if headers:
            kwargs["headers"] = dict(headers)
        if json_body is not None:
            kwargs["json"] = json_body
        elif method == "POST":
            kwargs["json"] = {}
        with self._http.stream(method, route, **kwargs) as response:
            buf = bytearray()
            limit = JSON_BOUND if response.status_code >= 400 else TRANSFER_BOUND
            for chunk in response.iter_bytes():
                buf.extend(chunk)
                if len(buf) > limit:
                    raise ProtocolError("Binary response exceeded client bound")
            if response.status_code >= 400:
                parse_json_response(response.status_code, buf)
            return _verify_download(
                response.status_code,
                response.headers,
                bytes(buf),
                expect_partial=expect_partial,
                expect_etag=expect_etag,
                expected_server_id=self._server_id,
            )

    def info(self) -> dict[str, Any]:
        data = self._request_json("GET", "/v1/info")
        server_id = data.get("serverId")
        if isinstance(server_id, str):
            self._server_id = check_uuid(server_id, "serverId")
        self._warned_release = _report_release(data, self._warned_release)
        return data

    def openapi(self, capability: str | None = None) -> dict[str, Any]:
        route = "/v1/openapi" if not capability else "/v1/openapi?" + urlencode({"capability": capability})
        return self._request_json("GET", route)

    # --- Runs ---

    def submit_run(
        self,
        command: Sequence[str],
        *,
        profile: str | None = None,
        id: str | None = None,
        timeout_ms: int | None = None,
        output_limit_bytes: int | None = None,
        memory_bytes: int | None = None,
        cpu_quota_percent: int | None = None,
        keep_result: bool = False,
    ) -> dict[str, Any]:
        if isinstance(command, (str, bytes)) or not command:
            raise ValueError("command must be a non-empty sequence of argument strings")
        run_id = check_uuid(id, "runId") if id is not None else str(uuid.uuid4())
        body: dict[str, Any] = {
            "id": run_id,
            "serverId": self._ensure_server_id(),
            "profile": self._resolve_profile(profile),
            "command": [str(arg) for arg in command],
        }
        if timeout_ms is not None:
            body["timeoutMillis"] = int(timeout_ms)
        if output_limit_bytes is not None:
            body["outputLimitBytes"] = int(output_limit_bytes)
        res = _resources(memory_bytes, cpu_quota_percent)
        if res is not None:
            body["resources"] = res
        if keep_result:
            body["keepResult"] = True
        return self._request_json(
            "POST", "/v1/runs", json_body=body, recovery_id=run_id, uncertain_op="submit_run"
        )

    def get_run(self, run_id: str) -> dict[str, Any]:
        check_uuid(run_id, "runId")
        return self._request_json("GET", f"/v1/runs/{run_id}", recovery_id=run_id)

    def list_runs(self, *, after: str | None = None) -> dict[str, Any]:
        route = "/v1/runs"
        if after is not None:
            route += "?" + urlencode({"after": check_uuid(after, "after")})
        return self._request_json("GET", route)

    def cancel_run(self, run_id: str) -> dict[str, Any]:
        check_uuid(run_id, "runId")
        return self._request_json("POST", f"/v1/runs/{run_id}/cancel", recovery_id=run_id)

    def forget_run(self, run_id: str) -> dict[str, Any]:
        check_uuid(run_id, "runId")
        return self._request_json("POST", f"/v1/runs/{run_id}/forget", recovery_id=run_id)

    def wait_run(
        self, run_id: str, *, poll_interval: float = 0.025, timeout: float | None = None
    ) -> dict[str, Any]:
        check_uuid(run_id, "runId")
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            run = self.get_run(run_id)
            state = run.get("state")
            if state == "closing":
                raise SandcrabError(503, "CONTAINMENT_UNCONFIRMED", recovery_id=run_id)
            if state not in ("queued", "running"):
                return run
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError(f"Timed out waiting for run {run_id}")
            time.sleep(poll_interval)

    def stream_events(self, run_id: str, *, after: str | None = None) -> Iterator[dict[str, Any]]:
        check_uuid(run_id, "runId")
        headers = {"Last-Event-ID": after} if after else {}
        with self._http.stream("GET", f"/v1/runs/{run_id}/events", headers=headers) as response:
            if response.status_code >= 400:
                raw = response.read()
                parse_json_response(response.status_code, raw, recovery_id=run_id)
            yield from parse_sse_lines(response.iter_lines())

    def stream_call_events(self, run_id: str, *, after: str | None = None) -> Iterator[dict[str, Any]]:
        check_uuid(run_id, "runId")
        headers = {"Last-Event-ID": after} if after else {}
        with self._http.stream("GET", f"/v1/runs/{run_id}/calls/events", headers=headers) as response:
            if response.status_code >= 400:
                raw = response.read()
                parse_json_response(response.status_code, raw, recovery_id=run_id)
            yield from parse_sse_lines(response.iter_lines())

    def list_calls(self, run_id: str) -> dict[str, Any]:
        check_uuid(run_id, "runId")
        return self._request_json("GET", f"/v1/runs/{run_id}/calls", recovery_id=run_id)

    def reply_call(
        self, run_id: str, call_id: str, reply: bytes | bytearray | memoryview | str
    ) -> dict[str, Any]:
        check_uuid(run_id, "runId")
        check_uuid(call_id, "callId")
        return self._request_json(
            "POST",
            f"/v1/runs/{run_id}/calls/{call_id}/reply",
            json_body=_reply_payload(reply),
            recovery_id=run_id,
        )

    def _observe_output(self, run_id: str, on_output: Callable[[str, bytes], Any]) -> None:
        cursor: str | None = None
        for _ in range(64):
            reconnect = False
            for frame in self.stream_events(run_id, after=cursor):
                if frame.get("id"):
                    cursor = frame["id"]
                kind = frame.get("event")
                if kind in ("stdout", "stderr"):
                    chunk = base64.b64decode(frame["data"]["base64"], validate=True)
                    on_output(kind, chunk)
                elif kind == "result":
                    return
                elif kind == "error":
                    code = (frame.get("data") or {}).get("code", "EVENT_STREAM_ERROR")
                    if code == "OBSERVATION_TIMEOUT" and cursor:
                        reconnect = True
                        break
                    raise ProtocolError(f"Output stream ended with error: {code}")
            if not reconnect:
                break
        raise ProtocolError("Output stream closed before terminal result frame")

    def _complete_submitted_run(
        self,
        run_id: str,
        *,
        on_output: Callable[[str, bytes], Any] | None,
        dispatcher: HostCallDispatcher | None,
        keep_result: bool,
        check: bool,
    ) -> dict[str, Any]:
        output_error: list[BaseException] = []
        worker: threading.Thread | None = None
        if dispatcher is not None and on_output is not None:
            def _bg() -> None:
                try:
                    self._observe_output(run_id, on_output)
                except BaseException as err:  # pragma: no cover - surfaced below
                    output_error.append(err)

            worker = threading.Thread(target=_bg, daemon=True)
            worker.start()

        if dispatcher is not None:
            dispatcher.drive(self, run_id, expected_server_id=self._server_id)
        elif on_output is not None:
            self._observe_output(run_id, on_output)

        if worker is not None:
            worker.join(timeout=10.0)
            if output_error:
                raise output_error[0]

        result = self.wait_run(run_id)
        if not keep_result:
            try:
                self.forget_run(run_id)
            except SandcrabError:
                pass
        if check and result.get("state") != "succeeded":
            raise CommandFailedError(result)
        return result

    def run(
        self,
        command: Sequence[str],
        *,
        profile: str | None = None,
        id: str | None = None,
        timeout_ms: int | None = None,
        output_limit_bytes: int | None = None,
        memory_bytes: int | None = None,
        cpu_quota_percent: int | None = None,
        on_output: Callable[[str, bytes], Any] | None = None,
        dispatcher: HostCallDispatcher | None = None,
        keep_result: bool = False,
        check: bool = False,
    ) -> dict[str, Any]:
        retain_while_running = keep_result or dispatcher is not None or on_output is not None
        submitted = self.submit_run(
            command,
            profile=profile,
            id=id,
            timeout_ms=timeout_ms,
            output_limit_bytes=output_limit_bytes,
            memory_bytes=memory_bytes,
            cpu_quota_percent=cpu_quota_percent,
            keep_result=retain_while_running,
        )
        return self._complete_submitted_run(
            submitted["id"],
            on_output=on_output,
            dispatcher=dispatcher,
            keep_result=keep_result,
            check=check,
        )

    # --- Sessions ---

    def open_session(
        self,
        *,
        profile: str | None = None,
        id: str | None = None,
        ttl_ms: int | None = None,
        volume_id: str | None = None,
        template_id: str | None = None,
        rootfs: bool = False,
        memory_bytes: int | None = None,
        cpu_quota_percent: int | None = None,
        keep_result: bool = False,
        auto_close: bool = True,
    ) -> Session:
        session_id = check_uuid(id, "sessionId") if id is not None else str(uuid.uuid4())
        body: dict[str, Any] = {
            "id": session_id,
            "serverId": self._ensure_server_id(),
            "profile": self._resolve_profile(profile),
        }
        if ttl_ms is not None:
            body["ttlMillis"] = int(ttl_ms)
        if volume_id is not None:
            body["volumeId"] = check_uuid(volume_id, "volumeId")
        if template_id is not None:
            body["templateId"] = check_digest(template_id, "templateId")
        if rootfs:
            body["rootfs"] = True
        res = _resources(memory_bytes, cpu_quota_percent)
        if res is not None:
            body["resources"] = res
        if keep_result:
            body["keepResult"] = True
        self._request_json(
            "POST", "/v1/sessions", json_body=body, recovery_id=session_id, uncertain_op="open_session"
        )
        ready = self.wait_session(session_id, terminal=False)
        if ready.get("state") != "ready":
            code = ready.get("code") or "SESSION_FAILED"
            raise SandcrabError(409, str(code), recovery_id=session_id)
        return Session(self, ready, auto_close=auto_close, keep_result=keep_result)

    def open_shell(
        self, parent_session_id: str, *, id: str | None = None, keep_result: bool = False, auto_close: bool = True
    ) -> Session:
        check_uuid(parent_session_id, "parentSessionId")
        shell_id = check_uuid(id, "sessionId") if id is not None else str(uuid.uuid4())
        body: dict[str, Any] = {"id": shell_id, "serverId": self._ensure_server_id()}
        if keep_result:
            body["keepResult"] = True
        self._request_json(
            "POST",
            f"/v1/sessions/{parent_session_id}/shells",
            json_body=body,
            recovery_id=shell_id,
            uncertain_op="open_shell",
        )
        ready = self.wait_session(shell_id, terminal=False)
        if ready.get("state") != "ready":
            code = ready.get("code") or "SESSION_FAILED"
            raise SandcrabError(409, str(code), recovery_id=shell_id)
        return Session(self, ready, auto_close=auto_close, keep_result=keep_result)

    def get_session(self, session_id: str) -> dict[str, Any]:
        check_uuid(session_id, "sessionId")
        return self._request_json("GET", f"/v1/sessions/{session_id}", recovery_id=session_id)

    def list_sessions(self, *, after: str | None = None) -> dict[str, Any]:
        route = "/v1/sessions"
        if after is not None:
            route += "?" + urlencode({"after": check_uuid(after, "after")})
        return self._request_json("GET", route)

    def renew_session(self, session_id: str, ttl_ms: int) -> dict[str, Any]:
        check_uuid(session_id, "sessionId")
        return self._request_json(
            "POST", f"/v1/sessions/{session_id}/renew", json_body={"ttlMillis": int(ttl_ms)}, recovery_id=session_id
        )

    def wait_session(
        self,
        session_id: str,
        *,
        terminal: bool = False,
        poll_interval: float = 0.025,
        timeout: float = 35.0,
    ) -> dict[str, Any]:
        check_uuid(session_id, "sessionId")
        deadline = time.monotonic() + timeout
        while True:
            session = self.get_session(session_id)
            state = session.get("state")
            if state == "closing":
                raise SandcrabError(503, "CONTAINMENT_UNCONFIRMED", recovery_id=session_id)
            if terminal:
                if state in ("closed", "expired", "failed"):
                    return session
            elif state != "starting":
                return session
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Timed out waiting for session {session_id}")
            time.sleep(poll_interval)

    def close_session(self, session_id: str, *, forget: bool = False) -> dict[str, Any]:
        check_uuid(session_id, "sessionId")
        self._request_json("POST", f"/v1/sessions/{session_id}/close", recovery_id=session_id)
        ended = self.wait_session(session_id, terminal=True)
        if forget:
            self.forget_session(session_id)
        return ended

    def forget_session(self, session_id: str) -> dict[str, Any]:
        check_uuid(session_id, "sessionId")
        return self._request_json("POST", f"/v1/sessions/{session_id}/forget", recovery_id=session_id)

    def submit_session_command(
        self,
        session_id: str,
        command: str,
        *,
        id: str | None = None,
        timeout_ms: int | None = None,
        output_limit_bytes: int | None = None,
        keep_result: bool = False,
    ) -> dict[str, Any]:
        check_uuid(session_id, "sessionId")
        if not isinstance(command, str) or not command:
            raise ValueError("session command must be a non-empty shell string")
        run_id = check_uuid(id, "runId") if id is not None else str(uuid.uuid4())
        body: dict[str, Any] = {
            "id": run_id,
            "serverId": self._ensure_server_id(),
            "command": command,
        }
        if timeout_ms is not None:
            body["timeoutMillis"] = int(timeout_ms)
        if output_limit_bytes is not None:
            body["outputLimitBytes"] = int(output_limit_bytes)
        if keep_result:
            body["keepResult"] = True
        return self._request_json(
            "POST",
            f"/v1/sessions/{session_id}/commands",
            json_body=body,
            recovery_id=run_id,
            uncertain_op="submit_session_command",
        )

    def session_exec(
        self,
        session_id: str,
        command: str,
        *,
        id: str | None = None,
        timeout_ms: int | None = None,
        output_limit_bytes: int | None = None,
        on_output: Callable[[str, bytes], Any] | None = None,
        dispatcher: HostCallDispatcher | None = None,
        keep_result: bool = False,
        check: bool = False,
    ) -> dict[str, Any]:
        retain_while_running = keep_result or dispatcher is not None or on_output is not None
        submitted = self.submit_session_command(
            session_id,
            command,
            id=id,
            timeout_ms=timeout_ms,
            output_limit_bytes=output_limit_bytes,
            keep_result=retain_while_running,
        )
        return self._complete_submitted_run(
            submitted["id"],
            on_output=on_output,
            dispatcher=dispatcher,
            keep_result=keep_result,
            check=check,
        )

    # --- Workspace Files ---

    def write_file(
        self,
        session_id: str,
        path: str,
        data: bytes | bytearray | memoryview | str,
        *,
        parents: bool = False,
        replace: bool = True,
        mode: int | None = None,
    ) -> dict[str, Any]:
        check_uuid(session_id, "sessionId")
        rel = check_relative_path(path, allow_root=False)
        payload = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        params: dict[str, str] = {"path": rel}
        if not replace:
            params["replace"] = "false"
        if parents:
            params["parents"] = "true"
        if mode is not None:
            if not 0 <= int(mode) <= 0o777:
                raise ValueError("File mode must be between 0 and 0o777")
            params["mode"] = str(int(mode))
        route = f"/v1/sessions/{session_id}/files?" + urlencode(params)
        return self._request_json(
            "PUT",
            route,
            content=payload,
            headers={"Content-Type": "application/octet-stream", "Content-Length": str(len(payload))},
            recovery_id=session_id,
        )

    def read_file(
        self,
        session_id: str,
        path: str,
        *,
        byte_range: tuple[int | None, int | None] | str | None = None,
        offset: int | None = None,
        limit: int | None = None,
    ) -> bytes:
        check_uuid(session_id, "sessionId")
        rel = check_relative_path(path, allow_root=False)
        if byte_range is not None and (offset is not None or limit is not None):
            raise ValueError("Cannot combine byte_range with line offset or limit")
        params: dict[str, str] = {"path": rel}
        headers: dict[str, str] = {}
        line_mode = offset is not None or limit is not None
        if offset is not None:
            if int(offset) < 1:
                raise ValueError("Line offset is 1-based and must be >= 1")
            params["offset"] = str(int(offset))
        if limit is not None:
            if int(limit) < 1:
                raise ValueError("Line limit must be >= 1")
            params["limit"] = str(int(limit))
        if byte_range is not None:
            headers["Range"] = format_byte_range(byte_range)
        route = f"/v1/sessions/{session_id}/files?" + urlencode(params)
        return self._request_bytes(
            "GET",
            route,
            headers=headers,
            expect_partial=byte_range is not None,
            expect_etag=(byte_range is None and not line_mode),
        )

    def mkdir(self, session_id: str, path: str, *, mode: int | None = None) -> dict[str, Any]:
        check_uuid(session_id, "sessionId")
        rel = check_relative_path(path, allow_root=False)
        body: dict[str, Any] = {"path": rel}
        if mode is not None:
            if not 0 <= int(mode) <= 0o777:
                raise ValueError("Directory mode must be between 0 and 0o777")
            body["mode"] = int(mode)
        return self._request_json("POST", f"/v1/sessions/{session_id}/files/mkdir", json_body=body)

    def list_files(self, session_id: str, path: str = ".", *, depth: int = 1) -> list[dict[str, Any]]:
        check_uuid(session_id, "sessionId")
        rel = check_relative_path(path, allow_root=True)
        if not 0 <= int(depth) <= 64:
            raise ValueError("depth must be between 0 and 64")
        route = f"/v1/sessions/{session_id}/files/list?" + urlencode({"path": rel, "depth": str(int(depth))})
        return self._request_json("GET", route)["entries"]

    def search_files(self, session_id: str, pattern: str, *, path: str = ".") -> list[dict[str, Any]]:
        check_uuid(session_id, "sessionId")
        rel = check_relative_path(path, allow_root=True)
        if not pattern:
            raise ValueError("pattern must be non-empty")
        route = f"/v1/sessions/{session_id}/files/search?" + urlencode({"path": rel, "pattern": pattern})
        return self._request_json("GET", route)["entries"]

    def remove_file(self, session_id: str, path: str, *, recursive: bool = False) -> dict[str, Any]:
        check_uuid(session_id, "sessionId")
        rel = check_relative_path(path, allow_root=False)
        params: dict[str, str] = {"path": rel}
        if recursive:
            params["recursive"] = "true"
        route = f"/v1/sessions/{session_id}/files?" + urlencode(params)
        return self._request_json("DELETE", route)

    def session_diff(self, session_id: str) -> bytes:
        check_uuid(session_id, "sessionId")
        return self._request_bytes("GET", f"/v1/sessions/{session_id}/diff", expect_etag=True)

    def session_snapshot(
        self,
        session_id: str,
        *,
        path: str = ".",
        format: str = "tar",
        frozen: bool = False,
        scope: str | None = None,
    ) -> bytes:
        check_uuid(session_id, "sessionId")
        rel = check_relative_path(path, allow_root=format == "tar")
        body: dict[str, Any] = {"path": rel, "format": format}
        if frozen:
            body["frozen"] = True
        if scope is not None:
            body["scope"] = scope
        return self._request_bytes(
            "POST", f"/v1/sessions/{session_id}/snapshot", json_body=body, expect_etag=True
        )

    # --- Volumes ---

    def create_volume(
        self,
        *,
        profile: str | None = None,
        id: str | None = None,
        clone_from: str | None = None,
        byte_limit: int | None = None,
        inode_limit: int | None = None,
        wait: bool = True,
    ) -> dict[str, Any]:
        vol_id = check_uuid(id, "volumeId") if id is not None else str(uuid.uuid4())
        body: dict[str, Any] = {
            "id": vol_id,
            "serverId": self._ensure_server_id(),
            "profile": self._resolve_profile(profile),
        }
        if clone_from is not None:
            body["cloneFrom"] = check_uuid(clone_from, "cloneFrom")
        if byte_limit is not None:
            body["byteLimit"] = int(byte_limit)
        if inode_limit is not None:
            body["inodeLimit"] = int(inode_limit)
        created = self._request_json(
            "POST", "/v1/volumes", json_body=body, recovery_id=vol_id, uncertain_op="create_volume"
        )
        if not wait or created.get("state") == "ready":
            return created
        return self.wait_volume(vol_id, target="ready")

    def get_volume(self, volume_id: str) -> dict[str, Any]:
        check_uuid(volume_id, "volumeId")
        return self._request_json("GET", f"/v1/volumes/{volume_id}", recovery_id=volume_id)

    def list_volumes(self, *, after: str | None = None) -> dict[str, Any]:
        route = "/v1/volumes"
        if after is not None:
            route += "?" + urlencode({"after": check_uuid(after, "after")})
        return self._request_json("GET", route)

    def wait_volume(
        self, volume_id: str, *, target: str = "ready", poll_interval: float = 0.025, timeout: float = 35.0
    ) -> dict[str, Any]:
        check_uuid(volume_id, "volumeId")
        deadline = time.monotonic() + timeout
        while True:
            vol = self.get_volume(volume_id)
            state = vol.get("state")
            if state == "closing":
                raise SandcrabError(503, "STORAGE_UNCERTAIN", recovery_id=volume_id)
            if state == target:
                return vol
            if state == "failed":
                raise SandcrabError(409, str(vol.get("code") or "VOLUME_FAILED"), recovery_id=volume_id)
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Timed out waiting for volume {volume_id}")
            time.sleep(poll_interval)

    def delete_volume(self, volume_id: str, *, forget: bool = False) -> dict[str, Any]:
        check_uuid(volume_id, "volumeId")
        self._request_json("POST", f"/v1/volumes/{volume_id}/delete", recovery_id=volume_id)
        deleted = self.wait_volume(volume_id, target="deleted")
        if forget:
            self.forget_volume(volume_id)
        return deleted

    def forget_volume(self, volume_id: str) -> dict[str, Any]:
        check_uuid(volume_id, "volumeId")
        return self._request_json("POST", f"/v1/volumes/{volume_id}/forget", recovery_id=volume_id)

    # --- Templates ---

    def import_template(
        self,
        archive: bytes | Path | str,
        *,
        profile: str | None = None,
        expected_id: str | None = None,
    ) -> dict[str, Any]:
        prof = self._resolve_profile(profile)
        params: dict[str, str] = {"profile": prof}
        if expected_id is not None:
            params["expectedId"] = check_digest(expected_id, "expectedId")
            existing = self.get_template(expected_id)
            if existing is not None:
                return existing
        source = Path(archive) if isinstance(archive, str) else archive
        route = "/v1/templates?" + urlencode(params)
        try:
            return self._request_json(
                "POST",
                route,
                content=iter_tar_chunks(source),
                headers={"Content-Type": "application/x-tar"},
            )
        except (httpx.TransportError, TimeoutError):
            if expected_id is not None:
                found = self.get_template(expected_id)
                if found is not None:
                    return found
                raise PublicationUncertain(expected_id) from None
            raise

    def get_template(self, template_id: str) -> dict[str, Any] | None:
        check_digest(template_id, "templateId")
        try:
            return self._request_json("GET", f"/v1/templates/{template_id}")
        except SandcrabError as err:
            if err.status == 404 and err.code == "TEMPLATE_NOT_FOUND":
                return None
            raise

    def list_templates(self, *, after: str | None = None) -> dict[str, Any]:
        route = "/v1/templates"
        if after is not None:
            route += "?" + urlencode({"after": check_digest(after, "after")})
        return self._request_json("GET", route)

    def compose_template(self, layers: Sequence[str]) -> dict[str, Any]:
        expected = recipe_id(list(layers))
        ordered = list(layers)
        existing = self.get_template(expected)
        if existing is None:
            try:
                existing = self._request_json("POST", "/v1/templates/compose", json_body={"layers": ordered})
            except (httpx.TransportError, TimeoutError):
                existing = self.get_template(expected)
                if existing is None:
                    raise PublicationUncertain(expected) from None
        if existing.get("id") != expected or existing.get("layers") != ordered:
            raise ProtocolError("Published recipe differs from the requested layer order")
        return existing

    def delete_template(self, template_id: str) -> dict[str, Any]:
        check_digest(template_id, "templateId")
        return self._request_json("DELETE", f"/v1/templates/{template_id}")


class AsyncSession:
    """Async context-managed handle to an isolated persistent Sandcrab session."""

    def __init__(
        self,
        client: AsyncSandcrabClient,
        data: dict[str, Any],
        *,
        auto_close: bool = True,
        keep_result: bool = False,
    ) -> None:
        self.client = client
        self.data = data
        self.id: str = data["id"]
        self.server_id: str = data["serverId"]
        self.profile: str = data["profile"]
        self._auto_close = auto_close
        self._keep_result = keep_result
        self._closed = False

    async def __aenter__(self) -> AsyncSession:
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if not self._auto_close:
            return
        try:
            await self.close(forget=not self._keep_result)
        except BaseException:
            if exc_type is None:
                raise

    async def refresh(self) -> dict[str, Any]:
        self.data = await self.client.get_session(self.id)
        return self.data

    async def renew(self, ttl_ms: int) -> dict[str, Any]:
        self.data = await self.client.renew_session(self.id, ttl_ms)
        return self.data

    async def exec(
        self,
        command: str,
        *,
        timeout_ms: int | None = None,
        output_limit_bytes: int | None = None,
        on_output: Callable[[str, bytes], Any] | None = None,
        dispatcher: AsyncHostCallDispatcher | None = None,
        keep_result: bool = False,
        check: bool = False,
    ) -> dict[str, Any]:
        return await self.client.session_exec(
            self.id,
            command,
            timeout_ms=timeout_ms,
            output_limit_bytes=output_limit_bytes,
            on_output=on_output,
            dispatcher=dispatcher,
            keep_result=keep_result,
            check=check,
        )

    async def open_shell(self, *, keep_result: bool = False, auto_close: bool = True) -> AsyncSession:
        return await self.client.open_shell(self.id, keep_result=keep_result, auto_close=auto_close)

    async def write_file(
        self,
        path: str,
        data: bytes | bytearray | memoryview | str,
        *,
        parents: bool = False,
        replace: bool = True,
        mode: int | None = None,
    ) -> dict[str, Any]:
        return await self.client.write_file(
            self.id, path, data, parents=parents, replace=replace, mode=mode
        )

    async def read_file(
        self,
        path: str,
        *,
        byte_range: tuple[int | None, int | None] | str | None = None,
        offset: int | None = None,
        limit: int | None = None,
    ) -> bytes:
        return await self.client.read_file(
            self.id, path, byte_range=byte_range, offset=offset, limit=limit
        )

    async def read_text(
        self,
        path: str,
        *,
        offset: int | None = None,
        limit: int | None = None,
        encoding: str = "utf-8",
    ) -> str:
        return (await self.read_file(path, offset=offset, limit=limit)).decode(encoding)

    async def mkdir(self, path: str, *, mode: int | None = None) -> dict[str, Any]:
        return await self.client.mkdir(self.id, path, mode=mode)

    async def list_files(self, path: str = ".", *, depth: int = 1) -> list[dict[str, Any]]:
        return await self.client.list_files(self.id, path, depth=depth)

    async def search_files(self, pattern: str, *, path: str = ".") -> list[dict[str, Any]]:
        return await self.client.search_files(self.id, pattern, path=path)

    async def remove_file(self, path: str, *, recursive: bool = False) -> dict[str, Any]:
        return await self.client.remove_file(self.id, path, recursive=recursive)

    async def diff(self) -> bytes:
        return await self.client.session_diff(self.id)

    async def snapshot(
        self,
        path: str = ".",
        *,
        format: str = "tar",
        frozen: bool = False,
        scope: str | None = None,
    ) -> bytes:
        return await self.client.session_snapshot(
            self.id, path=path, format=format, frozen=frozen, scope=scope
        )

    async def close(self, *, forget: bool = False) -> dict[str, Any]:
        if not self._closed:
            self.data = await self.client.close_session(self.id, forget=forget)
            self._closed = True
        elif forget:
            await self.client.forget_session(self.id)
        return self.data

    async def forget(self) -> dict[str, Any]:
        return await self.client.forget_session(self.id)


class AsyncSandcrabClient:
    """Asynchronous client for Sandcrab's native Unix-socket and loopback-HTTP control API."""

    async def workspace_tools(self, key: str, *, profile: str | None = None,
                              template_id: str | None = None, fresh_child: bool = False):
        from .workspace import WorkspaceTools
        return await WorkspaceTools.bind(self, key, profile, template_id=template_id, fresh_child=fresh_child)

    def __init__(
        self,
        *,
        socket_path: str | Path | None = None,
        endpoint: str | None = None,
        token: str | None = None,
        token_file: str | Path | None = None,
        default_profile: str | None = None,
        timeout: float = 75.0,
        transport: httpx.AsyncBaseTransport | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        environ = os.environ if env is None else env
        if transport is not None and socket_path is None and endpoint is None and not environ.get("SANDCRAB_SOCKET") and not environ.get("SANDCRAB_ENDPOINT"):
            uds, base_url, headers = None, "http://sandcrab", {}
        else:
            uds, base_url, headers = resolve_connection(
                socket_path=socket_path,
                endpoint=endpoint,
                token=token,
                token_file=token_file,
                env=environ,
                require_socket_stat=transport is None,
            )
        profile = default_profile if default_profile is not None else environ.get("SANDCRAB_PROFILE")
        self.default_profile: str | None = check_profile(profile) if profile else None
        chosen_transport = (
            transport if transport is not None else (httpx.AsyncHTTPTransport(uds=uds) if uds else None)
        )
        self._http = httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            timeout=httpx.Timeout(timeout, connect=min(10.0, timeout)),
            follow_redirects=False,
            trust_env=False,
            transport=chosen_transport,
            event_hooks={"request": [self._discover_before_request]},
        )
        self._server_id: str | None = None
        self._warned_release: str | None = None
        self._discovery_lock = asyncio.Lock()

    async def __aenter__(self) -> AsyncSandcrabClient:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def close(self) -> None:
        await self._http.aclose()

    def _resolve_profile(self, profile: str | None) -> str:
        chosen = profile if profile is not None else self.default_profile
        if not chosen:
            raise ValueError("Pass profile or set default_profile / SANDCRAB_PROFILE")
        return check_profile(chosen)

    async def _discover_before_request(self, request: httpx.Request) -> None:
        if self._server_id is None and request.url.path != "/v1/info":
            await self._ensure_server_id()

    async def _ensure_server_id(self) -> str:
        if self._server_id is None:
            async with self._discovery_lock:
                if self._server_id is None:
                    await self.info()
        if self._server_id is None:
            raise ProtocolError("Discovery returned no serverId")
        return self._server_id

    async def _request_json(
        self,
        method: str,
        route: str,
        *,
        json_body: dict[str, Any] | None = None,
        content: Any = None,
        headers: Mapping[str, str] | None = None,
        recovery_id: str | None = None,
        uncertain_op: str | None = None,
    ) -> dict[str, Any]:
        if uncertain_op and self._server_id is None:
            await self._ensure_server_id()
        kwargs: dict[str, Any] = {}
        if headers:
            kwargs["headers"] = dict(headers)
        if content is not None:
            kwargs["content"] = content
        elif json_body is not None:
            kwargs["json"] = json_body
        elif method == "POST":
            kwargs["json"] = {}
        try:
            async with self._http.stream(method, route, **kwargs) as response:
                buf = bytearray()
                async for chunk in response.aiter_bytes():
                    buf.extend(chunk)
                    if len(buf) > JSON_BOUND:
                        raise ProtocolError("JSON response exceeded client bound")
                status = response.status_code
        except (httpx.TransportError, TimeoutError) as error:
            if uncertain_op and recovery_id:
                raise TransportUncertainError(uncertain_op, recovery_id, error) from error
            raise
        return parse_json_response(status, buf, recovery_id=recovery_id)

    async def _request_bytes(
        self,
        method: str,
        route: str,
        *,
        json_body: dict[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        expect_partial: bool = False,
        expect_etag: bool = False,
    ) -> bytes:
        kwargs: dict[str, Any] = {}
        if headers:
            kwargs["headers"] = dict(headers)
        if json_body is not None:
            kwargs["json"] = json_body
        elif method == "POST":
            kwargs["json"] = {}
        async with self._http.stream(method, route, **kwargs) as response:
            buf = bytearray()
            limit = JSON_BOUND if response.status_code >= 400 else TRANSFER_BOUND
            async for chunk in response.aiter_bytes():
                buf.extend(chunk)
                if len(buf) > limit:
                    raise ProtocolError("Binary response exceeded client bound")
            if response.status_code >= 400:
                parse_json_response(response.status_code, buf)
            return _verify_download(
                response.status_code,
                response.headers,
                bytes(buf),
                expect_partial=expect_partial,
                expect_etag=expect_etag,
                expected_server_id=self._server_id,
            )

    async def info(self) -> dict[str, Any]:
        data = await self._request_json("GET", "/v1/info")
        server_id = data.get("serverId")
        if isinstance(server_id, str):
            self._server_id = check_uuid(server_id, "serverId")
        self._warned_release = _report_release(data, self._warned_release)
        return data

    async def openapi(self, capability: str | None = None) -> dict[str, Any]:
        route = "/v1/openapi" if not capability else "/v1/openapi?" + urlencode({"capability": capability})
        return await self._request_json("GET", route)

    async def submit_run(
        self,
        command: Sequence[str],
        *,
        profile: str | None = None,
        id: str | None = None,
        timeout_ms: int | None = None,
        output_limit_bytes: int | None = None,
        memory_bytes: int | None = None,
        cpu_quota_percent: int | None = None,
        keep_result: bool = False,
    ) -> dict[str, Any]:
        if isinstance(command, (str, bytes)) or not command:
            raise ValueError("command must be a non-empty sequence of argument strings")
        run_id = check_uuid(id, "runId") if id is not None else str(uuid.uuid4())
        body: dict[str, Any] = {
            "id": run_id,
            "serverId": await self._ensure_server_id(),
            "profile": self._resolve_profile(profile),
            "command": [str(arg) for arg in command],
        }
        if timeout_ms is not None:
            body["timeoutMillis"] = int(timeout_ms)
        if output_limit_bytes is not None:
            body["outputLimitBytes"] = int(output_limit_bytes)
        res = _resources(memory_bytes, cpu_quota_percent)
        if res is not None:
            body["resources"] = res
        if keep_result:
            body["keepResult"] = True
        return await self._request_json(
            "POST", "/v1/runs", json_body=body, recovery_id=run_id, uncertain_op="submit_run"
        )

    async def get_run(self, run_id: str) -> dict[str, Any]:
        check_uuid(run_id, "runId")
        return await self._request_json("GET", f"/v1/runs/{run_id}", recovery_id=run_id)

    async def list_runs(self, *, after: str | None = None) -> dict[str, Any]:
        route = "/v1/runs"
        if after is not None:
            route += "?" + urlencode({"after": check_uuid(after, "after")})
        return await self._request_json("GET", route)

    async def cancel_run(self, run_id: str) -> dict[str, Any]:
        check_uuid(run_id, "runId")
        return await self._request_json("POST", f"/v1/runs/{run_id}/cancel", recovery_id=run_id)

    async def forget_run(self, run_id: str) -> dict[str, Any]:
        check_uuid(run_id, "runId")
        return await self._request_json("POST", f"/v1/runs/{run_id}/forget", recovery_id=run_id)

    async def wait_run(
        self, run_id: str, *, poll_interval: float = 0.025, timeout: float | None = None
    ) -> dict[str, Any]:
        check_uuid(run_id, "runId")
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            run = await self.get_run(run_id)
            state = run.get("state")
            if state == "closing":
                raise SandcrabError(503, "CONTAINMENT_UNCONFIRMED", recovery_id=run_id)
            if state not in ("queued", "running"):
                return run
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError(f"Timed out waiting for run {run_id}")
            await asyncio.sleep(poll_interval)

    async def stream_events(self, run_id: str, *, after: str | None = None) -> AsyncIterator[dict[str, Any]]:
        check_uuid(run_id, "runId")
        headers = {"Last-Event-ID": after} if after else {}
        async with self._http.stream("GET", f"/v1/runs/{run_id}/events", headers=headers) as response:
            if response.status_code >= 400:
                raw = await response.aread()
                parse_json_response(response.status_code, raw, recovery_id=run_id)
            async for frame in parse_sse_lines_async(response.aiter_lines()):
                yield frame

    async def stream_call_events(
        self, run_id: str, *, after: str | None = None
    ) -> AsyncIterator[dict[str, Any]]:
        check_uuid(run_id, "runId")
        headers = {"Last-Event-ID": after} if after else {}
        async with self._http.stream("GET", f"/v1/runs/{run_id}/calls/events", headers=headers) as response:
            if response.status_code >= 400:
                raw = await response.aread()
                parse_json_response(response.status_code, raw, recovery_id=run_id)
            async for frame in parse_sse_lines_async(response.aiter_lines()):
                yield frame

    async def list_calls(self, run_id: str) -> dict[str, Any]:
        check_uuid(run_id, "runId")
        return await self._request_json("GET", f"/v1/runs/{run_id}/calls", recovery_id=run_id)

    async def reply_call(
        self, run_id: str, call_id: str, reply: bytes | bytearray | memoryview | str
    ) -> dict[str, Any]:
        check_uuid(run_id, "runId")
        check_uuid(call_id, "callId")
        return await self._request_json(
            "POST",
            f"/v1/runs/{run_id}/calls/{call_id}/reply",
            json_body=_reply_payload(reply),
            recovery_id=run_id,
        )

    async def _observe_output(self, run_id: str, on_output: Callable[[str, bytes], Any]) -> None:
        cursor: str | None = None
        for _ in range(64):
            reconnect = False
            async for frame in self.stream_events(run_id, after=cursor):
                if frame.get("id"):
                    cursor = frame["id"]
                kind = frame.get("event")
                if kind in ("stdout", "stderr"):
                    chunk = base64.b64decode(frame["data"]["base64"], validate=True)
                    res = on_output(kind, chunk)
                    if inspect.isawaitable(res):
                        await res
                elif kind == "result":
                    return
                elif kind == "error":
                    code = (frame.get("data") or {}).get("code", "EVENT_STREAM_ERROR")
                    if code == "OBSERVATION_TIMEOUT" and cursor:
                        reconnect = True
                        break
                    raise ProtocolError(f"Output stream ended with error: {code}")
            if not reconnect:
                break
        raise ProtocolError("Output stream closed before terminal result frame")

    async def _complete_submitted_run(
        self,
        run_id: str,
        *,
        on_output: Callable[[str, bytes], Any] | None,
        dispatcher: AsyncHostCallDispatcher | None,
        keep_result: bool,
        check: bool,
    ) -> dict[str, Any]:
        tasks = []
        if dispatcher is not None:
            tasks.append(dispatcher.drive(self, run_id, expected_server_id=self._server_id))
        if on_output is not None:
            tasks.append(self._observe_output(run_id, on_output))
        if tasks:
            await asyncio.gather(*tasks)
        result = await self.wait_run(run_id)
        if not keep_result:
            try:
                await self.forget_run(run_id)
            except SandcrabError:
                pass
        if check and result.get("state") != "succeeded":
            raise CommandFailedError(result)
        return result

    async def run(
        self,
        command: Sequence[str],
        *,
        profile: str | None = None,
        id: str | None = None,
        timeout_ms: int | None = None,
        output_limit_bytes: int | None = None,
        memory_bytes: int | None = None,
        cpu_quota_percent: int | None = None,
        on_output: Callable[[str, bytes], Any] | None = None,
        dispatcher: AsyncHostCallDispatcher | None = None,
        keep_result: bool = False,
        check: bool = False,
    ) -> dict[str, Any]:
        retain_while_running = keep_result or dispatcher is not None or on_output is not None
        submitted = await self.submit_run(
            command,
            profile=profile,
            id=id,
            timeout_ms=timeout_ms,
            output_limit_bytes=output_limit_bytes,
            memory_bytes=memory_bytes,
            cpu_quota_percent=cpu_quota_percent,
            keep_result=retain_while_running,
        )
        return await self._complete_submitted_run(
            submitted["id"],
            on_output=on_output,
            dispatcher=dispatcher,
            keep_result=keep_result,
            check=check,
        )

    async def open_session(
        self,
        *,
        profile: str | None = None,
        id: str | None = None,
        ttl_ms: int | None = None,
        volume_id: str | None = None,
        template_id: str | None = None,
        rootfs: bool = False,
        memory_bytes: int | None = None,
        cpu_quota_percent: int | None = None,
        keep_result: bool = False,
        auto_close: bool = True,
    ) -> AsyncSession:
        session_id = check_uuid(id, "sessionId") if id is not None else str(uuid.uuid4())
        body: dict[str, Any] = {
            "id": session_id,
            "serverId": await self._ensure_server_id(),
            "profile": self._resolve_profile(profile),
        }
        if ttl_ms is not None:
            body["ttlMillis"] = int(ttl_ms)
        if volume_id is not None:
            body["volumeId"] = check_uuid(volume_id, "volumeId")
        if template_id is not None:
            body["templateId"] = check_digest(template_id, "templateId")
        if rootfs:
            body["rootfs"] = True
        res = _resources(memory_bytes, cpu_quota_percent)
        if res is not None:
            body["resources"] = res
        if keep_result:
            body["keepResult"] = True
        await self._request_json(
            "POST", "/v1/sessions", json_body=body, recovery_id=session_id, uncertain_op="open_session"
        )
        ready = await self.wait_session(session_id, terminal=False)
        if ready.get("state") != "ready":
            code = ready.get("code") or "SESSION_FAILED"
            raise SandcrabError(409, str(code), recovery_id=session_id)
        return AsyncSession(self, ready, auto_close=auto_close, keep_result=keep_result)

    async def open_shell(
        self,
        parent_session_id: str,
        *,
        id: str | None = None,
        keep_result: bool = False,
        auto_close: bool = True,
    ) -> AsyncSession:
        check_uuid(parent_session_id, "parentSessionId")
        shell_id = check_uuid(id, "sessionId") if id is not None else str(uuid.uuid4())
        body: dict[str, Any] = {"id": shell_id, "serverId": await self._ensure_server_id()}
        if keep_result:
            body["keepResult"] = True
        await self._request_json(
            "POST",
            f"/v1/sessions/{parent_session_id}/shells",
            json_body=body,
            recovery_id=shell_id,
            uncertain_op="open_shell",
        )
        ready = await self.wait_session(shell_id, terminal=False)
        if ready.get("state") != "ready":
            code = ready.get("code") or "SESSION_FAILED"
            raise SandcrabError(409, str(code), recovery_id=shell_id)
        return AsyncSession(self, ready, auto_close=auto_close, keep_result=keep_result)

    async def get_session(self, session_id: str) -> dict[str, Any]:
        check_uuid(session_id, "sessionId")
        return await self._request_json("GET", f"/v1/sessions/{session_id}", recovery_id=session_id)

    async def list_sessions(self, *, after: str | None = None) -> dict[str, Any]:
        route = "/v1/sessions"
        if after is not None:
            route += "?" + urlencode({"after": check_uuid(after, "after")})
        return await self._request_json("GET", route)

    async def renew_session(self, session_id: str, ttl_ms: int) -> dict[str, Any]:
        check_uuid(session_id, "sessionId")
        return await self._request_json(
            "POST", f"/v1/sessions/{session_id}/renew", json_body={"ttlMillis": int(ttl_ms)}, recovery_id=session_id
        )

    async def wait_session(
        self,
        session_id: str,
        *,
        terminal: bool = False,
        poll_interval: float = 0.025,
        timeout: float = 35.0,
    ) -> dict[str, Any]:
        check_uuid(session_id, "sessionId")
        deadline = time.monotonic() + timeout
        while True:
            session = await self.get_session(session_id)
            state = session.get("state")
            if state == "closing":
                raise SandcrabError(503, "CONTAINMENT_UNCONFIRMED", recovery_id=session_id)
            if terminal:
                if state in ("closed", "expired", "failed"):
                    return session
            elif state != "starting":
                return session
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Timed out waiting for session {session_id}")
            await asyncio.sleep(poll_interval)

    async def close_session(self, session_id: str, *, forget: bool = False) -> dict[str, Any]:
        check_uuid(session_id, "sessionId")
        await self._request_json("POST", f"/v1/sessions/{session_id}/close", recovery_id=session_id)
        ended = await self.wait_session(session_id, terminal=True)
        if forget:
            await self.forget_session(session_id)
        return ended

    async def forget_session(self, session_id: str) -> dict[str, Any]:
        check_uuid(session_id, "sessionId")
        return await self._request_json("POST", f"/v1/sessions/{session_id}/forget", recovery_id=session_id)

    async def submit_session_command(
        self,
        session_id: str,
        command: str,
        *,
        id: str | None = None,
        timeout_ms: int | None = None,
        output_limit_bytes: int | None = None,
        keep_result: bool = False,
    ) -> dict[str, Any]:
        check_uuid(session_id, "sessionId")
        if not isinstance(command, str) or not command:
            raise ValueError("session command must be a non-empty shell string")
        run_id = check_uuid(id, "runId") if id is not None else str(uuid.uuid4())
        body: dict[str, Any] = {
            "id": run_id,
            "serverId": await self._ensure_server_id(),
            "command": command,
        }
        if timeout_ms is not None:
            body["timeoutMillis"] = int(timeout_ms)
        if output_limit_bytes is not None:
            body["outputLimitBytes"] = int(output_limit_bytes)
        if keep_result:
            body["keepResult"] = True
        return await self._request_json(
            "POST",
            f"/v1/sessions/{session_id}/commands",
            json_body=body,
            recovery_id=run_id,
            uncertain_op="submit_session_command",
        )

    async def session_exec(
        self,
        session_id: str,
        command: str,
        *,
        id: str | None = None,
        timeout_ms: int | None = None,
        output_limit_bytes: int | None = None,
        on_output: Callable[[str, bytes], Any] | None = None,
        dispatcher: AsyncHostCallDispatcher | None = None,
        keep_result: bool = False,
        check: bool = False,
    ) -> dict[str, Any]:
        retain_while_running = keep_result or dispatcher is not None or on_output is not None
        submitted = await self.submit_session_command(
            session_id,
            command,
            id=id,
            timeout_ms=timeout_ms,
            output_limit_bytes=output_limit_bytes,
            keep_result=retain_while_running,
        )
        return await self._complete_submitted_run(
            submitted["id"],
            on_output=on_output,
            dispatcher=dispatcher,
            keep_result=keep_result,
            check=check,
        )

    async def write_file(
        self,
        session_id: str,
        path: str,
        data: bytes | bytearray | memoryview | str,
        *,
        parents: bool = False,
        replace: bool = True,
        mode: int | None = None,
    ) -> dict[str, Any]:
        check_uuid(session_id, "sessionId")
        rel = check_relative_path(path, allow_root=False)
        payload = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        params: dict[str, str] = {"path": rel}
        if not replace:
            params["replace"] = "false"
        if parents:
            params["parents"] = "true"
        if mode is not None:
            if not 0 <= int(mode) <= 0o777:
                raise ValueError("File mode must be between 0 and 0o777")
            params["mode"] = str(int(mode))
        route = f"/v1/sessions/{session_id}/files?" + urlencode(params)
        return await self._request_json(
            "PUT",
            route,
            content=payload,
            headers={"Content-Type": "application/octet-stream", "Content-Length": str(len(payload))},
            recovery_id=session_id,
        )

    async def read_file(
        self,
        session_id: str,
        path: str,
        *,
        byte_range: tuple[int | None, int | None] | str | None = None,
        offset: int | None = None,
        limit: int | None = None,
    ) -> bytes:
        check_uuid(session_id, "sessionId")
        rel = check_relative_path(path, allow_root=False)
        if byte_range is not None and (offset is not None or limit is not None):
            raise ValueError("Cannot combine byte_range with line offset or limit")
        params: dict[str, str] = {"path": rel}
        headers: dict[str, str] = {}
        line_mode = offset is not None or limit is not None
        if offset is not None:
            if int(offset) < 1:
                raise ValueError("Line offset is 1-based and must be >= 1")
            params["offset"] = str(int(offset))
        if limit is not None:
            if int(limit) < 1:
                raise ValueError("Line limit must be >= 1")
            params["limit"] = str(int(limit))
        if byte_range is not None:
            headers["Range"] = format_byte_range(byte_range)
        route = f"/v1/sessions/{session_id}/files?" + urlencode(params)
        return await self._request_bytes(
            "GET",
            route,
            headers=headers,
            expect_partial=byte_range is not None,
            expect_etag=(byte_range is None and not line_mode),
        )

    async def mkdir(self, session_id: str, path: str, *, mode: int | None = None) -> dict[str, Any]:
        check_uuid(session_id, "sessionId")
        rel = check_relative_path(path, allow_root=False)
        body: dict[str, Any] = {"path": rel}
        if mode is not None:
            if not 0 <= int(mode) <= 0o777:
                raise ValueError("Directory mode must be between 0 and 0o777")
            body["mode"] = int(mode)
        return await self._request_json("POST", f"/v1/sessions/{session_id}/files/mkdir", json_body=body)

    async def list_files(self, session_id: str, path: str = ".", *, depth: int = 1) -> list[dict[str, Any]]:
        check_uuid(session_id, "sessionId")
        rel = check_relative_path(path, allow_root=True)
        if not 0 <= int(depth) <= 64:
            raise ValueError("depth must be between 0 and 64")
        route = f"/v1/sessions/{session_id}/files/list?" + urlencode({"path": rel, "depth": str(int(depth))})
        return (await self._request_json("GET", route))["entries"]

    async def search_files(self, session_id: str, pattern: str, *, path: str = ".") -> list[dict[str, Any]]:
        check_uuid(session_id, "sessionId")
        rel = check_relative_path(path, allow_root=True)
        if not pattern:
            raise ValueError("pattern must be non-empty")
        route = f"/v1/sessions/{session_id}/files/search?" + urlencode({"path": rel, "pattern": pattern})
        return (await self._request_json("GET", route))["entries"]

    async def remove_file(self, session_id: str, path: str, *, recursive: bool = False) -> dict[str, Any]:
        check_uuid(session_id, "sessionId")
        rel = check_relative_path(path, allow_root=False)
        params: dict[str, str] = {"path": rel}
        if recursive:
            params["recursive"] = "true"
        route = f"/v1/sessions/{session_id}/files?" + urlencode(params)
        return await self._request_json("DELETE", route)

    async def session_diff(self, session_id: str) -> bytes:
        check_uuid(session_id, "sessionId")
        return await self._request_bytes("GET", f"/v1/sessions/{session_id}/diff", expect_etag=True)

    async def session_snapshot(
        self,
        session_id: str,
        *,
        path: str = ".",
        format: str = "tar",
        frozen: bool = False,
        scope: str | None = None,
    ) -> bytes:
        check_uuid(session_id, "sessionId")
        rel = check_relative_path(path, allow_root=format == "tar")
        body: dict[str, Any] = {"path": rel, "format": format}
        if frozen:
            body["frozen"] = True
        if scope is not None:
            body["scope"] = scope
        return await self._request_bytes(
            "POST", f"/v1/sessions/{session_id}/snapshot", json_body=body, expect_etag=True
        )

    async def create_volume(
        self,
        *,
        profile: str | None = None,
        id: str | None = None,
        clone_from: str | None = None,
        byte_limit: int | None = None,
        inode_limit: int | None = None,
        wait: bool = True,
    ) -> dict[str, Any]:
        vol_id = check_uuid(id, "volumeId") if id is not None else str(uuid.uuid4())
        body: dict[str, Any] = {
            "id": vol_id,
            "serverId": await self._ensure_server_id(),
            "profile": self._resolve_profile(profile),
        }
        if clone_from is not None:
            body["cloneFrom"] = check_uuid(clone_from, "cloneFrom")
        if byte_limit is not None:
            body["byteLimit"] = int(byte_limit)
        if inode_limit is not None:
            body["inodeLimit"] = int(inode_limit)
        created = await self._request_json(
            "POST", "/v1/volumes", json_body=body, recovery_id=vol_id, uncertain_op="create_volume"
        )
        if not wait or created.get("state") == "ready":
            return created
        return await self.wait_volume(vol_id, target="ready")

    async def get_volume(self, volume_id: str) -> dict[str, Any]:
        check_uuid(volume_id, "volumeId")
        return await self._request_json("GET", f"/v1/volumes/{volume_id}", recovery_id=volume_id)

    async def list_volumes(self, *, after: str | None = None) -> dict[str, Any]:
        route = "/v1/volumes"
        if after is not None:
            route += "?" + urlencode({"after": check_uuid(after, "after")})
        return await self._request_json("GET", route)

    async def wait_volume(
        self, volume_id: str, *, target: str = "ready", poll_interval: float = 0.025, timeout: float = 35.0
    ) -> dict[str, Any]:
        check_uuid(volume_id, "volumeId")
        deadline = time.monotonic() + timeout
        while True:
            vol = await self.get_volume(volume_id)
            state = vol.get("state")
            if state == "closing":
                raise SandcrabError(503, "STORAGE_UNCERTAIN", recovery_id=volume_id)
            if state == target:
                return vol
            if state == "failed":
                raise SandcrabError(409, str(vol.get("code") or "VOLUME_FAILED"), recovery_id=volume_id)
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Timed out waiting for volume {volume_id}")
            await asyncio.sleep(poll_interval)

    async def delete_volume(self, volume_id: str, *, forget: bool = False) -> dict[str, Any]:
        check_uuid(volume_id, "volumeId")
        await self._request_json("POST", f"/v1/volumes/{volume_id}/delete", recovery_id=volume_id)
        deleted = await self.wait_volume(volume_id, target="deleted")
        if forget:
            await self.forget_volume(volume_id)
        return deleted

    async def forget_volume(self, volume_id: str) -> dict[str, Any]:
        check_uuid(volume_id, "volumeId")
        return await self._request_json("POST", f"/v1/volumes/{volume_id}/forget", recovery_id=volume_id)

    async def import_template(
        self,
        archive: bytes | Path | str,
        *,
        profile: str | None = None,
        expected_id: str | None = None,
    ) -> dict[str, Any]:
        prof = self._resolve_profile(profile)
        params: dict[str, str] = {"profile": prof}
        if expected_id is not None:
            params["expectedId"] = check_digest(expected_id, "expectedId")
            existing = await self.get_template(expected_id)
            if existing is not None:
                return existing
        source = Path(archive) if isinstance(archive, str) else archive

        async def _chunks() -> AsyncIterator[bytes]:
            for chunk in iter_tar_chunks(source):
                yield chunk
                await asyncio.sleep(0)

        route = "/v1/templates?" + urlencode(params)
        try:
            return await self._request_json(
                "POST",
                route,
                content=_chunks(),
                headers={"Content-Type": "application/x-tar"},
            )
        except (httpx.TransportError, TimeoutError):
            if expected_id is not None:
                found = await self.get_template(expected_id)
                if found is not None:
                    return found
                raise PublicationUncertain(expected_id) from None
            raise

    async def get_template(self, template_id: str) -> dict[str, Any] | None:
        check_digest(template_id, "templateId")
        try:
            return await self._request_json("GET", f"/v1/templates/{template_id}")
        except SandcrabError as err:
            if err.status == 404 and err.code == "TEMPLATE_NOT_FOUND":
                return None
            raise

    async def list_templates(self, *, after: str | None = None) -> dict[str, Any]:
        route = "/v1/templates"
        if after is not None:
            route += "?" + urlencode({"after": check_digest(after, "after")})
        return await self._request_json("GET", route)

    async def compose_template(self, layers: Sequence[str]) -> dict[str, Any]:
        expected = recipe_id(list(layers))
        ordered = list(layers)
        existing = await self.get_template(expected)
        if existing is None:
            try:
                existing = await self._request_json(
                    "POST", "/v1/templates/compose", json_body={"layers": ordered}
                )
            except (httpx.TransportError, TimeoutError):
                existing = await self.get_template(expected)
                if existing is None:
                    raise PublicationUncertain(expected) from None
        if existing.get("id") != expected or existing.get("layers") != ordered:
            raise ProtocolError("Published recipe differs from the requested layer order")
        return existing

    async def delete_template(self, template_id: str) -> dict[str, Any]:
        check_digest(template_id, "templateId")
        return await self._request_json("DELETE", f"/v1/templates/{template_id}")
