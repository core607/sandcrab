"""Unit tests for SandcrabClient, AsyncSandcrabClient, Session and HostCallDispatcher."""
from __future__ import annotations

import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import gzip
import hashlib
import hmac
import json
from pathlib import Path
import tempfile
import threading
import unittest
import warnings

import httpx

from sandcrab import (
    AsyncHostCallDispatcher,
    AsyncSandcrabClient,
    CallContext,
    CommandFailedError,
    HostCallDispatcher,
    InMemoryReplyLedger,
    ProtocolError,
    SandcrabClient,
    SandcrabError,
    TemplateClient,
    TransportUncertainError,
    recipe_id,
)

EPOCH = "00000000-0000-0000-0000-000000000010"
RUN_ID = "00000000-0000-0000-0000-000000000011"
SESSION_ID = "00000000-0000-0000-0000-000000000012"
CALL_ID = "00000000-0000-0000-0000-000000000013"
GUEST_REQ_ID = "00000000-0000-0000-0000-000000000014"
STREAM_ID = "00000000-0000-0000-0000-000000000015"
VOL_ID = "00000000-0000-0000-0000-000000000016"
TOKEN = "c" * 64


def sse_frame(cursor: str, event: str, data: dict) -> str:
    return f"id: {cursor}\nevent: {event}\ndata: {json.dumps(data)}\n\n"


class ConcurrentCallsTests(unittest.IsolatedAsyncioTestCase):
    context = CallContext(RUN_ID, EPOCH, CALL_ID, GUEST_REQ_ID, 1, hashlib.sha256(b"ping").hexdigest(), None)

    def test_threads_sharing_a_ledger_invoke_one_handler(self) -> None:
        ledger = InMemoryReplyLedger()
        first = HostCallDispatcher(ledger=ledger)
        second = HostCallDispatcher(ledger=ledger)
        started, finish = threading.Event(), threading.Event()
        effects = []

        @first.on_call
        def handler(payload, _):
            effects.append(payload)
            started.set()
            self.assertTrue(finish.wait(5))
            return b"reply"

        with ThreadPoolExecutor(2) as pool:
            owner = pool.submit(first.handle_payload, b"ping", self.context)
            try:
                self.assertTrue(started.wait(5))
                follower = pool.submit(second.handle_payload, b"ping", self.context)
                with self.assertRaisesRegex(ProtocolError, "changed"):
                    second.handle_payload(b"other", replace(self.context, request_sha256="different"))
            finally:
                finish.set()
            self.assertEqual([owner.result(), follower.result()], [b"reply", b"reply"])
        self.assertEqual(effects, [b"ping"])

    async def test_async_observers_share_replies_and_waiter_cancellation(self) -> None:
        dispatcher = AsyncHostCallDispatcher()
        started, finish = asyncio.Event(), asyncio.Event()
        effects = []

        @dispatcher.on_call
        async def handler(payload, _):
            effects.append(payload)
            started.set()
            await finish.wait()
            return b"reply"

        owner = asyncio.create_task(dispatcher.handle_payload(b"ping", self.context))
        await started.wait()
        follower = asyncio.create_task(dispatcher.handle_payload(b"ping", self.context))
        cancelled = asyncio.create_task(dispatcher.handle_payload(b"ping", self.context))
        await asyncio.sleep(0)
        cancelled.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await cancelled
        try:
            with self.assertRaisesRegex(ProtocolError, "changed"):
                await asyncio.wait_for(dispatcher.handle_payload(b"other", replace(self.context, request_sha256="other")), 1)
        finally:
            finish.set()
        self.assertEqual(await asyncio.gather(owner, follower), [b"reply", b"reply"])
        self.assertEqual(effects, [b"ping"])


class ConnectionAndValidationTests(unittest.TestCase):
    def test_reexports_legacy_templates_api(self) -> None:
        from sandcrab_templates import TemplateClient as LegacyClient, recipe_id as legacy_recipe

        self.assertIs(TemplateClient, LegacyClient)
        self.assertIs(recipe_id, legacy_recipe)

    def test_transport_and_env_boundaries(self) -> None:
        for bad_endpoint in (
            "https://127.0.0.1:8080",
            "http://example.com:8080",
            "http://127.0.0.1",
            "http://127.0.0.1:8080/v1",
            "http://user@127.0.0.1:8080",
        ):
            with self.subTest(endpoint=bad_endpoint), self.assertRaises(ValueError):
                SandcrabClient(endpoint=bad_endpoint, token=TOKEN)

        with self.assertRaisesRegex(ValueError, "Both SANDCRAB_SOCKET and SANDCRAB_ENDPOINT"):
            SandcrabClient(
                env={
                    "SANDCRAB_SOCKET": "/run/sandcrab/sandcrab.sock",
                    "SANDCRAB_ENDPOINT": "http://127.0.0.1:8080",
                }
            )

        with tempfile.TemporaryDirectory() as tmp:
            token_path = Path(tmp) / "client.token"
            token_path.write_text(TOKEN + "\n", encoding="utf-8")
            token_path.chmod(0o600)
            seen_auth: list[str] = []

            def handler(req: httpx.Request) -> httpx.Response:
                seen_auth.append(req.headers.get("authorization", ""))
                return httpx.Response(200, json={"apiVersion": 1, "serverId": EPOCH})

            with SandcrabClient(
                transport=httpx.MockTransport(handler),
                env={
                    "SANDCRAB_ENDPOINT": "http://127.0.0.1:9011",
                    "SANDCRAB_TOKEN_FILE": str(token_path),
                    "SANDCRAB_PROFILE": "python",
                },
            ) as client:
                self.assertEqual("python", client.default_profile)
                self.assertEqual(EPOCH, client.info()["serverId"])
            self.assertEqual(["Bearer " + TOKEN], seen_auth)


class SyncClientTests(unittest.TestCase):
    def test_first_request_discovers_version_and_warns_once_for_a_mismatch(self):
        calls = []
        def handle(req):
            calls.append(req.url.path)
            return httpx.Response(200, json={"serverId": EPOCH, "releaseVersion": "9.8.7"})
        with SandcrabClient(transport=httpx.MockTransport(handle)) as client, warnings.catch_warnings(record=True) as seen:
            warnings.simplefilter("always")
            client.list_runs()
            client.info()
        self.assertEqual(calls, ["/v1/info", "/v1/runs", "/v1/info"])
        self.assertEqual(len(seen), 1)
        self.assertIn("9.8.7", str(seen[0].message))

    def test_run_streams_output_forgets_by_default_and_checks_exit(self) -> None:
        calls: list[tuple[str, str, bytes]] = []
        chunks: list[tuple[str, bytes]] = []

        def handler(req: httpx.Request) -> httpx.Response:
            calls.append((req.method, req.url.path, req.content))
            if req.url.path == "/v1/info":
                return httpx.Response(200, json={"apiVersion": 1, "serverId": EPOCH})
            if req.method == "POST" and req.url.path == "/v1/runs":
                body = json.loads(req.content)
                self.assertEqual(["echo", "hi"], body["command"])
                self.assertTrue(body["keepResult"])
                return httpx.Response(200, json={"id": body["id"], "state": "running"})
            if req.url.path.endswith("/events"):
                payload = (
                    sse_frame(f"{STREAM_ID}:0:0", "state", {"state": "running"})
                    + sse_frame(
                        f"{STREAM_ID}:3:0",
                        "stdout",
                        {"offset": 0, "base64": base64.b64encode(b"hi\n").decode()},
                    )
                    + sse_frame(f"{STREAM_ID}:3:0", "result", {"state": "succeeded"})
                )
                return httpx.Response(200, content=payload.encode("utf-8"))
            if req.method == "GET" and req.url.path.startswith("/v1/runs/"):
                return httpx.Response(
                    200,
                    json={
                        "id": RUN_ID,
                        "serverId": EPOCH,
                        "profile": "default",
                        "state": "succeeded",
                        "result": {"exitCode": 0, "stdout": "hi\n", "stderr": ""},
                    },
                )
            if req.method == "POST" and req.url.path.endswith("/forget"):
                self.assertEqual(b"{}", req.content)
                return httpx.Response(200, json={"forgotten": True})
            raise AssertionError(f"Unhandled route {req.method} {req.url}")

        with SandcrabClient(default_profile="default", transport=httpx.MockTransport(handler)) as client:
            res = client.run(["echo", "hi"], id=RUN_ID, on_output=lambda s, b: chunks.append((s, b)), check=True)
            self.assertEqual("hi\n", res["result"]["stdout"])
        self.assertEqual([("stdout", b"hi\n")], chunks)
        self.assertEqual(f"/v1/runs/{RUN_ID}/forget", calls[-1][1])

    def test_lost_submit_raises_transport_uncertain_with_recovery_id(self) -> None:
        posts = 0

        def handler(req: httpx.Request) -> httpx.Response:
            nonlocal posts
            if req.url.path == "/v1/info":
                return httpx.Response(200, json={"apiVersion": 1, "serverId": EPOCH})
            posts += 1
            raise httpx.ReadError("socket dropped after write", request=req)

        with SandcrabClient(default_profile="default", transport=httpx.MockTransport(handler)) as client:
            with self.assertRaises(TransportUncertainError) as ctx:
                client.submit_run(["true"], id=RUN_ID)
            self.assertEqual(RUN_ID, ctx.exception.recovery_id)
        self.assertEqual(1, posts)

    def test_session_context_files_volumes_and_gzip_templates(self) -> None:
        events: list[tuple[str, str]] = []
        stored_tar = bytearray()
        file_bytes = b"alpha\nbeta\ngamma\n"
        file_etag = '"' + hashlib.sha256(file_bytes).hexdigest() + '"'
        session_closed = False
        vol_deleted = False

        def handler(req: httpx.Request) -> httpx.Response:
            nonlocal session_closed, vol_deleted
            events.append((req.method, str(req.url)))
            path = req.url.path
            if path == "/v1/info":
                return httpx.Response(200, json={"apiVersion": 1, "serverId": EPOCH})
            if req.method == "POST" and path == "/v1/sessions":
                return httpx.Response(200, json={"id": SESSION_ID, "state": "starting"})
            if req.method == "GET" and path == f"/v1/sessions/{SESSION_ID}":
                state = "closed" if session_closed else "ready"
                return httpx.Response(200, json={"id": SESSION_ID, "serverId": EPOCH, "profile": "default", "state": state})
            if req.method == "POST" and path == f"/v1/sessions/{SESSION_ID}/close":
                self.assertEqual(b"{}", req.content)
                session_closed = True
                return httpx.Response(200, json={"id": SESSION_ID, "state": "closed"})
            if req.method == "POST" and path == f"/v1/sessions/{SESSION_ID}/forget":
                self.assertEqual(b"{}", req.content)
                return httpx.Response(200, json={"forgotten": True})
            if req.method == "PUT" and path == f"/v1/sessions/{SESSION_ID}/files":
                self.assertEqual("src/notes.txt", req.url.params["path"])
                self.assertEqual("true", req.url.params["parents"])
                return httpx.Response(200, json={"path": "src/notes.txt", "bytes": len(req.content)})
            if req.method == "GET" and path == f"/v1/sessions/{SESSION_ID}/files":
                if "range" in req.headers:
                    self.assertEqual("bytes=0-4", req.headers["range"])
                    return httpx.Response(206, content=file_bytes[:5], headers={"x-sandcrab-server-id": EPOCH})
                if "offset" in req.url.params:
                    self.assertEqual("2", req.url.params["offset"])
                    self.assertEqual("1", req.url.params["limit"])
                    return httpx.Response(200, content=b"beta", headers={"x-sandcrab-server-id": EPOCH})
                return httpx.Response(
                    200,
                    content=file_bytes,
                    headers={"etag": file_etag, "x-sandcrab-server-id": EPOCH},
                )
            if req.method == "POST" and path == f"/v1/sessions/{SESSION_ID}/files/mkdir":
                return httpx.Response(200, json={"path": json.loads(req.content)["path"]})
            if req.method == "GET" and path == f"/v1/sessions/{SESSION_ID}/files/list":
                return httpx.Response(200, json={"entries": [{"path": "src/notes.txt", "kind": "file"}]})
            if req.method == "GET" and path == f"/v1/sessions/{SESSION_ID}/files/search":
                return httpx.Response(200, json={"entries": [{"path": "src/notes.txt", "kind": "file"}]})
            if req.method == "DELETE" and path == f"/v1/sessions/{SESSION_ID}/files":
                return httpx.Response(200, json={"removed": True})
            if req.method == "POST" and path == "/v1/volumes":
                return httpx.Response(200, json={"id": VOL_ID, "state": "creating"})
            if req.method == "GET" and path == f"/v1/volumes/{VOL_ID}":
                return httpx.Response(200, json={"id": VOL_ID, "state": "deleted" if vol_deleted else "ready"})
            if req.method == "POST" and path == f"/v1/volumes/{VOL_ID}/delete":
                vol_deleted = True
                return httpx.Response(200, json={"id": VOL_ID, "state": "deleting"})
            if req.method == "POST" and path == f"/v1/volumes/{VOL_ID}/forget":
                return httpx.Response(200, json={"forgotten": True})
            if req.method == "POST" and path == "/v1/templates":
                self.assertEqual("application/x-tar", req.headers["content-type"])
                stored_tar.extend(req.content)
                return httpx.Response(200, json={"id": hashlib.sha256(stored_tar).hexdigest()})
            raise AssertionError(f"Unhandled {req.method} {req.url}")

        with SandcrabClient(default_profile="default", transport=httpx.MockTransport(handler)) as client:
            vol = client.create_volume(id=VOL_ID)
            self.assertEqual("ready", vol["state"])
            client.delete_volume(VOL_ID, forget=True)

            raw_tar = b"ustar-tar-stream-payload" * 100
            gz_tar = gzip.compress(raw_tar)
            imported = client.import_template(gz_tar)
            self.assertEqual(bytes(stored_tar), raw_tar)
            self.assertEqual(hashlib.sha256(raw_tar).hexdigest(), imported["id"])

            with client.open_session(id=SESSION_ID) as session:
                session.mkdir("src")
                session.write_file("src/notes.txt", file_bytes, parents=True)
                self.assertEqual(file_bytes, session.read_file("src/notes.txt"))
                self.assertEqual(b"alpha", session.read_file("src/notes.txt", byte_range=(0, 4)))
                self.assertEqual("beta", session.read_text("src/notes.txt", offset=2, limit=1))
                self.assertEqual(1, len(session.list_files("src")))
                self.assertEqual(1, len(session.search_files("*.txt")))
                session.remove_file("src/notes.txt")
                for bad_path in ("../escape", "/etc/passwd", "a//b", "a/./b"):
                    with self.assertRaises(ValueError):
                        session.read_file(bad_path)

        close_routes = [u for m, u in events if m == "POST" and ("/close" in u or "/sessions/" in u and "/forget" in u)]
        self.assertEqual(2, len(close_routes))

    def test_host_call_dispatcher_ledger_reconnect_and_cancel_on_unauthorized(self) -> None:
        key = b"k" * 32
        artifact_digest = hashlib.sha256(b"artifact").hexdigest()
        ledger = InMemoryReplyLedger()
        dispatcher = HostCallDispatcher(ledger=ledger)
        invocations = 0

        @dispatcher.on_json("sign-sha256")
        def sign_digest(req: dict, ctx: object) -> dict:
            nonlocal invocations
            invocations += 1
            if req.get("digest") != artifact_digest:
                raise PermissionError("outside build grant")
            sig = hmac.new(key, bytes.fromhex(artifact_digest), hashlib.sha256).hexdigest()
            return {"signature": sig}

        req_bytes = json.dumps({"operation": "sign-sha256", "digest": artifact_digest}).encode()
        req_b64 = base64.b64encode(req_bytes).decode()
        req_sha = hashlib.sha256(req_bytes).hexdigest()
        replied: list[bytes] = []
        stream_opens = 0

        def handler(req: httpx.Request) -> httpx.Response:
            nonlocal stream_opens
            if req.url.path == "/v1/info":
                return httpx.Response(200, json={"apiVersion": 1, "serverId": EPOCH})
            if req.method == "POST" and req.url.path == "/v1/runs":
                return httpx.Response(200, json={"id": RUN_ID, "state": "running"})
            if req.url.path == f"/v1/runs/{RUN_ID}/calls/events":
                stream_opens += 1
                if stream_opens == 1:
                    body = (
                        sse_frame(f"{STREAM_ID}:0", "state", {"runId": RUN_ID, "serverId": EPOCH, "calls": {}})
                        + sse_frame(f"{STREAM_ID}:0", "error", {"code": "OBSERVATION_TIMEOUT"})
                    )
                    return httpx.Response(200, content=body.encode())
                self.assertEqual(f"{STREAM_ID}:0", req.headers.get("last-event-id"))
                call_obj = {
                    "id": CALL_ID,
                    "requestId": GUEST_REQ_ID,
                    "sequence": 1,
                    "state": "pending",
                    "requestSha256": req_sha,
                    "base64": req_b64,
                }
                body = (
                    sse_frame(f"{STREAM_ID}:0", "state", {"runId": RUN_ID, "serverId": EPOCH, "calls": {}})
                    + sse_frame(f"{STREAM_ID}:1", "call", call_obj)
                    + sse_frame(f"{STREAM_ID}:1", "call", call_obj)
                    + sse_frame(f"{STREAM_ID}:1", "result", {"run": {"id": RUN_ID, "state": "succeeded"}})
                )
                return httpx.Response(200, content=body.encode())
            if req.method == "POST" and req.url.path == f"/v1/runs/{RUN_ID}/calls/{CALL_ID}/reply":
                replied.append(base64.b64decode(json.loads(req.content)["base64"]))
                return httpx.Response(200, json={"id": CALL_ID, "state": "replied"})
            if req.method == "GET" and req.url.path == f"/v1/runs/{RUN_ID}":
                return httpx.Response(
                    200,
                    json={"id": RUN_ID, "state": "succeeded", "result": {"exitCode": 0, "stdout": "", "stderr": ""}},
                )
            if req.method == "POST" and req.url.path == f"/v1/runs/{RUN_ID}/forget":
                return httpx.Response(200, json={"forgotten": True})
            raise AssertionError(f"Unexpected {req.method} {req.url}")

        with SandcrabClient(default_profile="python", transport=httpx.MockTransport(handler)) as client:
            done = client.run(["python3", "-c", "pass"], id=RUN_ID, dispatcher=dispatcher, check=True)
            self.assertEqual("succeeded", done["state"])
        self.assertEqual(1, invocations)
        self.assertEqual(2, len(replied))
        self.assertEqual(replied[0], replied[1])

        cancelled = False
        forgotten = False
        bad_bytes = json.dumps({"operation": "steal-secret"}).encode()

        def cancel_handler(req: httpx.Request) -> httpx.Response:
            nonlocal cancelled, forgotten
            if req.url.path == "/v1/info":
                return httpx.Response(200, json={"apiVersion": 1, "serverId": EPOCH})
            if req.method == "POST" and req.url.path == "/v1/runs":
                return httpx.Response(200, json={"id": RUN_ID, "state": "running"})
            if req.url.path == f"/v1/runs/{RUN_ID}/calls/events":
                call_obj = {
                    "id": CALL_ID,
                    "requestId": GUEST_REQ_ID,
                    "sequence": 1,
                    "state": "pending",
                    "requestSha256": hashlib.sha256(bad_bytes).hexdigest(),
                    "base64": base64.b64encode(bad_bytes).decode(),
                }
                body = sse_frame(f"{STREAM_ID}:0", "state", {"runId": RUN_ID, "serverId": EPOCH}) + sse_frame(
                    f"{STREAM_ID}:1", "call", call_obj
                )
                return httpx.Response(200, content=body.encode())
            if req.method == "POST" and req.url.path == f"/v1/runs/{RUN_ID}/cancel":
                cancelled = True
                return httpx.Response(200, json={"id": RUN_ID, "state": "cancelled"})
            if req.method == "POST" and req.url.path == f"/v1/runs/{RUN_ID}/forget":
                forgotten = True
                return httpx.Response(200, json={"forgotten": True})
            raise AssertionError(f"Unexpected {req.method} {req.url}")

        with SandcrabClient(default_profile="python", transport=httpx.MockTransport(cancel_handler)) as client:
            with self.assertRaises(PermissionError):
                client.run(["python3", "-c", "pass"], id=RUN_ID, dispatcher=HostCallDispatcher())
        self.assertTrue(cancelled)
        self.assertFalse(forgotten)


class AsyncClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_concurrent_first_requests_share_discovery(self):
        calls = []
        async def handle(req):
            calls.append(req.url.path)
            await asyncio.sleep(0)
            return httpx.Response(200, json={"serverId": EPOCH})
        async with AsyncSandcrabClient(transport=httpx.MockTransport(handle)) as client:
            await asyncio.gather(client.list_runs(), client.list_runs())
        self.assertEqual(calls, ["/v1/info", "/v1/runs", "/v1/runs"])

    async def test_async_session_host_calls_and_command_failed(self) -> None:
        dispatcher = AsyncHostCallDispatcher()

        @dispatcher.on_json("ping")
        async def handle_ping(req: dict, ctx: object) -> dict:
            return {"pong": req["value"]}

        req_bytes = json.dumps({"operation": "ping", "value": 42}).encode()
        closed = False

        async def handler(req: httpx.Request) -> httpx.Response:
            nonlocal closed
            p = req.url.path
            if p == "/v1/info":
                return httpx.Response(200, json={"apiVersion": 1, "serverId": EPOCH})
            if req.method == "POST" and p == "/v1/sessions":
                return httpx.Response(200, json={"id": SESSION_ID, "state": "ready"})
            if req.method == "GET" and p == f"/v1/sessions/{SESSION_ID}":
                return httpx.Response(
                    200, json={"id": SESSION_ID, "serverId": EPOCH, "profile": "python", "state": "closed" if closed else "ready"}
                )
            if req.method == "POST" and p == f"/v1/sessions/{SESSION_ID}/commands":
                return httpx.Response(200, json={"id": RUN_ID, "state": "running"})
            if p == f"/v1/runs/{RUN_ID}/calls/events":
                call_obj = {
                    "id": CALL_ID,
                    "requestId": GUEST_REQ_ID,
                    "sequence": 1,
                    "state": "pending",
                    "requestSha256": hashlib.sha256(req_bytes).hexdigest(),
                    "base64": base64.b64encode(req_bytes).decode(),
                }
                body = (
                    sse_frame(f"{STREAM_ID}:0", "state", {"runId": RUN_ID, "serverId": EPOCH})
                    + sse_frame(f"{STREAM_ID}:1", "call", call_obj)
                    + sse_frame(f"{STREAM_ID}:1", "result", {"run": {"id": RUN_ID, "state": "failed"}})
                )
                return httpx.Response(200, content=body.encode())
            if req.method == "POST" and p == f"/v1/runs/{RUN_ID}/calls/{CALL_ID}/reply":
                return httpx.Response(200, json={"id": CALL_ID, "state": "replied"})
            if req.method == "GET" and p == f"/v1/runs/{RUN_ID}":
                return httpx.Response(
                    200, json={"id": RUN_ID, "state": "failed", "result": {"exitCode": 2, "stdout": "", "stderr": "boom"}}
                )
            if req.method == "POST" and p == f"/v1/runs/{RUN_ID}/forget":
                return httpx.Response(200, json={"forgotten": True})
            if req.method == "POST" and p == f"/v1/sessions/{SESSION_ID}/close":
                closed = True
                return httpx.Response(200, json={"id": SESSION_ID, "state": "closed"})
            if req.method == "POST" and p == f"/v1/sessions/{SESSION_ID}/forget":
                return httpx.Response(200, json={"forgotten": True})
            raise AssertionError(f"Unexpected {req.method} {req.url}")

        async with AsyncSandcrabClient(default_profile="python", transport=httpx.MockTransport(handler)) as client:
            async with await client.open_session(id=SESSION_ID) as session:
                with self.assertRaises(CommandFailedError) as err:
                    await session.exec("exit 2", dispatcher=dispatcher, check=True)
                self.assertEqual(2, err.exception.run["result"]["exitCode"])
        self.assertTrue(closed)

    async def test_etag_mismatch_raises_protocol_error(self) -> None:
        async def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path == "/v1/info":
                return httpx.Response(200, json={"apiVersion": 1, "serverId": EPOCH})
            return httpx.Response(200, content=b"tampered", headers={"etag": '"' + "0" * 64 + '"'})

        async with AsyncSandcrabClient(default_profile="default", transport=httpx.MockTransport(handler)) as client:
            with self.assertRaises(ProtocolError):
                await client.read_file(SESSION_ID, "a.txt")


if __name__ == "__main__":
    unittest.main()
