"""Unit tests for the pure-stdlib Sandcrab stdio MCP server."""
from __future__ import annotations

import hashlib
import io
import json
import unittest

import httpx

from sandcrab import SandcrabClient, SandcrabMcpServer

EPOCH = "00000000-0000-0000-0000-000000000020"
SESSION_ID = "00000000-0000-0000-0000-000000000021"
RUN_ID = "00000000-0000-0000-0000-000000000022"


class McpServerTests(unittest.TestCase):
    def _mock_client(self, log: list[tuple[str, str]], opened_ids: list[str] | None = None) -> SandcrabClient:
        sessions: dict[str, str] = {}
        runs: set[str] = set()
        stored: dict[tuple[str, str], bytes] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            log.append((req.method, req.url.path))
            p = req.url.path
            if p == "/v1/info":
                return httpx.Response(200, json={"apiVersion": 1, "serverId": EPOCH})
            if req.method == "POST" and p == "/v1/sessions":
                sid = json.loads(req.content)["id"]
                sessions[sid] = "ready"
                if opened_ids is not None:
                    opened_ids.append(sid)
                return httpx.Response(200, json={"id": sid, "state": "ready"})
            if p.startswith("/v1/sessions/"):
                parts = p.removeprefix("/v1/sessions/").split("/")
                sid = parts[0]
                tail = "/".join(parts[1:])
                if req.method == "GET" and not tail:
                    return httpx.Response(
                        200, json={"id": sid, "serverId": EPOCH, "profile": "default", "state": sessions[sid]}
                    )
                if req.method == "PUT" and tail == "files":
                    rel = req.url.params["path"]
                    stored[(sid, rel)] = req.content
                    return httpx.Response(200, json={"path": rel, "bytes": len(req.content)})
                if req.method == "GET" and tail == "files":
                    rel = req.url.params["path"]
                    if (sid, rel) not in stored:
                        return httpx.Response(404, json={"error": {"code": "FILE_NOT_FOUND"}})
                    raw = stored[(sid, rel)]
                    etag = '"' + hashlib.sha256(raw).hexdigest() + '"'
                    return httpx.Response(200, content=raw, headers={"etag": etag, "x-sandcrab-server-id": EPOCH})
                if req.method == "POST" and tail == "commands":
                    rid = json.loads(req.content)["id"]
                    runs.add(rid)
                    return httpx.Response(200, json={"id": rid, "state": "running"})
                if req.method == "POST" and tail == "close":
                    sessions[sid] = "closed"
                    return httpx.Response(200, json={"id": sid, "state": "closed"})
                if req.method == "POST" and tail == "forget":
                    return httpx.Response(200, json={"forgotten": True})
            if p.startswith("/v1/runs/"):
                parts = p.removeprefix("/v1/runs/").split("/")
                rid = parts[0]
                tail = "/".join(parts[1:])
                if req.method == "GET" and not tail and rid in runs:
                    return httpx.Response(
                        200,
                        json={
                            "id": rid,
                            "state": "succeeded",
                            "result": {"exitCode": 0, "stdout": "ok\n", "stderr": ""},
                        },
                    )
                if req.method == "POST" and tail == "forget":
                    return httpx.Response(200, json={"forgotten": True})
            raise AssertionError(f"Unhandled {req.method} {req.url}")

        return SandcrabClient(default_profile="default", transport=httpx.MockTransport(handler))

    def test_jsonl_protocol_tools_errors_and_eof_session_cleanup(self) -> None:
        log: list[tuple[str, str]] = []
        opened_ids: list[str] = []
        server = SandcrabMcpServer(self._mock_client(log, opened_ids))

        init_reply = server.handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}}
        )
        assert init_reply is not None
        self.assertEqual("2024-11-05", init_reply["result"]["protocolVersion"])
        self.assertIsNone(server.handle_message({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        tools_reply = server.handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert tools_reply is not None
        self.assertGreaterEqual(len(tools_reply["result"]["tools"]), 9)

        open_reply = server.handle_message(
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "sandcrab_session_open", "arguments": {}}}
        )
        assert open_reply is not None
        sid = json.loads(open_reply["result"]["content"][0]["text"])["id"]
        self.assertEqual([sid], opened_ids)

        requests = [
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "sandcrab_write_file",
                    "arguments": {"session_id": sid, "path": "app/hello.txt", "content": "hello mcp\n"},
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "sandcrab_read_file",
                    "arguments": {"session_id": sid, "path": "app/hello.txt"},
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {
                    "name": "sandcrab_session_exec",
                    "arguments": {"session_id": sid, "command": "cat app/hello.txt"},
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "sandcrab_read_file",
                    "arguments": {"session_id": sid, "path": "missing.txt"},
                },
            },
        ]
        stdin = io.BytesIO("".join(json.dumps(r) + "\n" for r in requests).encode("utf-8"))
        stdout = io.BytesIO()
        server.serve_stdio(stdin=stdin, stdout=stdout)

        replies = [json.loads(line) for line in stdout.getvalue().decode("utf-8").splitlines() if line]
        self.assertEqual([4, 5, 6, 7], [r["id"] for r in replies])
        read_back = json.loads(replies[1]["result"]["content"][0]["text"])
        self.assertEqual("hello mcp\n", read_back["content"])
        exec_res = json.loads(replies[2]["result"]["content"][0]["text"])
        self.assertEqual("ok\n", exec_res["result"]["stdout"])
        self.assertTrue(replies[3]["result"]["isError"])
        err_body = json.loads(replies[3]["result"]["content"][0]["text"])
        self.assertEqual("FILE_NOT_FOUND", err_body["code"])

        # EOF must automatically close and forget the unclosed session opened by MCP.
        self.assertIn(("POST", f"/v1/sessions/{sid}/close"), log)
        self.assertIn(("POST", f"/v1/sessions/{sid}/forget"), log)

    def test_content_length_framing(self) -> None:
        log: list[tuple[str, str]] = []
        body = json.dumps({"jsonrpc": "2.0", "id": 99, "method": "ping"}).encode("utf-8")
        stdin = io.BytesIO(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body)
        stdout = io.BytesIO()
        server = SandcrabMcpServer(self._mock_client(log))
        server.serve_stdio(stdin=stdin, stdout=stdout)
        out = stdout.getvalue()
        self.assertTrue(out.startswith(b"Content-Length: "))
        _, _, payload = out.partition(b"\r\n\r\n")
        self.assertEqual({"jsonrpc": "2.0", "id": 99, "result": {}}, json.loads(payload))


if __name__ == "__main__":
    unittest.main()
