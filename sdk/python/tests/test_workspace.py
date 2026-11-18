import unittest

import httpx

from sandcrab import AsyncSandcrabClient


class WorkspaceToolTests(unittest.IsolatedAsyncioTestCase):
    async def test_lost_command_reply_never_submits_again(self):
        epoch = "11111111-1111-4111-8111-111111111111"
        generation = "22222222-2222-4222-8222-222222222222"
        submitted = []

        async def serve(request):
            path = request.url.path
            if path == "/v1/info":
                return httpx.Response(200, json={"serverId": epoch})
            if path == "/v1/workspace-tools":
                schema = {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}
                return httpx.Response(200, json={"tools": [{"name": name, "inputSchema": schema} for name in ("exec", "future_tool")]})
            if path.endswith("/commands"):
                submitted.append(request.content)
                raise httpx.ReadError("connection closed", request=request)
            return httpx.Response(200, json={"state": "ready", "generation": generation, "serverId": epoch, "submissionWindow": 0})

        async with AsyncSandcrabClient(transport=httpx.MockTransport(serve), env={}) as client:
            tools = await client.workspace_tools("example")
            self.assertEqual(list(tools.handlers), ["exec"])
            result = await tools.call("exec", {"command": "printf x >> record"})
            self.assertEqual(result["code"], "OUTCOME_UNKNOWN")
            self.assertFalse(result["ok"])
            self.assertEqual(len(submitted), 1)

    async def test_unusable_write_receipts_leave_the_outcome_unknown(self):
        digest = "0" * 64
        write = {"path": "note", "content": "x"}
        edit = {"path": "note", "version": digest, "old": "x", "new": "y"}
        command = {"command": "printf x >> note"}
        definitions = {"exec": command, "write_file": write, "edit_file": edit}
        mutations = []
        tools_schema = [
            {"name": name, "inputSchema": {
                "required": list(args), "properties": {key: {"type": "string"} for key in args},
            }}
            for name, args in definitions.items()
        ]

        def serve(request):
            if request.url.path == "/v1/workspace-tools":
                return httpx.Response(200, json={"tools": tools_schema})
            if request.url.path.endswith(("/files", "/edit", "/commands")):
                mutations.append(request.url.path)
                return response
            return httpx.Response(200, json={"state": "ready", "submissionWindow": 0,
                "serverId": "11111111-1111-4111-8111-111111111111",
                "generation": "22222222-2222-4222-8222-222222222222"})

        cases = [
            ("exec", httpx.Response(202, content=b"{")),
            ("write_file", httpx.Response(200, json={})),
            ("write_file", httpx.Response(200, json={"path": "note", "bytes": 1, "sha256": digest})),
            ("edit_file", httpx.Response(200, json={"path": "other", "replacedCount": 1})),
            ("edit_file", httpx.Response(200, json={"path": "note", "replacedCount": 0})),
        ]
        async with AsyncSandcrabClient(transport=httpx.MockTransport(serve), env={}) as client:
            tools = await client.workspace_tools("example")
            for name, response in cases:
                with self.subTest(name=name, body=response.content):
                    before = len(mutations)
                    result = await tools.call(name, definitions[name])
                    self.assertEqual((result.get("ok"), result.get("code")), (False, "OUTCOME_UNKNOWN"))
                    self.assertEqual(len(mutations), before + 1)
            response = httpx.Response(409, json={"error": {"code": "EDIT_CONFLICT"}})
            self.assertEqual(await tools.call("edit_file", edit), {"ok": False, "code": "EDIT_CONFLICT"})
