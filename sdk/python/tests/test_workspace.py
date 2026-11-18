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
