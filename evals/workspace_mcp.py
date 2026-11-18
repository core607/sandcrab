"""Compare the two real Sandcrab MCP catalogs on the same isolated programming fixtures."""
import asyncio
from contextlib import ExitStack, contextmanager
import json
import uuid

import httpx
from inspect_ai.tool import ToolDef, ToolError, ToolParams

from workspace_client import Rejected, Workspace


class McpWorkspace(Workspace):
    def __init__(self, endpoint, directory, state, interface):
        super().__init__(endpoint, directory, state)
        self.bound = interface == "workspace-mcp"
        self.key = "eval-" + uuid.uuid4().hex
        self.route = "/v1/workspaces/" + self.key
        self.generation = None
        self.managed_post = False
        self.stack = ExitStack()
        self.server = None
        self.state.update(workspaceClient=interface, mcpCalls=0)
        self.parents = set()

    @contextmanager
    def trace(self, request):
        route = request.url.path
        method = request.method
        record = {"phase": self.phase, "method": method, "path": route, "status": None}
        self.state["observations"].append(record)
        creates = {"/v1/sessions": "sessions", "/v1/runs": "runs", "/v1/uploads": "uploads"}
        kind = "runs" if route.endswith("/commands") else creates.get(route)
        identity = None
        if method == "POST" and kind:
            identity = str(uuid.UUID(json.loads(request.content)["id"]))
            if identity not in self.state[kind]:
                self.state[kind].append(identity)
            else:
                identity = None
        if method == "POST" and route == self.route:
            self.managed_post = True
        yield record
        status = record["status"]
        if identity and 400 <= status < 500:
            self.state[kind].remove(identity)
        if method == "POST" and status == 200 and route.endswith("/forget"):
            parts = route.split("/")
            if len(parts) == 5 and parts[2] in ("sessions", "runs", "uploads") and parts[3] in self.state[parts[2]]:
                self.finished(parts[2], parts[3])
                self.state[parts[2]].remove(parts[3])

    def rpc(self, method, params):
        response = self.server.handle_message({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        if "error" in response:
            raise RuntimeError("Local MCP exchange failed: " + str(response["error"]["code"]))
        return response["result"]

    def prepare(self, case):
        from sandcrab import SandcrabClient, open_workspace_tools
        from sandcrab.mcp import SandcrabMcpServer
        owner = self

        class Sync(httpx.HTTPTransport):
            def handle_request(self, request):
                with owner.trace(request) as row:
                    response = super().handle_request(request)
                    row["status"] = response.status_code
                    return response

        class Async(httpx.AsyncHTTPTransport):
            async def handle_async_request(self, request):
                with owner.trace(request) as row:
                    response = await super().handle_async_request(request)
                    row["status"] = response.status_code
                    return response

        if self.bound:
            with self.exclusive("setup"):
                self.directory.mkdir(parents=True, mode=0o700)
                self.refresh()
                tools = self.stack.enter_context(open_workspace_tools(
                    self.key, profile="python", socket_path=self.endpoint, transport=Async(uds=self.endpoint)))
                self.server = self.stack.enter_context(SandcrabMcpServer(tools))
                workspace = self.require(*self.api("GET", self.route))
                self.generation, self.volume = workspace["generation"], workspace["id"]
                self.session = self.working_session()
                runtime = self.execute(self.session, "python3 --version")
                if runtime["state"] != "succeeded":
                    raise RuntimeError("Sandbox Python is unavailable")
                self.state["sandboxPython"] = runtime["result"]["stdout"].strip()
                self.populate(self.session, case["fixture"]["files"])
        else:
            super().prepare(case)
            client = self.stack.enter_context(SandcrabClient(
                socket_path=self.endpoint, default_profile="python", transport=Sync(uds=self.endpoint)))
            self.server = self.stack.enter_context(SandcrabMcpServer(client))
        self.rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                                "clientInfo": {"name": "sandcrab-evaluation", "version": "1"}})
        self.schemas = self.rpc("tools/list", {})["tools"]

    def working_session(self):
        if self.bound:
            info = self.rpc("tools/call", {"name": "list_dir", "arguments": {"path": "."}})
            if info["isError"]:
                raise RuntimeError("Workspace files could not be opened for export")
        record = self.require(*self.api("GET", "/v1/volumes/" + self.volume))
        identity = record.get("attachedTo")
        if not identity and not self.bound:
            identity = self.open_session(self.volume)
        if not identity:
            raise RuntimeError("The workspace has no confirmed open session")
        if self.bound:
            self.parents.add(identity)
        return identity

    def call(self, name, arguments):
        with self.exclusive("agent"):
            if not self.bound:
                if arguments.get("session_id") is not None and arguments["session_id"] not in self.state["sessions"]:
                    raise Rejected("Choose a session in the current sample")
                if arguments.get("volume_id") not in (None, self.volume) or arguments.get("template_id") is not None:
                    raise Rejected("Choose storage in the current sample")
                if arguments.get("profile") not in (None, "python"):
                    raise Rejected("The sample uses the python profile")
            self.state["mcpCalls"] += 1
            reply = self.rpc("tools/call", {"name": name, "arguments": arguments})
            text = reply["content"][0]["text"]
            if reply["isError"]:
                raise Rejected(text)
            return text

    def export(self):
        with self.exclusive("agent"):
            self.session = self.working_session()
            return super().export()

    def available_tools(self):
        def convert(schema):
            async def invoke(**kwargs):
                try:
                    return await asyncio.to_thread(self.call, schema["name"], kwargs)
                except Rejected as error:
                    raise ToolError(str(error)) from None
            params = ToolParams.model_validate(schema["inputSchema"])
            # Inspect requires parameter descriptions; mirror the name for either catalog when omitted.
            for name, parameter in params.properties.items():
                if not parameter.description:
                    parameter.description = name
            return ToolDef(invoke, name=schema["name"], description=schema["description"],
                           parameters=params, parallel=False).as_tool()
        return [convert(schema) for schema in self.schemas]

    def stop_client(self):
        self.stack.close()
        if not self.managed_post:
            return
        status, workspace = self.api("GET", self.route)
        self.require(status, workspace)
        if self.generation and workspace["generation"] != self.generation:
            raise RuntimeError("Workspace generation changed before evaluation cleanup")
        expected = {"generation": workspace["generation"]}
        if workspace["state"] not in ("deleted", "failed"):
            self.require(*self.api("POST", self.route + "/delete", expected), accepted=(200, 202))
            if self.poll("workspaces", self.key, {"deleting"})["state"] != "deleted":
                raise RuntimeError("Workspace containment was not confirmed")
        self.require(*self.api("POST", self.route + "/forget", expected))
        self.managed_post = False
        for identity in self.parents:
            if identity not in self.state["sessions"]:
                self.state["sessions"].append(identity)
            self.finished("sessions", identity)

    def grade(self, case):
        self.agent_closed.set()
        with self.exclusive("grading"):
            self.stop_client()
        return super().grade(case)

    def cleanup(self):
        self.agent_closed.set()
        with self.exclusive("cleanup"):
            self.stop_client()
        super().cleanup()
