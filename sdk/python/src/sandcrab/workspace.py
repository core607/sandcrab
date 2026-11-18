"""Agent tools bound to one application-selected workspace."""
from __future__ import annotations

import asyncio
import base64
import codecs
from contextlib import contextmanager
from functools import partial
import hashlib
import re
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode
import uuid

import httpx

from ._wire import check_digest, check_profile, check_relative_path, check_uuid, parse_json_response
from .errors import ProtocolError, SandcrabError, TransportUncertainError

if TYPE_CHECKING:
    from .client import AsyncSandcrabClient


TEXT_BYTES = 16384
TRUNCATED = "\n[truncated]"
TOOL_NAMES = {"exec", "read_file", "write_file", "edit_file", "list_dir", "search"}
UNKNOWN = {"ok": False, "code": "OUTCOME_UNKNOWN", "message": "Inspect the workspace before submitting another write."}


def _clip(text: str) -> tuple[str, bool]:
    raw = text.encode()
    if len(raw) <= TEXT_BYTES:
        return text, False
    return raw[:TEXT_BYTES].decode(errors="ignore") + TRUNCATED, True


class WorkspaceTools:
    def __init__(self, client: AsyncSandcrabClient, route: str, generation: str, schemas: list[dict], *, fresh_child: bool = False):
        self._client = client
        self._route = route
        self._generation = generation
        self._fresh_child = fresh_child
        self.schemas = [item for item in schemas if item["name"] in TOOL_NAMES]
        self._inputs = {item["name"]: item["inputSchema"] for item in self.schemas}
        self.handlers = {name: partial(self.call, name) for name in self._inputs}

    @classmethod
    async def bind(cls, client: AsyncSandcrabClient, key: str, profile: str | None = None, *,
                   template_id: str | None = None, fresh_child: bool = False) -> WorkspaceTools:
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", key):
            raise ValueError("Invalid workspace key")
        route = "/v1/workspaces/" + key
        if type(fresh_child) is not bool:
            raise ValueError("fresh_child must be a boolean")
        plan = {"profile": check_profile(profile or client.default_profile or "default")}
        if template_id is not None:
            plan["templateId"] = check_digest(template_id, "template ID")
        info = await client._request_json("POST", route, json_body=plan)
        generation = check_uuid(info["generation"], "generation")
        until = time.monotonic() + 35
        while info["state"] == "creating" and time.monotonic() < until:
            await asyncio.sleep(.025)
            info = await client._request_json("GET", route)
        if info["generation"] != generation or info["state"] != "ready":
            raise SandcrabError(409, "WORKSPACE_NOT_READY")
        catalog = await client._request_json("GET", "/v1/workspace-tools")
        return cls(client, route, generation, catalog["tools"], fresh_child=fresh_child)

    def _validate(self, name: str, args: dict[str, Any]) -> None:
        schema = self._inputs[name]
        if not isinstance(args, dict) or set(args) - schema["properties"].keys() or not set(schema["required"]).issubset(args):
            raise ValueError("Invalid tool arguments")
        for key, value in args.items():
            spec = schema["properties"][key]
            expected = {"string": str, "integer": int, "boolean": bool}[spec["type"]]
            if type(value) is not expected:
                raise ValueError("Invalid " + key)
            if expected is str and not spec.get("minLength", 0) <= len(value) <= spec.get("maxLength", 65536):
                raise ValueError("Invalid " + key)
            if expected is int and not spec.get("minimum", 0) <= value <= spec.get("maximum", 2**53 - 1):
                raise ValueError("Invalid " + key)

    async def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name not in self.handlers:
            return {"ok": False, "code": "UNKNOWN_TOOL"}
        try:
            self._validate(name, arguments)
            until = time.monotonic() + 5
            while True:
                try:
                    if name == "exec":
                        return await self._exec(arguments)
                    return await self._file(name, arguments)
                except SandcrabError as error:
                    if error.code not in ("WORKSPACE_REOPENING", "SESSION_FILES_BUSY", "WORKSPACE_SUBMISSION_EXPIRED") or time.monotonic() >= until:
                        raise
                    await asyncio.sleep(.025)
        except (ValueError, TypeError):
            return {"ok": False, "code": "INVALID_ARGUMENTS"}
        except (TransportUncertainError, TimeoutError):
            return dict(UNKNOWN)
        except SandcrabError as error:
            if error.code == "EDIT_CONFLICT":
                return {"ok": False, "code": "EDIT_CONFLICT"}
            if error.code == "EDIT_MATCH_COUNT":
                return {"ok": False, "code": "EDIT_CONFLICT", "message": "Read the file and choose one exact match."}
            if error.status == 404:
                return {"ok": False, "code": "NOT_FOUND"}
            if error.status == 429 or error.code in ("WORKSPACE_REOPENING", "SESSION_FILES_BUSY"):
                return {"ok": False, "code": "BUSY"}
            if error.status == 413:
                return {"ok": False, "code": "LIMIT"}
            if name in ("exec", "write_file", "edit_file") and (error.status >= 500 or "UNKNOWN" in error.code or "UNCONFIRMED" in error.code):
                return dict(UNKNOWN)
            return {"ok": False, "code": "REFUSED"}
        except (httpx.TransportError, ProtocolError):
            return {"ok": False, "code": "TRANSPORT_ERROR"}

    async def _exec(self, args: dict) -> dict:
        current = await self._client._request_json("GET", self._route)
        if current["generation"] != self._generation:
            raise SandcrabError(409, "WORKSPACE_CHANGED")
        run_id = str(uuid.uuid4())
        body = {**args, "id": run_id, "generation": self._generation, "serverId": current["serverId"],
                "submissionWindow": current["submissionWindow"]}
        if self._fresh_child:
            body["freshChild"] = True
        await self._client._request_json("POST", self._route + "/commands", json_body=body,
                                         recovery_id=run_id, uncertain_op="workspace command")
        try:
            run = await self._client.wait_run(run_id)
        except (httpx.TransportError, ProtocolError, SandcrabError) as error:
            raise TransportUncertainError("workspace command", run_id, error) from error
        result = run.get("result") or {}
        if result.get("executed") is False:
            return {"ok": False, "code": "REFUSED"}
        stdout, cut_out = _clip(result.get("stdout", ""))
        stderr, cut_err = _clip(result.get("stderr", ""))
        out = {"ok": run["state"] == "succeeded", "exitCode": result.get("exitCode"), "stdout": stdout, "stderr": stderr,
               "freshShell": run["freshShell"], "truncated": bool(result.get("truncated")) or cut_out or cut_err}
        if not out["ok"]:
            out["code"] = "TIMEOUT" if run["state"] in ("timeout", "timed_out") else "COMMAND_FAILED"
        return out

    async def checkpoint(self) -> bytes:
        """Download a digest-verified tar of changes relative to the pinned template."""
        return await self._client._request_bytes("GET", self._route + "/diff",
            headers={"X-Sandcrab-Workspace-Generation": self._generation}, expect_etag=True)

    async def dispose(self) -> None:
        expected = {"generation": self._generation}
        await self._client._request_json("POST", self._route + "/delete", json_body=expected)
        until = time.monotonic() + 65
        while time.monotonic() < until:
            info = await self._client._request_json("GET", self._route)
            if info["generation"] != self._generation:
                raise SandcrabError(409, "WORKSPACE_CHANGED")
            if info["state"] == "deleted":
                await self._client._request_json("POST", self._route + "/forget", json_body=expected)
                return
            if info["state"] != "deleting":
                raise SandcrabError(409, "WORKSPACE_CLEANUP_UNCONFIRMED")
            await asyncio.sleep(.025)
        raise TimeoutError("Workspace deletion did not finish")

    async def _file(self, name: str, args: dict) -> dict:
        path = check_relative_path(args.get("path", "."), allow_root=name in ("list_dir", "search"))
        headers = {"X-Sandcrab-Workspace-Generation": self._generation}
        route = self._route + "/files"
        if name == "read_file":
            return await self._read(route, path, args, headers)
        if name == "write_file":
            data = args["content"].encode()
            if len(data) > 32768:
                raise ValueError("Content exceeds tool limit")
            query = urlencode({"path": path, "parents": str(args.get("parents", True)).lower(),
                               "replace": str(args.get("replace", True)).lower()})
            receipt = await self._client._request_json("PUT", route + "?" + query, content=data, headers=headers,
                                                       recovery_id=path, uncertain_op="write file")
            if (receipt.get("path") != path or type(receipt.get("bytes")) is not int
                    or receipt["bytes"] != len(data) or receipt.get("sha256") != hashlib.sha256(data).hexdigest()):
                return dict(UNKNOWN)
            return {"ok": True, "bytes": receipt["bytes"], "version": receipt["sha256"]}
        if name == "edit_file":
            edit = {"path": path, "expectedSha256": check_digest(args["version"]), "old": args["old"], "new": args["new"]}
            receipt = await self._client._request_json("POST", route + "/edit", json_body=edit, headers=headers,
                                                       recovery_id=path, uncertain_op="edit file")
            if (receipt.get("path") != path or type(receipt.get("replacedCount")) is not int
                    or receipt["replacedCount"] != 1):
                return dict(UNKNOWN)
            return {"ok": True, "replacedCount": receipt["replacedCount"]}
        query = {"path": path}
        if name == "list_dir":
            action, query["depth"] = "list", args.get("depth", 1)
        else:
            action, query["pattern"] = "search", args.get("pattern", "*")
            if "contains" in args:
                query["contains"] = args["contains"]
        data = await self._client._request_json("GET", route + "/" + action + "?" + urlencode(query), headers=headers)
        entries = []
        budget = TEXT_BYTES
        for item in data["entries"]:
            size = len(item["path"].encode()) + 64
            if size > budget or len(entries) == 128:
                break
            entries.append({key: item[key] for key in ("path", "type", "size")})
            budget -= size
        return {"ok": True, "entries": entries, "truncated": len(entries) != len(data["entries"])}

    async def _read(self, route: str, path: str, args: dict, headers: dict) -> dict:
        query = {"path": path}
        headers["X-Sandcrab-Read-Version"] = "sha256"
        as_bytes = "byteStart" in args or "byteEnd" in args
        if as_bytes:
            start = args.get("byteStart", 0)
            end = args.get("byteEnd", start + TEXT_BYTES - 1)
            if end < start or "offset" in args or "limit" in args:
                raise ValueError("Choose one file range")
            headers["Range"] = f"bytes={start}-{min(end, start + TEXT_BYTES)}"
        else:
            query.update(offset=args.get("offset", 1), limit=args.get("limit", 201), maxBytes=TEXT_BYTES + 1)
        async with self._client._http.stream("GET", route + "?" + urlencode(query), headers=headers) as response:
            if response.status_code >= 400:
                parse_json_response(response.status_code, await response.aread())
            if response.status_code != (206 if as_bytes else 200):
                raise ProtocolError("Unexpected file selection response")
            raw = bytearray()
            async for chunk in response.aiter_bytes(8192):
                raw.extend(chunk[:TEXT_BYTES + 1 - len(raw)])
            version = response.headers.get("x-sandcrab-file-sha256")
            if version:
                check_digest(version)
        clipped = len(raw) > TEXT_BYTES
        raw = bytes(raw[:TEXT_BYTES])
        if as_bytes:
            content, encoding = base64.b64encode(raw).decode(), "base64"
        else:
            rows = raw.split(b"\n")
            limit = args.get("limit", 200)
            clipped |= "limit" not in args and len(rows) > limit
            raw = b"\n".join(rows[:limit])
            try:
                content = codecs.getincrementaldecoder("utf-8")().decode(raw, final=not clipped)
            except UnicodeDecodeError:
                return {"ok": False, "code": "BINARY_FILE", "message": "Use a byte range to read binary content."}
            encoding = "utf-8"
            if clipped:
                content += TRUNCATED
        return {"ok": True, "content": content, "encoding": encoding, "version": version, "truncated": clipped}


class SyncWorkspaceTools:
    def __init__(self, tools: WorkspaceTools, runner: asyncio.Runner):
        self.schemas = tools.schemas
        self._tools = tools
        self._runner = runner

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self._runner.run(self._tools.call(name, arguments))

    def dispose(self) -> None:
        self._runner.run(self._tools.dispose())

    def checkpoint(self) -> bytes:
        return self._runner.run(self._tools.checkpoint())


@contextmanager
def open_workspace_tools(key: str, *, profile: str | None = None, template_id: str | None = None,
                         fresh_child: bool = False, **connection):
    """Bind the same tools in a synchronous application, including a stdio MCP server."""
    from .client import AsyncSandcrabClient
    with asyncio.Runner() as runner:
        client = AsyncSandcrabClient(**connection)
        try:
            tools = runner.run(WorkspaceTools.bind(client, key, profile, template_id=template_id, fresh_child=fresh_child))
            yield SyncWorkspaceTools(tools, runner)
        finally:
            runner.run(client.close())
