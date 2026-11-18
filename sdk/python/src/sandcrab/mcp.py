"""Standard-library JSON-RPC 2.0 stdio MCP server for Sandcrab."""
from __future__ import annotations

import argparse
import base64
import io
import json
import sys
from typing import Any, BinaryIO

import httpx

from .client import SandcrabClient
from ._version import __version__
from .errors import CommandFailedError, ProtocolError, SandcrabError, TransportUncertainError

SUPPORTED_PROTOCOLS = ("2025-03-26", "2024-11-05")
DEFAULT_PROTOCOL = "2024-11-05"
MCP_MAX_MESSAGE_BYTES = 4 * 1024 * 1024
MCP_FILE_BOUND_BYTES = 1024 * 1024


TOOLS: list[dict[str, Any]] = [
    {
        "name": "sandcrab_run",
        "description": "Execute one argv command inside a fresh ephemeral Sandcrab sandbox.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "description": "Executable and arguments passed directly without a host shell.",
                },
                "profile": {"type": "string", "description": "Sandbox profile name."},
                "timeout_ms": {"type": "integer", "minimum": 1},
                "output_limit_bytes": {"type": "integer", "minimum": 1},
            },
            "required": ["command"],
            "additionalProperties": False,
        },
    },
    {
        "name": "sandcrab_session_open",
        "description": "Open an isolated persistent Sandcrab session. Unclosed sessions opened by this MCP server are closed on exit.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "profile": {"type": "string"},
                "ttl_ms": {"type": "integer", "minimum": 1},
                "template_id": {"type": "string"},
                "volume_id": {"type": "string"},
                "rootfs": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "sandcrab_session_exec",
        "description": "Execute a shell command inside an existing Sandcrab session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "command": {"type": "string", "minLength": 1},
                "timeout_ms": {"type": "integer", "minimum": 1},
                "output_limit_bytes": {"type": "integer", "minimum": 1},
            },
            "required": ["session_id", "command"],
            "additionalProperties": False,
        },
    },
    {
        "name": "sandcrab_session_close",
        "description": "Close and forget an open Sandcrab session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
            },
            "required": ["session_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "sandcrab_write_file",
        "description": "Write UTF-8 text or base64 bytes to a workspace-relative path in a session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "path": {"type": "string"},
                "content": {"type": "string", "description": "UTF-8 file contents."},
                "base64": {"type": "string", "description": "Base64-encoded binary contents."},
                "parents": {"type": "boolean", "default": True},
                "replace": {"type": "boolean", "default": True},
                "mode": {"type": "integer", "minimum": 0, "maximum": 511},
            },
            "required": ["session_id", "path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "sandcrab_read_file",
        "description": "Read a workspace-relative file, optionally bounded by 1-based line offset/limit or HTTP byte range.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "path": {"type": "string"},
                "offset": {"type": "integer", "minimum": 1},
                "limit": {"type": "integer", "minimum": 1},
                "byte_range": {"type": "string", "description": "Byte range such as 0-4095 or -1024."},
                "encoding": {"type": "string", "enum": ["utf-8", "base64"], "default": "utf-8"},
            },
            "required": ["session_id", "path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "sandcrab_mkdir",
        "description": "Create a workspace-relative directory (and missing parents) in a session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "path": {"type": "string"},
                "mode": {"type": "integer", "minimum": 0, "maximum": 511},
            },
            "required": ["session_id", "path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "sandcrab_list_files",
        "description": "List bounded metadata entries under a workspace-relative directory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "path": {"type": "string", "default": "."},
                "depth": {"type": "integer", "minimum": 0, "maximum": 64, "default": 1},
            },
            "required": ["session_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "sandcrab_search_files",
        "description": "Search workspace paths matching a glob pattern.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "pattern": {"type": "string", "minLength": 1},
                "path": {"type": "string", "default": "."},
            },
            "required": ["session_id", "pattern"],
            "additionalProperties": False,
        },
    },
]


def _read_rpc_frame(stream: BinaryIO) -> tuple[bytes, str] | None:
    while True:
        first = stream.readline(MCP_MAX_MESSAGE_BYTES + 1)
        if not first:
            return None
        if len(first) > MCP_MAX_MESSAGE_BYTES:
            raise ProtocolError("MCP stdio frame exceeded size limit")
        stripped = first.strip()
        if not stripped:
            continue
        if stripped.lower().startswith(b"content-length:"):
            _, _, length_text = stripped.partition(b":")
            try:
                length = int(length_text.strip())
            except ValueError as error:
                raise ProtocolError("Invalid Content-Length header") from error
            if length < 0 or length > MCP_MAX_MESSAGE_BYTES:
                raise ProtocolError("MCP Content-Length out of bounds")
            while True:
                header_line = stream.readline(4096)
                if not header_line:
                    raise ProtocolError("EOF inside MCP headers")
                if header_line in (b"\r\n", b"\n"):
                    break
            body = stream.read(length)
            if len(body) != length:
                raise ProtocolError("Truncated MCP Content-Length payload")
            return body, "content-length"
        return stripped, "jsonl"


def _write_rpc_frame(stream: BinaryIO, payload: dict[str, Any], framing: str) -> None:
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if framing == "content-length":
        stream.write(f"Content-Length: {len(encoded)}\r\n\r\n".encode("ascii"))
        stream.write(encoded)
    else:
        stream.write(encoded + b"\n")
    stream.flush()


class SandcrabMcpServer:
    """Bounded stdio MCP server delegating sandbox operations to `SandcrabClient`."""

    def __init__(self, client: SandcrabClient) -> None:
        self.client = client
        self._owned_sessions: set[str] = set()

    def close(self) -> None:
        for session_id in list(self._owned_sessions):
            try:
                self.client.close_session(session_id, forget=True)
            except BaseException:
                pass
            self._owned_sessions.discard(session_id)
        self.client.close()

    def __enter__(self) -> SandcrabMcpServer:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        if name == "sandcrab_run":
            command = args.get("command")
            if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
                raise ValueError("command must be a non-empty array of strings")
            return self.client.run(
                command,
                profile=args.get("profile"),
                timeout_ms=args.get("timeout_ms"),
                output_limit_bytes=args.get("output_limit_bytes"),
            )

        if name == "sandcrab_session_open":
            session = self.client.open_session(
                profile=args.get("profile"),
                ttl_ms=args.get("ttl_ms"),
                template_id=args.get("template_id"),
                volume_id=args.get("volume_id"),
                rootfs=bool(args.get("rootfs", False)),
                auto_close=False,
            )
            self._owned_sessions.add(session.id)
            return session.data

        if name == "sandcrab_session_exec":
            return self.client.session_exec(
                str(args["session_id"]),
                str(args["command"]),
                timeout_ms=args.get("timeout_ms"),
                output_limit_bytes=args.get("output_limit_bytes"),
            )

        if name == "sandcrab_session_close":
            session_id = str(args["session_id"])
            closed = self.client.close_session(session_id, forget=True)
            self._owned_sessions.discard(session_id)
            return closed

        if name == "sandcrab_write_file":
            has_text = "content" in args and args["content"] is not None
            has_b64 = "base64" in args and args["base64"] is not None
            if has_text == has_b64:
                raise ValueError("Provide exactly one of 'content' or 'base64'")
            if has_text:
                raw = str(args["content"]).encode("utf-8")
            else:
                raw = base64.b64decode(str(args["base64"]), validate=True)
            if len(raw) > MCP_FILE_BOUND_BYTES:
                raise ValueError(f"MCP file write exceeds {MCP_FILE_BOUND_BYTES} bytes")
            return self.client.write_file(
                str(args["session_id"]),
                str(args["path"]),
                raw,
                parents=bool(args.get("parents", True)),
                replace=bool(args.get("replace", True)),
                mode=args.get("mode"),
            )

        if name == "sandcrab_read_file":
            encoding = args.get("encoding", "utf-8")
            if encoding not in ("utf-8", "base64"):
                raise ValueError("encoding must be 'utf-8' or 'base64'")
            raw = self.client.read_file(
                str(args["session_id"]),
                str(args["path"]),
                byte_range=args.get("byte_range"),
                offset=args.get("offset"),
                limit=args.get("limit"),
            )
            if len(raw) > MCP_FILE_BOUND_BYTES:
                raise ValueError(
                    f"File slice ({len(raw)} bytes) exceeds {MCP_FILE_BOUND_BYTES} bytes; pass offset/limit or byte_range"
                )
            if encoding == "base64":
                return {"path": args["path"], "encoding": "base64", "base64": base64.b64encode(raw).decode("ascii")}
            try:
                text = raw.decode("utf-8")
                return {"path": args["path"], "encoding": "utf-8", "content": text}
            except UnicodeDecodeError:
                return {"path": args["path"], "encoding": "base64", "base64": base64.b64encode(raw).decode("ascii")}

        if name == "sandcrab_mkdir":
            return self.client.mkdir(str(args["session_id"]), str(args["path"]), mode=args.get("mode"))

        if name == "sandcrab_list_files":
            entries = self.client.list_files(
                str(args["session_id"]),
                str(args.get("path", ".")),
                depth=int(args.get("depth", 1)),
            )
            return {"entries": entries}

        if name == "sandcrab_search_files":
            entries = self.client.search_files(
                str(args["session_id"]),
                str(args["pattern"]),
                path=str(args.get("path", ".")),
            )
            return {"entries": entries}

        raise KeyError(name)

    def handle_message(self, message: Any) -> dict[str, Any] | None:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return {
                "jsonrpc": "2.0",
                "id": message.get("id") if isinstance(message, dict) else None,
                "error": {"code": -32600, "message": "Invalid JSON-RPC 2.0 request"},
            }
        is_notification = "id" not in message
        req_id = message.get("id")
        method = message.get("method")
        params = message.get("params") if message.get("params") is not None else {}
        if not isinstance(method, str):
            if is_notification:
                return None
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32600, "message": "Missing method"}}
        if is_notification:
            return None
        if not isinstance(params, dict):
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Params must be an object"}}

        if method == "initialize":
            requested = params.get("protocolVersion")
            negotiated = requested if requested in SUPPORTED_PROTOCOLS else DEFAULT_PROTOCOL
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": negotiated,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "sandcrab", "version": __version__},
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}

        if method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments") if params.get("arguments") is not None else {}
            if not isinstance(tool_name, str) or not isinstance(tool_args, dict):
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": "tools/call requires string name and object arguments"},
                }
            known_names = {tool["name"] for tool in TOOLS}
            if tool_name not in known_names:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": f"Unknown tool: {tool_name}"},
                }
            try:
                output = self._call_tool(tool_name, tool_args)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(output)}],
                        "isError": False,
                    },
                }
            except (
                SandcrabError,
                TransportUncertainError,
                CommandFailedError,
                ProtocolError,
                ValueError,
                KeyError,
                TimeoutError,
                httpx.TransportError,
            ) as err:
                err_payload: dict[str, Any] = {"error": str(err)}
                if isinstance(err, SandcrabError):
                    err_payload["status"] = err.status
                    err_payload["code"] = err.code
                    if err.recovery_id:
                        err_payload["recoveryId"] = err.recovery_id
                elif isinstance(err, TransportUncertainError):
                    err_payload["code"] = "TRANSPORT_UNCERTAIN"
                    err_payload["recoveryId"] = err.recovery_id
                elif isinstance(err, httpx.TransportError):
                    err_payload["code"] = "TRANSPORT_ERROR"
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(err_payload)}],
                        "isError": True,
                    },
                }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    def serve_stdio(
        self,
        stdin: BinaryIO | None = None,
        stdout: BinaryIO | None = None,
    ) -> None:
        reader = sys.stdin.buffer if stdin is None else stdin
        writer = sys.stdout.buffer if stdout is None else stdout
        try:
            while True:
                framed = _read_rpc_frame(reader)
                if framed is None:
                    break
                raw, mode = framed
                try:
                    parsed = json.loads(raw.decode("utf-8"))
                except ValueError:
                    _write_rpc_frame(
                        writer,
                        {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
                        mode,
                    )
                    continue
                reply = self.handle_message(parsed)
                if reply is not None:
                    _write_rpc_frame(writer, reply, mode)
        finally:
            self.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sandcrab-mcp",
        description="Run the Sandcrab JSON-RPC 2.0 MCP server over stdio.",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--socket", dest="socket_path", help="Root-owned Sandcrab Unix socket path")
    group.add_argument("--endpoint", help="Loopback HTTP endpoint such as http://127.0.0.1:8080")
    parser.add_argument("--token-file", help="64-hex service token file for loopback HTTP")
    parser.add_argument("--profile", help="Default Sandcrab profile when tool calls omit profile")
    args = parser.parse_args(argv)
    try:
        client = SandcrabClient(
            socket_path=args.socket_path,
            endpoint=args.endpoint,
            token_file=args.token_file,
            default_profile=args.profile,
        )
    except ValueError as err:
        print(f"sandcrab-mcp: {err}", file=sys.stderr)
        return 2
    with SandcrabMcpServer(client) as server:
        server.serve_stdio()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
