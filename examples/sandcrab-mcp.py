#!/usr/bin/env python3
"""Launch the Sandcrab stdio MCP server for local agent harnesses.

Configure the control plane through flags or SANDCRAB_ENDPOINT / SANDCRAB_TOKEN_FILE /
SANDCRAB_SOCKET / SANDCRAB_PROFILE environment variables. Sessions opened through MCP
are closed and forgotten automatically when stdin closes.
"""
from pathlib import Path
import sys

REPO_SDK = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
if REPO_SDK.is_dir() and str(REPO_SDK) not in sys.path:
    sys.path.insert(0, str(REPO_SDK))

from sandcrab.mcp import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
