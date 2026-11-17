"""CLI module entrypoint (`python3 -m sandcrab.mcp` or `python3 -m sandcrab`)."""
from .mcp import main

if __name__ == "__main__":
    raise SystemExit(main())
