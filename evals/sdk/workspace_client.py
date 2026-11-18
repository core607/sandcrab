"""JSON-line adapter used to exercise a packaged async workspace client."""
import asyncio
import json
import sys

from sandcrab import AsyncSandcrabClient


async def main():
    async with AsyncSandcrabClient() as client:
        tools = await client.workspace_tools(sys.argv[1], profile="default")
        print(json.dumps(tools.schemas), flush=True)
        for line in sys.stdin:
            request = json.loads(line)
            if request["name"] == "dispose":
                await tools.dispose()
                print("true", flush=True)
                return
            result = await tools.handlers[request["name"]](request["arguments"])
            print(json.dumps(result), flush=True)


asyncio.run(main())
