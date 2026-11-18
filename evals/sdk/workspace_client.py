"""JSON-line adapter used to exercise a packaged async workspace client."""
import asyncio
import base64
import json
import sys

from sandcrab import AsyncSandcrabClient


async def main():
    async with AsyncSandcrabClient() as client:
        base = await client.import_template(sys.argv[2], profile="default")
        tools = await client.workspace_tools(sys.argv[1], profile="default", template_id=base["id"], fresh_child=True)
        print(json.dumps(tools.schemas), flush=True)
        for line in sys.stdin:
            request = json.loads(line)
            if request["name"] == "checkpoint":
                print(json.dumps(base64.b64encode(await tools.checkpoint()).decode()), flush=True)
                continue
            if request["name"] == "dispose":
                await tools.dispose()
                await client.delete_template(base["id"])
                print("true", flush=True)
                return
            result = await tools.handlers[request["name"]](request["arguments"])
            print(json.dumps(result), flush=True)


asyncio.run(main())
