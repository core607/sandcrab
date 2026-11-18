"""Run identical, validated commands against both services using one upstream SDK."""
import asyncio
from datetime import timedelta
from importlib.metadata import version
import json
from pathlib import Path
import sys
import time

from opensandbox import Sandbox
from opensandbox.config import ConnectionConfig
from protocol import load
from workload import AgentWorkload


def elapsed(start):
    return (time.perf_counter_ns() - start) / 1_000_000


async def execute(box, argv):
    result = await box.commands.run(argv)
    if result.exit_code != 0 or result.error is not None or result.complete is None:
        raise RuntimeError("Command did not complete successfully")
    return "".join(chunk.text for chunk in result.logs.stdout)


class Client:
    def __init__(self):
        self.connection = None
        self.image = None
        self.boxes = []
        self.seed = load()["seed"]

    async def create(self, ttl):
        start = time.perf_counter_ns()
        box = await Sandbox.create(self.image, connection_config=self.connection, timeout=timedelta(seconds=ttl),
                                   resource={"cpu": "0.25", "memory": "64Mi"})
        self.boxes.append(box)
        create = elapsed(start)
        output = await execute(box, ["python3", "-c", "print(6 * 7)"])
        if output.strip() != "42":
            raise RuntimeError("Incorrect first command output")
        return {"createMs": create, "createAndFirstCommandMs": elapsed(start)}

    async def seed_latest(self, files):
        box = self.boxes[-1]
        script = Path(__file__).with_name("workload.py").read_text()
        await box.files.write_file("/workspace/generator.py", script)
        # Both services use the same corpus generator and validate its returned digest.
        out = await execute(box, ["bash", "-ec", "mkdir -p /workspace/case && python3 /workspace/generator.py --root "
                            f"/workspace/case --seed {self.seed} --files {files}"])
        return json.loads(out.strip().splitlines()[-1])

    async def dispatch(self, request):
        op = request["op"]
        if op == "connect":
            self.connection = ConnectionConfig(domain=request["endpoint"], protocol="http", api_key=request["key"])
            self.image = request["image"]
            return {"sdk": version("opensandbox")}
        if op == "create":
            return await self.create(request["ttl"])
        if op == "seed":
            return await self.seed_latest(request["files"])
        if op == "exercise":
            async def validate(i, box):
                workload = AgentWorkload(self.seed, i, files=request["files"])
                row = {}
                for _ in range(request["operations"]):
                    task = workload.next()
                    started = time.perf_counter_ns()
                    await execute(box, ["bash", "-ec", "cd /workspace/case && " + task["command"]])
                    row.setdefault(task["kind"], []).append(elapsed(started))
                return row
            results = await asyncio.gather(*(validate(i, box) for i, box in enumerate(self.boxes)), return_exceptions=True)
            return {"samples": [item for item in results if isinstance(item, dict)],
                    "errors": [type(item).__name__ for item in results if isinstance(item, BaseException)]}
        if op == "close":
            while self.boxes:
                box = self.boxes[-1]
                try:
                    await box.kill()
                finally:
                    await box.close()
                self.boxes.pop()
            return {"closed": True}
        raise ValueError("Unknown measurement operation")


async def main():
    client = Client()
    print(json.dumps({"ready": True}), flush=True)
    for line in sys.stdin:
        try:
            value = await client.dispatch(json.loads(line))
        except Exception as error:
            # The controller supplies an ephemeral service credential. Record only the error class and API code.
            value = {"error": type(error).__name__, "code": str(getattr(error, "code", "") or "")[:120],
                     "status": getattr(error, "status_code", None)}
        print(json.dumps(value), flush=True)


if __name__ == "__main__":
    asyncio.run(main())
