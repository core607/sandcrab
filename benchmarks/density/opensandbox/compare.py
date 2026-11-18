"""Measure both services sequentially in isolated guests of the same Docker engine."""
import argparse
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import time
import uuid

MEMORY = 4_000_000_000
STAGES = (1, 4, 8, 16, 25, 50, 100)
LABEL = "sandcrab.comparison.fixture"


def docker(*args, timeout=180):
    result = subprocess.run(["docker", *map(str, args)], capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace")[-1500:])
    return result.stdout


def summary(values):
    if not values:
        return {"count": 0}
    ordered = sorted(values)
    return {"count": len(values), **{label: round(ordered[math.ceil(len(values)*q)-1], 3)
                                     for label, q in (("p50", .5), ("p95", .95))}}


def checksum(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


@contextmanager
def machine(args):
    name = "sandcrab-compare-" + uuid.uuid4().hex
    guest = docker("run", "--detach", "--privileged", "--cgroupns=private", "--network=none",
                   "--mount", "type=volume,destination=/var/lib", "--tmpfs", "/run", "--tmpfs", "/tmp",
                   "--cpus=2", "--memory", MEMORY, "--memory-swap", MEMORY, "--pids-limit=4096",
                   "--name", name, "--label", LABEL+"="+name, "-e", "SANDCRAB_COMPARISON_FIXTURE="+name,
                   args.machine).decode().strip()
    try:
        until = time.monotonic() + 45
        while True:
            state = subprocess.run(["docker", "exec", guest, "systemctl", "is-system-running"], capture_output=True)
            if state.stdout.strip() in (b"running", b"degraded"):
                break
            if time.monotonic() > until:
                raise RuntimeError("Comparison guest failed to boot")
            time.sleep(.25)
        docker("cp", Path(__file__).with_name("machine.py"), guest + ":/root/compare-machine.py")
        yield guest
    finally:
        actual = json.loads(docker("inspect", guest))[0]
        if actual["Config"]["Labels"].get(LABEL) != name:
            raise RuntimeError("Comparison fixture ownership changed")
        docker("rm", "--force", "--volumes", guest)


def inside(guest, action, *args):
    return docker("exec", guest, "python3", "/root/compare-machine.py", action, *args, timeout=240)


class Sdk:
    def __init__(self, guest, image):
        self.process = subprocess.Popen(["docker", "run", "--rm", "-i", "--network", "container:"+guest,
                                         "--read-only", "--tmpfs", "/tmp", "--cap-drop=ALL", image],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        text=True, encoding="utf-8", bufsize=1)
        self.reader = ThreadPoolExecutor(max_workers=1)

    def receive(self, timeout=120):
        try:
            line = self.reader.submit(self.process.stdout.readline).result(timeout=timeout)
        except TimeoutError:
            self.process.kill()
            raise TimeoutError("SDK did not finish the requested operation") from None
        if not line:
            raise RuntimeError("SDK client exited before its response")
        reply = json.loads(line)
        if reply.get("error"):
            raise RuntimeError(f"{reply['error']} {reply.get('code','')} {reply.get('status')}")
        return reply

    def call(self, op, **args):
        print(json.dumps({"op": op, **args}), file=self.process.stdin, flush=True)
        return self.receive(timeout=240 if op in ("exercise", "close") else 120)

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.reader.shutdown()


def measure(backend, args, raw):
    stages = (1, 2) if args.smoke else STAGES
    files = 64 if args.smoke else 256
    ops = 3 if args.smoke else 12
    with machine(args) as guest:
        host = json.loads(inside(guest, "host"))
        if abs(int(host["memoryMax"])-MEMORY) > 4096 or host["swapMax"] != "0":
            raise RuntimeError("Memory or swap limits differ from the comparison protocol")
        quota, period = map(int, host["cpuMax"].split())
        if quota != 2*period:
            raise RuntimeError("CPU limit differs from the comparison protocol")
        def sample():
            value = json.loads(inside(guest, "sample"))
            raw({"backend": backend, "sample": value})
            return value
        docker("cp", args.bundle if backend == "sandcrab" else args.images,
               guest + (":/root/sandcrab.zip" if backend == "sandcrab" else ":/root/images.tar"))
        sdk = Sdk(guest, args.client)
        rows, created, first, latencies = [], [], [], []
        report = {"environment": host, "stages": rows, "largestPassingStage": 0, "stop": "stage ceiling"}
        n = 0
        try:
            if sdk.receive() != {"ready": True}:
                raise RuntimeError("SDK client failed to initialize")
            baseline = sample()
            start = time.perf_counter()
            inside(guest, "install", backend)
            key_path = "/etc/sandcrab/token" if backend == "sandcrab" else "/root/measure.key"
            connection = {"key": docker("exec", guest, "cat", key_path).decode().strip(),
                          "endpoint": "127.0.0.1:" + ("9011" if backend == "sandcrab" else "8090"),
                          "image": "default" if backend == "sandcrab" else "sandcrab-measure-workload:1"}
            report.update(sdk.call("connect", **connection))
            sdk.call("create", ttl=60)
            report["installToFirstCommandMs"] = round(1000*(time.perf_counter()-start), 3)
            sdk.call("close")
            if backend == "sandcrab":
                inside(guest, "tune")
                sdk.call("connect", **connection)
            inside(guest, "idle", backend)
            idle = sample()
            report.update(idleGuestPssBytes=idle["pssBytes"], baseGuestPssBytes=baseline["pssBytes"],
                          idleRuntimePssBytes=idle["pssBytes"]-baseline["pssBytes"],
                          idleCgroupBytes=idle["memoryCurrentBytes"], seedFiles=files, commandsPerSandbox=ops)
            for target in stages:
                row = {"requested": target, "ready": n, "passed": False}
                rows.append(row)
                try:
                    while n < target:
                        record = sdk.call("create", ttl=900)
                        seed = sdk.call("seed", files=files)
                        if report.setdefault("seedDigest", seed["corpusSha256"]) != seed["corpusSha256"]:
                            raise RuntimeError("Seeded fixtures differ")
                        n += 1
                        row["ready"] = n
                        created.append(record["createMs"])
                        first.append(record["createAndFirstCommandMs"])
                        raw({"backend": backend, "stage": target, "index": n, "create": record})
                    time.sleep(.25)
                    resident = sample()
                    row["idlePssPerSandboxBytes"] = (resident["pssBytes"]-idle["pssBytes"])//n
                    row["guestPssBytes"] = resident["pssBytes"]
                    row["chargedBytes"] = resident["memoryCurrentBytes"]
                    if resident["memoryCurrentBytes"] >= MEMORY-128*1024**2:
                        raise RuntimeError("Cgroup reached the fixed measurement reserve")
                    result = sdk.call("exercise", files=files, operations=ops)
                    raw({"backend": backend, "stage": target, "workload": result})
                    samples = [v for box in result["samples"] for values in box.values() for v in values]
                    latencies.extend(samples)
                    row["commandMs"] = summary(samples)
                    row["errors"] = len(result["errors"])
                    row["oomKills"] = sample()["oomKills"] - baseline["oomKills"]
                    row["passed"] = (len(samples) == n*ops and not row["errors"] and
                                     not row["oomKills"] and row["commandMs"]["p95"] <= 1000)
                    if not row["passed"]:
                        report["stop"] = "validated operation, latency or memory target missed"
                        break
                    report["largestPassingStage"] = target
                except (RuntimeError, TimeoutError, OSError, ValueError, KeyError) as failure:
                    row["failure"] = str(failure)[:500]
                    report["stop"] = "stage failed"
                    break
            report.update(createMs=summary(created), createAndFirstCommandMs=summary(first),
                          commandRoundTripMs=summary(latencies))
        finally:
            try:
                if sdk.process.poll() is None:
                    sdk.call("close")
            finally:
                sdk.close()
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--machine", required=True)
    parser.add_argument("--client", required=True)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--images", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--checkpoint", choices=("L2", "L7", "L9"))
    parser.add_argument("--smoke", action="store_true")
    parsed = parser.parse_args()
    if not parsed.smoke and not parsed.checkpoint:
        parser.error("Full measurements require an L2, L7 or L9 checkpoint")
    parsed.output.mkdir(parents=True, exist_ok=False)
    result = {"schema": 1, "checkpoint": parsed.checkpoint, "smoke": parsed.smoke, "trials": [],
              "revision": os.environ.get("GITHUB_SHA") or subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
              "bundleSha256": checksum(parsed.bundle), "imagesTarSha256": checksum(parsed.images),
              "sdkImage": json.loads(docker("image", "inspect", parsed.client))[0]["Id"],
              "machineImage": json.loads(docker("image", "inspect", parsed.machine))[0]["Id"],
              "budgetBytes": MEMORY, "cpuLimit": 2, "upstreamServer": "1.2.1", "passed": False}
    with (parsed.output/"attempts.jsonl").open("x", encoding="utf-8", buffering=1) as stream:
        try:
            for repetition in range(1 if parsed.smoke else 3):
                order = ("sandcrab", "opensandbox") if repetition % 2 == 0 else ("opensandbox", "sandcrab")
                trial = {"order": order, "backends": {}}
                result["trials"].append(trial)
                for backend in order:
                    def raw(entry):
                        stream.write(json.dumps({"repetition": repetition + 1, **entry})+"\n")
                    trial["backends"][backend] = measure(backend, parsed, raw)
                left, right = trial["backends"].values()
                if left["environment"] != right["environment"] or not left.get("seedDigest") or left["seedDigest"] != right.get("seedDigest"):
                    raise RuntimeError("The two measurements used different environments or corpora")
            result["largestPassingStage"] = {name: min(trial["backends"][name]["largestPassingStage"] for trial in result["trials"])
                                               for name in ("sandcrab", "opensandbox")}
            result["passed"] = min(result["largestPassingStage"].values()) >= 1
        finally:
            (parsed.output/"summary.json").write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
    if not result["passed"]:
        raise SystemExit("The comparison did not validate work on both backends")


if __name__ == "__main__":
    main()
