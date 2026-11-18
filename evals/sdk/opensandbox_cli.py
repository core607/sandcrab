"""Check supported osb commands against an installed Sandcrab loopback endpoint."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid


def check(executable, token_file, endpoint, report):
    token = token_file.read_text(encoding="utf-8").strip()
    successes = []
    summary = {"status": "failed", "commands": successes}
    with tempfile.TemporaryDirectory() as home:
        env = {**os.environ, "HOME": home, "XDG_CONFIG_HOME": home,
               "OPEN_SANDBOX_DOMAIN": endpoint, "OPEN_SANDBOX_PROTOCOL": "http",
               "OPEN_SANDBOX_API_KEY": token, "NO_COLOR": "1"}
        def invoke(*args, raw=False):
            command = [str(executable), *args]
            result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=75)
            if result.returncode:
                raise RuntimeError(f"osb {' '.join(args[:2])} exited {result.returncode}: "
                                   + result.stderr.replace(token, "[redacted]")[-1200:])
            return result.stdout if raw else json.loads(result.stdout)

        owned_id = None
        try:
            summary["version"] = invoke("--version", raw=True).strip()
            key = uuid.uuid4().hex
            created = invoke("sandbox", "create", "--image", "default", "--timeout", "60s",
                             "--resource", "cpu=0.25", "--resource", "memory=32Mi",
                             "--metadata", "test=" + key, "-o", "json")
            owned_id = str(uuid.UUID(created["id"]))
            successes.append("sandbox create")
            listed = invoke("sandbox", "list", "--metadata", "test=" + key, "-o", "json")
            assert [entry["id"] for entry in listed["items"]] == [owned_id], listed
            successes.append("sandbox list")
            detail = invoke("sandbox", "get", owned_id, "-o", "json")
            assert detail["id"] == owned_id, detail
            successes.append("sandbox get")
            health = invoke("sandbox", "health", owned_id, "-o", "json")
            assert health["healthy"] is True, health
            successes.append("sandbox health")
            output = invoke("command", "run", owned_id, "-o", "raw", "--",
                            "python3", "-c", "print(6 * 7)", raw=True)
            assert output.strip() == "42", output
            successes.append("command run")
            invoke("file", "write", owned_id, "/workspace/answer.txt", "-c", "42", "-o", "json")
            successes.append("file write")
            assert invoke("file", "cat", owned_id, "/workspace/answer.txt", "-o", "raw", raw=True) == "42"
            successes.append("file cat")
        finally:
            try:
                if owned_id:
                    invoke("sandbox", "kill", owned_id, "-o", "json")
                    successes.append("sandbox kill")
                    after = invoke("sandbox", "list", "--metadata", "test=" + key, "-o", "json")
                    assert all(row["id"] != owned_id for row in after["items"]), after
            finally:
                report.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    summary["status"] = "passed"
    report.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--osb", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--endpoint", default="127.0.0.1:9011")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    check(args.osb, args.token_file, args.endpoint, args.report)
