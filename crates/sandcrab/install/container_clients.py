"""Exercise the published socket layout from an unprivileged application container."""
import argparse
import json
from pathlib import Path
import time
import uuid

from probe import disposable_machine, run


def wait_ready(daemon):
    until = time.monotonic() + 45
    while True:
        logs = run(["docker", "logs", daemon])
        if '{"ready":true,' in logs.stdout:
            return
        state = run(["docker", "inspect", "--format", "{{.State.Running}}", daemon]).stdout.strip()
        if state != "true" or time.monotonic() >= until:
            raise RuntimeError("Daemon failed to start: " + logs.stderr[-1000:])
        time.sleep(0.1)


def exercise(image, network, checks):
    volume = "sandcrab-client-" + uuid.uuid4().hex
    label = "sandcrab.socket-probe"
    run(["docker", "volume", "create", "--label", label + "=" + volume, volume])
    try:
        with disposable_machine(image, checks.append, systemd=False, network=network, client_volume=volume) as daemon:
            wait_ready(daemon)
            def client(*args, user="14001:14001", check=True):
                return run([
                    "docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL",
                    "--security-opt=no-new-privileges", "--user", user,
                    "--mount", f"type=volume,source={volume},target=/run/sandcrab,readonly",
                    "-e", "SANDCRAB_SOCKET=/run/sandcrab/control.sock",
                    "--entrypoint", "/opt/sandcrab/sandcrab", image, *args,
                ], check=check)

            info = json.loads(client("info").stdout)
            assert info["profiles"]["default"]["network"] == "none"
            assert info["limits"]["maxSandboxes"] == 6, info["limits"]
            rejected = client("info", user="14002:14001", check=False)
            assert rejected.returncode and "PEER_REJECTED" in rejected.stderr, rejected
            result = json.loads(client("run", "--", "python3", "-c", "print(42)").stdout)
            assert result["state"] == "succeeded" and result["result"]["stdout"] == "42\n", result
            checks.append("isolated application checks the peer and runs with daemon network=" + network)
            if network == "bridge":
                install = (
                    "python3 -m pip --disable-pip-version-check install --retries 1 --timeout 8 "
                    "--no-input --no-cache-dir --no-deps --index-url https://pypi.org/simple "
                    "--target /workspace/site idna==3.10 >/dev/null && "
                    "PYTHONPATH=/workspace/site python3 -c 'import idna; print(idna.__version__)'"
                )
                result = json.loads(client("run", "--profile", "packages", "--", "bash", "-c", install, check=False).stdout)
                assert result["state"] == "succeeded" and result["result"]["stdout"] == "3.10\n", result
                denied = (
                    "import urllib.request, urllib.error\n"
                    "try: urllib.request.urlopen('https://example.org/', timeout=5)\n"
                    "except urllib.error.URLError as error: print(error.reason)\n"
                )
                result = json.loads(client("run", "--profile", "packages", "--", "python3", "-c", denied).stdout)
                assert result["state"] == "succeeded" and "403" in result["result"]["stdout"], result
                checks.append("package profile installs and imports an approved package and refuses an unlisted host")
    finally:
        details = json.loads(run(["docker", "volume", "inspect", volume]).stdout)
        if details[0]["Labels"].get(label) != volume:
            raise RuntimeError("Socket fixture ownership changed")
        run(["docker", "volume", "rm", volume])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    receipt = {"status": "failed", "checks": []}
    try:
        for mode in ("none", "bridge"):
            exercise(args.image, mode, receipt["checks"])
        receipt["status"] = "passed"
    finally:
        args.report.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
