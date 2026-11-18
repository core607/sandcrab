"""Installation, cgroup and process measurements inside one disposable systemd guest."""
import json
from http.client import HTTPConnection
import os
from pathlib import Path
import platform
import re
import secrets
import socket
import subprocess
import sys
import time
import urllib.request


def run(*args):
    subprocess.run(args, check=True, stdout=sys.stderr, stderr=sys.stderr)


def install(backend):
    if backend == "sandcrab":
        run("python3", "-I", "/root/sandcrab.zip")
        return
    if backend != "opensandbox":
        raise ValueError("Unknown backend")
    run("python3", "-m", "venv", "/opt/server")
    run("/opt/server/bin/pip", "install", "--disable-pip-version-check", "--no-index",
        "--find-links", "/opt/wheels", "opensandbox-server==1.2.1")
    run("systemctl", "unmask", "docker.service", "docker.socket", "containerd.service")
    run("systemctl", "start", "docker.service")
    run("docker", "load", "-i", "/root/images.tar")
    key = secrets.token_hex(32)
    os.umask(0o077)
    Path("/root/measure.key").write_text(key)
    config = Path("/root/opensandbox.toml")
    config.write_text(
        f'[server]\nhost="127.0.0.1"\nport=8090\napi_key="{key}"\n'
        '[runtime]\ntype="docker"\nexecd_image="sandcrab-measure-execd:1.2.1"\n'
        '[docker]\nnetwork_mode="bridge"\nhost_ip="127.0.0.1"\npublish_host="127.0.0.1"\n'
        '[proxy]\nresolve_internal=false\n[ingress]\nmode="direct"\n')
    run("systemd-run", "--unit=opensandbox-benchmark", "/opt/server/bin/opensandbox-server",
        "--config", str(config))
    until = time.monotonic() + 60
    while time.monotonic() < until:
        try:
            request = urllib.request.Request("http://127.0.0.1:8090/v1/sandboxes", headers={"OPEN-SANDBOX-API-KEY": key})
            with urllib.request.urlopen(request, timeout=2) as reply:
                if reply.status == 200:
                    return
        except OSError:
            time.sleep(.15)
    raise RuntimeError("Upstream server did not become ready")


def tune():
    config = Path("/etc/sandcrab/config.toml")
    text = config.read_text()
    for key, value in (("max_sandboxes", 128), ("max_records", 512), ("session_ttl_millis", 900000)):
        text, count = re.subn(r"(?m)^" + key + r"\s*=\s*\d+$", f"{key} = {value}", text)
        if not count:
            raise RuntimeError("Missing benchmark setting " + key)
    config.write_text(text)
    # The common outer cgroup owns CPU, memory, swap and task limits for both backends.
    run("systemctl", "set-property", "--runtime", "sandcrab.slice", "MemoryMax=infinity", "TasksMax=infinity")
    run("systemctl", "restart", "sandcrab.service")
    until = time.monotonic() + 30
    while time.monotonic() < until:
        ready = subprocess.run(["/var/lib/sandcrab-release/sandcrab", "info", "--socket",
                                "/var/lib/sandcrab/runtime/control.sock"], capture_output=True)
        if ready.returncode == 0:
            return
        time.sleep(.1)
    raise RuntimeError("Tuned Sandcrab fixture did not become ready")


def read_fields(file):
    return {key: int(value) for key, value in (line.split() for line in file.read_text().splitlines())}


def verify_idle(backend):
    def native(route):
        connection = HTTPConnection("localhost", timeout=3)
        connection.sock = socket.socket(socket.AF_UNIX)
        try:
            connection.sock.connect("/var/lib/sandcrab/runtime/control.sock")
            connection.request("GET", route)
            response = connection.getresponse()
            if response.status != 200:
                raise RuntimeError("Native inventory unavailable")
            return json.loads(response.read())
        finally:
            connection.close()
    until = time.monotonic() + 30
    while time.monotonic() < until:
        if backend == "sandcrab":
            idle = all(native("/v1/sessions/" + identifier)["state"] in ("closed", "failed", "expired")
                       for identifier in native("/v1/sessions")["ids"])
        else:
            idle = not subprocess.check_output(["docker", "ps", "-q"]).strip()
        if idle:
            return
        time.sleep(.1)
    raise RuntimeError("Runtime still has live work before idle sampling")


def sample():
    group = Path("/sys/fs/cgroup")
    mem = read_fields(group / "memory.stat")
    events = read_fields(group / "memory.events")
    pss = rss = processes = 0
    for process in Path("/proc").glob("[0-9]*"):
        if int(process.name) == os.getpid():
            continue
        try:
            lines = (process / "smaps_rollup").read_text().splitlines()
        except (FileNotFoundError, ProcessLookupError):
            continue
        values = {line.split(':')[0]: int(line.split()[1]) * 1024 for line in lines if line.startswith(("Pss:", "Rss:"))}
        pss += values.get("Pss", 0)
        rss += values.get("Rss", 0)
        processes += 1
    return {"pssBytes": pss, "rssBytes": rss, "processes": processes,
            "memoryCurrentBytes": int((group / "memory.current").read_text()), "oomKills": events["oom_kill"],
            "memoryStat": {key: mem[key] for key in ("anon", "file", "kernel", "inactive_file")},
            "pids": int((group / "pids.current").read_text())}


def host():
    group = Path("/sys/fs/cgroup")
    try:
        fd = os.open("/dev/kvm", os.O_RDWR)
    except OSError as exc:
        kvm = {"open": False, "errno": exc.errno}
    else:
        os.close(fd)
        kvm = {"open": True}
    return {"kernel": platform.release(), "architecture": platform.machine(), "kvm": kvm,
            "memoryMax": (group / "memory.max").read_text().strip(),
            "swapMax": (group / "memory.swap.max").read_text().strip(), "cpuMax": (group / "cpu.max").read_text().strip(),
            "pidsMax": (group / "pids.max").read_text().strip()}


if __name__ == "__main__":
    if not Path("/.dockerenv").is_file() or not os.environ.get("SANDCRAB_COMPARISON_FIXTURE"):
        raise SystemExit("Run through the disposable comparison controller")
    op = sys.argv[1]
    if op == "install":
        install(sys.argv[2])
    elif op == "tune":
        tune()
    elif op == "sample":
        print(json.dumps(sample()))
    elif op == "host":
        print(json.dumps(host()))
    elif op == "idle":
        verify_idle(sys.argv[2])
    else:
        raise ValueError("Unknown action")
