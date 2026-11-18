"""Exercise preflight, failed activation and a successful published-bundle upgrade on systemd."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

from quickstart import README, RELEASE, fresh


UNIT = Path('/etc/systemd/system/sandcrab.service')
SOCKET = '/var/lib/sandcrab/runtime/control.sock'


def run(*args, check=True, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=60, **kwargs)
    if check and result.returncode:
        raise RuntimeError(f'{args[0]} exited {result.returncode}: {result.stderr[-1500:]}')
    return result


def active_version():
    pid = run('systemctl', 'show', '--property=MainPID', '--value', UNIT.name).stdout.strip()
    return pid, run(f'/proc/{int(pid)}/exe', '--version').stdout.strip()


def verify_run():
    exe = RELEASE / 'sandcrab'
    for _ in range(50):
        if run(exe, 'info', '--socket', SOCKET, check=False).returncode == 0:
            break
        time.sleep(.1)
    result = run(exe, 'run', '--socket', SOCKET, '--profile', 'default', '--', 'python3', '-c', 'print(6 * 7)')
    assert json.loads(result.stdout)['result']['stdout'] == '42\n'


def verify(previous, candidate):
    fresh()
    run(sys.executable, '-I', previous)
    original = active_version()
    assert original[1] == 'sandcrab 0.2.0'
    config = Path('/etc/sandcrab/config.toml')
    token = Path('/etc/sandcrab/token')
    settings = config.read_bytes() + b'\n# operator setting\n'
    credential = token.read_bytes()
    exe = RELEASE / 'sandcrab'
    binary = exe.read_bytes()
    config.write_bytes(b'invalid configuration =')
    try:
        assert run(sys.executable, '-I', candidate, '--upgrade', check=False).returncode
        assert active_version() == original and exe.read_bytes() == binary
    finally:
        config.write_bytes(settings)

    previous_unit = UNIT.read_bytes() + b'\n# original unit\n'
    UNIT.write_bytes(previous_unit)
    overrides = UNIT.with_name(UNIT.name + '.d')
    overrides.mkdir()
    guard = overrides / 'upgrade-test.conf'
    guard.write_text("[Service]\nExecStartPre=/bin/sh -c '/var/lib/sandcrab-release/sandcrab --version "
                     "| /usr/bin/grep -qx \"sandcrab 0.2.0\"'\n")
    run('systemctl', 'daemon-reload')
    try:
        assert run(sys.executable, '-I', candidate, '--upgrade', check=False).returncode
        assert active_version()[1] == original[1] and exe.read_bytes() == binary
        assert UNIT.read_bytes() == previous_unit
        assert config.read_bytes() == settings and token.read_bytes() == credential
        verify_run()
    finally:
        guard.unlink()
        overrides.rmdir()
        run('systemctl', 'daemon-reload')

    run(sys.executable, '-I', candidate, '--upgrade')
    assert active_version()[1] == run(exe, '--version').stdout.strip() != original[1]
    assert config.read_bytes() == settings and token.read_bytes() == credential
    verify_run()
    example = re.search(r'<!-- sandcrab-template-example -->\n```sh\n(.+?)\n```', README.read_text(), re.S)
    with tempfile.TemporaryDirectory() as directory:
        result = run('bash', '-euc', example.group(1), cwd=directory,
                     env={**os.environ, 'PATH': str(RELEASE) + ':' + os.defpath, 'SANDCRAB_SOCKET': SOCKET})
        template = json.loads(result.stdout)['id']
        assert re.fullmatch('[0-9a-f]{64}', template)
        run(exe, 'template', 'delete', '--socket', SOCKET, template)
    print('Previous release preserved on preflight failure, restored after activation failure, and upgraded successfully.')


if __name__ == '__main__':
    verify(*map(Path, sys.argv[1:]))
