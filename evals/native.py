#!/usr/bin/env python3
"""Root controller creates a disposable native service; Inspect runs as its ordinary client."""
import argparse
import importlib.util
import os
from pathlib import Path
import pwd
import shutil
import signal
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--python', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('native preflight requires root to create its isolated fixture')
    def interrupted(signum, frame):
        raise KeyboardInterrupt('Native preflight interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    source = Path(__file__).resolve().parent.parent
    output = args.output.resolve()
    output.mkdir(mode=0o755)  # Never overwrite an earlier attempt.
    client = pwd.getpwnam('daemon')
    os.chown(output, client.pw_uid, client.pw_gid)
    spec = importlib.util.spec_from_file_location('native_probe', source / 'executor-service/rust/sandcrab/native_probe.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fixture = module.Probe(args.binary.resolve(), args.tools.resolve(), output / 'fixture.json')
    try:
        fixture.setup()
        fixture.cli_completed_outcome()
        fixture.startup_cancellation()
        fixture.receipt['scope'] = 'Disposable native service for an Inspect scripted preflight; no model or production endpoint'
        revision = subprocess.run(['git', '-c', f'safe.directory={source}', 'rev-parse', 'HEAD'],
                                  cwd=source, check=True, capture_output=True, text=True).stdout.strip()
        client_home = fixture.root / 'client'
        client_home.mkdir(mode=0o750)
        os.chown(client_home, client.pw_uid, client.pw_gid)
        staged = fixture.root / 'evals'
        for origin in (source / 'evals').rglob('*'):
            if origin.is_symlink():
                raise ValueError('Evaluation source must not contain symlinks')
            if not origin.is_file() or origin.suffix not in {'.py', '.yaml'}:
                continue
            target = staged / origin.relative_to(source / 'evals')
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            shutil.copyfile(origin, target)
            target.chmod(0o644)
        # Do not pass root's provider credentials, SSH configuration or environment to Inspect.
        child_env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': str(client_home), 'PYTHONUTF8': '1',
                     'LD_LIBRARY_PATH': str(args.python.resolve().parent.parent / 'lib')}
        # Preserve the venv path: resolving its python symlink selects the base interpreter.
        child = subprocess.Popen([str(args.python.absolute()), str(staged / 'run.py'),
                                  '--endpoint', str(fixture.socket), '--output', str(output), '--revision', revision],
                                 cwd=staged, env=child_env, start_new_session=True,
                                 user=client.pw_uid, group=client.pw_gid, extra_groups=[client.pw_gid])
        try:
            returncode = child.wait(timeout=600)
        finally:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=10)
        fixture.receipt['result'] = 'PASS' if returncode == 0 else 'FAIL'
        if returncode:
            raise SystemExit(returncode)
    except BaseException:
        fixture.receipt['result'] = 'FAIL'
        raise
    finally:
        try:
            fixture.cleanup()
        finally:
            fixture.save()


if __name__ == '__main__':
    main()
