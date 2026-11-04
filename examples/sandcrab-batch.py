"""Run each supplied Python file in a separate sandbox and print one result per file."""
import json
import os
from pathlib import Path
import subprocess
import sys


def main(paths):
    if not paths:
        raise SystemExit('Usage: python3 sandcrab-batch.py FILE.py [FILE.py ...]')
    binary = os.environ.get('SANDCRAB_BIN', '/var/lib/sandcrab-release/sandcrab')
    socket = os.environ.get('SANDCRAB_SOCKET', '/var/lib/sandcrab/runtime/control.sock')
    profile = os.environ.get('SANDCRAB_PROFILE', 'default')
    failed = False
    for path in paths:
        run = subprocess.run([binary, 'run', '--socket', socket, '--profile', profile,
                              '--', 'python3', '-c', Path(path).read_text(encoding='utf-8')],
                             stdout=subprocess.PIPE, text=True)
        # A refused or interrupted submission is reported once for this input.
        print(json.dumps({'file': path, 'exitCode': run.returncode,
                          'run': json.loads(run.stdout) if run.stdout.strip() else None}), flush=True)
        failed |= run.returncode != 0
    return int(failed)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
