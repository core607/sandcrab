"""Internal unprivileged runner, invoked by native.py for a disposable fixture only."""
import argparse
from pathlib import Path
import subprocess
import sys

from inspect_ai import eval

from report import write
from sandcrab import sandcrab_native


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--endpoint', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    args = parser.parse_args()
    # The preflight uses no provider, credentials or generated code. Paid runs need a separately
    # validated spend controller; the task's per-sample cost threshold alone can overshoot once.
    task = sandcrab_native(args.endpoint, baseline=True)
    task.metadata['revision'] = args.revision
    logs = eval(task, model='mockllm/model', max_samples=1, log_dir=str(args.output / 'logs'),
                display='plain', log_model_api=False, retry_on_error=0)
    if len(logs) != 1:
        raise RuntimeError('Expected one complete Inspect log')
    result = write(logs[0], args.output)
    subprocess.run([sys.executable, '-m', 'inspect_ai', 'view', 'bundle', '--log-dir', str(args.output / 'logs'),
                    '--output-dir', str(args.output / 'viewer')], check=True)
    attempts = [a for rows in result['cases'].values() for a in rows]
    expected = len(task.dataset) * 3
    if result['status'] != 'success' or len(attempts) != expected or not all(a['passed'] for a in attempts):
        raise SystemExit('Native evaluation preflight failed; all attempts retained')


if __name__ == '__main__':
    main()
