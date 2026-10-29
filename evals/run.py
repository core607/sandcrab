"""Internal unprivileged runner, invoked by native.py for a disposable fixture only."""
import argparse
from pathlib import Path
import subprocess
import sys

from inspect_ai import eval
from inspect_ai.model import Model, ModelCost

from budget import Ledger, Prices
from model import BoundedDeepSeek
from report import write
from sandcrab import sandcrab_native


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--endpoint', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--mode', choices=['scripted', 'model'], default='scripted')
    parser.add_argument('--suite', choices=['native', 'workspace', 'all'], default='all')
    parser.add_argument('--epochs', type=int, choices=range(1, 6), default=3)
    parser.add_argument('--model', choices=['deepseek-flash'], default='deepseek-flash')
    parser.add_argument('--budget-usd', default='1.00')
    args = parser.parse_args()
    baseline = args.mode == 'scripted'
    task = sandcrab_native(args.endpoint, baseline=baseline, suite=args.suite, artifacts=str(args.output / 'artifacts'))
    task.metadata['revision'] = args.revision
    ledger = None
    costs = None
    selected = 'mockllm/model'
    if not baseline:
        prices = Prices()
        prices.require_current()
        ledger = Ledger(args.output / 'budget.jsonl', args.budget_usd, prices)
        selected = Model(BoundedDeepSeek(args.model, ledger), task.config)
        costs = {str(selected): ModelCost(input=float(prices.input_rate), output=float(prices.output_rate),
                                         input_cache_read=float(prices.input_rate), input_cache_write=float(prices.input_rate))}
        task.metadata['pricing'] = prices.data
        task.metadata['batchBudgetUsd'] = args.budget_usd
    logs = eval(task, model=selected, model_cost_config=costs, epochs=args.epochs, max_samples=1, log_dir=str(args.output / 'logs'),
                display='plain', log_model_api=False, retry_on_error=0)
    if len(logs) != 1:
        raise RuntimeError('Expected one complete Inspect log')
    result = write(logs[0], args.output, ledger.summary() if ledger else None)
    subprocess.run([sys.executable, '-m', 'inspect_ai', 'view', 'bundle', '--log-dir', str(args.output / 'logs'),
                    '--output-dir', str(args.output / 'viewer')], check=True)
    attempts = [a for rows in result['cases'].values() for a in rows]
    expected = len(task.dataset) * args.epochs
    incomplete = (result['status'] != 'success' or len(attempts) != expected
                  or any(a['error'] or a['cleanup'] != 'PASS' for a in attempts)
                  or (ledger is not None and ledger.stopped))
    if incomplete or (baseline and not all(a['passed'] for a in attempts)):
        raise SystemExit('Evaluation incomplete or scripted preflight failed; all attempts retained')


if __name__ == '__main__':
    main()
