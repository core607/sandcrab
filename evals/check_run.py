"""Reject invalid paid workflow launches explicitly, before the evaluator job can start."""
import os
from pathlib import Path
import sys


def validate(ref: str, attempt: str):
    if ref != 'refs/heads/main':
        raise ValueError('Paid evaluations require main; no evaluation was run.')
    if attempt != '1':
        raise ValueError('Paid evaluations cannot be rerun. Inspect the earlier ledger, then explicitly start a new run with a fresh budget.')


def main():
    try:
        validate(os.environ.get('GITHUB_REF', ''), os.environ.get('GITHUB_RUN_ATTEMPT', ''))
    except ValueError as error:
        print('::error::' + str(error))
        summary = os.environ.get('GITHUB_STEP_SUMMARY')
        if summary:
            with Path(summary).open('a', encoding='utf-8') as file:
                file.write(str(error) + '\n\nNo model request was sent by this attempt.\n')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
