"""Small, strict case vocabulary shared by the native task and its scripted baseline."""
import hashlib
import json
from pathlib import Path
import re

import yaml


def load(directory: Path) -> tuple[list[dict], str]:
    cases = []
    digest = hashlib.sha256()
    for path in sorted(directory.glob('*.yaml')):
        raw = path.read_bytes()
        if len(raw) > 16384:
            raise ValueError(f'{path.name}: case exceeds 16 KiB')
        value = yaml.safe_load(raw)
        if not isinstance(value, dict) or set(value) != {'id', 'task', 'fixture', 'expected'}:
            raise ValueError(f'{path.name}: expected id, task, fixture and expected')
        if not isinstance(value['id'], str) or not re.fullmatch('[a-z][a-z0-9-]{0,63}', value['id']):
            raise ValueError(f'{path.name}: invalid id')
        if not isinstance(value['task'], str) or not value['task'].strip():
            raise ValueError(f'{path.name}: missing task')
        fixture, expected = value['fixture'], value['expected']
        if not isinstance(fixture, dict) or set(fixture) - {'command', 'timeoutMillis', 'outputLimitBytes', 'exercise'}:
            raise ValueError(f'{path.name}: invalid fixture fields')
        command = fixture.get('command')
        if not isinstance(command, list) or not 1 <= len(command) <= 128 or any(not isinstance(s, str) for s in command):
            raise ValueError(f'{path.name}: command must be an argv list')
        if fixture.get('exercise', 'run') not in {'run', 'cancel', 'replay', 'profile-recovery', 'forget'}:
            raise ValueError(f'{path.name}: unknown exercise')
        for key in ['timeoutMillis', 'outputLimitBytes']:
            if key in fixture and (type(fixture[key]) is not int or not 1 <= fixture[key] <= 10000):
                raise ValueError(f'{path.name}: invalid {key}')
        if not isinstance(expected, dict) or set(expected) - {'state', 'stdout', 'stderr', 'exitCode', 'truncated', 'errors', 'refusalBeforeRun', 'forgotten', 'replay'}:
            raise ValueError(f'{path.name}: unknown expected-state check')
        if expected.get('state') not in {'succeeded', 'failed', 'cancelled', 'timed_out', 'output_limit', 'resource_limit'}:
            raise ValueError(f'{path.name}: terminal state is required')
        if any(not isinstance(expected[k], str) for k in ['stdout', 'stderr'] if k in expected):
            raise ValueError(f'{path.name}: output checks must be strings')
        if 'exitCode' in expected and type(expected['exitCode']) is not int:
            raise ValueError(f'{path.name}: exitCode must be an integer')
        if any(type(expected[k]) is not bool for k in ['truncated', 'forgotten', 'replay'] if k in expected):
            raise ValueError(f'{path.name}: expected boolean check')
        if 'errors' in expected and (not isinstance(expected['errors'], list) or any(not isinstance(s, str) for s in expected['errors'])):
            raise ValueError(f'{path.name}: errors must be a list of codes')
        if 'refusalBeforeRun' in expected and not isinstance(expected['refusalBeforeRun'], str):
            raise ValueError(f'{path.name}: refusalBeforeRun must be an error code')
        digest.update(path.name.encode() + b'\0' + raw + b'\0')
        cases.append(value)
    if not cases or len({c['id'] for c in cases}) != len(cases):
        raise ValueError('Cases must be nonempty and have unique IDs')
    # YAML aliases must not smuggle non-JSON values into Inspect metadata or expected state.
    json.dumps(cases, allow_nan=False)
    return cases, digest.hexdigest()
