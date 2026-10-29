"""Workspace tasks, reference clients and host-side checks; only task text reaches the model."""
import base64
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile

import yaml

MAX_FILE = 65536
MAX_ARTIFACT = 2 * 1024 * 1024


def path(value):
    return (isinstance(value, str) and 0 < len(value.encode('utf-8')) <= 4096
            and '\\' not in value and not any(ord(c) < 32 or ord(c) == 127 for c in value)
            and len(value.split('/')) <= 64
            and all(p not in ('', '.', '..') and len(p.encode('utf-8')) <= 255 for p in value.split('/')))


def content(value):
    if isinstance(value, str):
        data = value.encode('utf-8')
    elif isinstance(value, dict) and set(value) == {'base64'} and isinstance(value['base64'], str):
        data = base64.b64decode(value['base64'], validate=True)
    else:
        raise ValueError('File content must be text or one base64 field')
    if len(data) > MAX_FILE:
        raise ValueError('Case file exceeds 64 KiB')
    return data


def files(value):
    if not isinstance(value, dict) or len(value) > 16 or any(not path(p) for p in value):
        raise ValueError('Invalid case file map')
    if sum(len(content(v)) for v in value.values()) > 128 * 1024:
        raise ValueError('Case files exceed 128 KiB')


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate JSON field')
            result[key] = value
        return result
    def constant(value):
        raise ValueError('Nonfinite JSON value')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def same_json(actual, expected):
    return json.dumps(actual, sort_keys=True, allow_nan=False) == json.dumps(expected, sort_keys=True, allow_nan=False)


def load(directory: Path):
    result, digest = [], hashlib.sha256()
    for filename in sorted(directory.glob('*.yaml')):
        raw = filename.read_bytes()
        if len(raw) > 32768:
            raise ValueError('Workspace case exceeds 32 KiB')
        case = yaml.safe_load(raw)
        if not isinstance(case, dict) or set(case) != {'id', 'task', 'fixture', 'reference', 'expected'}:
            raise ValueError('Workspace cases require id, task, fixture, reference and expected')
        if not isinstance(case['id'], str) or not re.fullmatch('workspace-[a-z][a-z0-9-]{0,53}', case['id']):
            raise ValueError('Invalid workspace case ID')
        if not isinstance(case['task'], str) or not case['task'].strip():
            raise ValueError('Missing workspace task')
        if not isinstance(case['fixture'], dict) or set(case['fixture']) != {'files'}:
            raise ValueError('Invalid workspace fixture')
        files(case['fixture']['files'])
        reference = case['reference']
        if not isinstance(reference, dict) or set(reference) != {'files', 'check'}:
            raise ValueError('Reference requires files and check commands')
        files(reference['files'])
        if not isinstance(reference['check'], list) or len(reference['check']) > 4 or any(not isinstance(s, str) or '\0' in s or len(s.encode()) > 16384 for s in reference['check']):
            raise ValueError('Invalid reference commands')
        expected = case['expected']
        if not isinstance(expected, dict) or not {'artifacts', 'preserve', 'steps'} <= set(expected) or set(expected) - {'artifacts', 'preserve', 'steps', 'textContains'}:
            raise ValueError('Expected checks require artifacts, preserve and steps')
        for key in ('artifacts', 'preserve'):
            values = expected[key]
            if not isinstance(values, list) or len(values) > 16 or any(not path(p) for p in values) or len(set(values)) != len(values):
                raise ValueError('Invalid artifact path list')
        if not expected['artifacts'] or set(expected['artifacts']) != set(reference['files']):
            raise ValueError('Reference files must match the required artifacts')
        if set(expected['preserve']) - set(case['fixture']['files']):
            raise ValueError('Preserved files must come from the fixture')
        if set(expected['preserve']) & set(expected['artifacts']):
            raise ValueError('Submitted source cannot also be a preserved fixture')
        text_checks = expected.get('textContains', {})
        if not isinstance(text_checks, dict) or set(text_checks) - set(expected['artifacts']):
            raise ValueError('Text checks require a submitted artifact')
        if any(not isinstance(values, list) or not 1 <= len(values) <= 8
               or any(not isinstance(text, str) or not text or len(text) > 256 for text in values)
               for values in text_checks.values()):
            raise ValueError('Invalid artifact text checks')
        if not isinstance(expected['steps'], list) or not 1 <= len(expected['steps']) <= 8:
            raise ValueError('Use one to eight independent check steps')
        for step in expected['steps']:
            if not isinstance(step, dict) or not {'argv', 'stdin', 'stdoutJson'} <= set(step) or set(step) - {'argv', 'stdin', 'stdoutJson', 'files', 'links', 'reset', 'filesJson', 'absentFiles', 'unchangedFiles'}:
                raise ValueError('Unknown workspace check')
            files(step.get('files', {}))
            argv = step['argv']
            if not isinstance(argv, list) or not 2 <= len(argv) <= 8 or argv[0] != 'python3' or any(not isinstance(a, str) or '\0' in a for a in argv):
                raise ValueError('Checks invoke a Python file with bounded arguments')
            if argv[1] not in set(expected['artifacts']) | set(step.get('files', {})):
                raise ValueError('Checks invoke a submitted source or a supplied check driver')
            if not isinstance(step['stdin'], str) or '\0' in step['stdin'] or len(step['stdin'].encode()) > 16384:
                raise ValueError('Invalid check input')
            links = step.get('links', {})
            if not isinstance(links, dict) or len(links) > 16 or any(not path(p) or not isinstance(t, str) or not t or '\0' in t or len(t.encode()) > 4096 for p, t in links.items()):
                raise ValueError('Invalid verification symlinks')
            for key in ('reset', 'absentFiles', 'unchangedFiles'):
                values = step.get(key, [])
                if not isinstance(values, list) or len(values) > 16 or any(not path(p) for p in values):
                    raise ValueError('Invalid check paths')
            if not isinstance(step.get('filesJson', {}), dict) or len(step.get('filesJson', {})) > 16 or any(not path(p) for p in step.get('filesJson', {})):
                raise ValueError('Invalid file JSON checks')
            if any(p == a or a.startswith(p + '/') for p in step.get('reset', []) for a in expected['artifacts']):
                raise ValueError('Checks must not remove submitted artifacts')
            if any(p == a or a.startswith(p + '/') for p in set(step.get('files', {})) | set(links) for a in expected['artifacts']):
                raise ValueError('Checks must not replace submitted artifacts')
        json.dumps(case, allow_nan=False)
        result.append(case)
        digest.update(filename.name.encode() + b'\0' + raw + b'\0')
    if not result or len({c['id'] for c in result}) != len(result):
        raise ValueError('Workspace cases must be nonempty and unique')
    return result, digest.hexdigest()


def submitted(raw: bytes, case: dict) -> dict[str, bytes]:
    """Read selected regular files without extracting or executing archive content on the host."""
    if len(raw) > MAX_ARTIFACT:
        raise ValueError('Artifact exceeds 2 MiB')
    wanted = set(case['expected']['artifacts']) | set(case['expected']['preserve'])
    entries, found = set(), {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            name = member.name.rstrip('/')
            if not path(name) or name in entries or len(entries) >= 128:
                raise ValueError('Invalid or excessive artifact entries')
            entries.add(name)
            if name in wanted:
                if not member.isfile() or member.issparse() or member.size > MAX_FILE:
                    raise ValueError('Submitted source must be a bounded regular file')
                data = archive.extractfile(member).read(MAX_FILE + 1)
                if len(data) != member.size:
                    raise ValueError('Incomplete artifact entry')
                found[name] = data
    if set(found) != wanted:
        raise ValueError('Required artifact or preserved input is missing')
    for name in case['expected']['preserve']:
        if found[name] != content(case['fixture']['files'][name]):
            raise ValueError('Preserved input changed: ' + name)
    for name, snippets in case['expected'].get('textContains', {}).items():
        text = found[name].decode('utf-8')
        if any(snippet not in text for snippet in snippets):
            raise ValueError('Required artifact text is missing: ' + name)
    return {name: found[name] for name in case['expected']['artifacts']}
