"""Run the same six tools through the installed Python, Node and MCP interfaces."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import uuid


def cases(call, seed=None):
    executed = call('exec', {'command': 'printf 42'})
    assert executed['ok'] and executed['freshShell'] and executed['stdout'] == '42', executed
    failed = call('exec', {'command': 'false'})
    assert not failed['ok'] and failed['exitCode'] == 1 and failed['freshShell'] == (seed is not None), failed
    if seed is not None:
        initial = call('read_file', {'path': 'seed'})
        assert initial['ok'] and initial['content'] == seed, initial
        assert call('exec', {'command': 'mkdir child && cd child && export CHILD_STATE=changed'})['ok']
        fresh = call('exec', {'command': 'printf "%s:%s" "$PWD" "${CHILD_STATE:-reset}"'})
        assert fresh['freshShell'] and fresh['stdout'] == '/workspace:reset', fresh
    original = 'one\r\nneedle\nthree\n'
    path = 'notes/work.txt'
    receipt = call('write_file', {'path': path, 'content': original})
    version = hashlib.sha256(original.encode()).hexdigest()
    assert receipt['ok'] and receipt['version'] == version, receipt
    read = call('read_file', {'path': path, 'offset': 2, 'limit': 1})
    assert read == {'ok': True, 'content': 'needle', 'encoding': 'utf-8', 'version': version, 'truncated': False}, read
    binary = call('read_file', {'path': path, 'byteStart': 0, 'byteEnd': 2})
    assert binary['content'] == 'b25l' and binary['version'] == version, binary
    edit = {'path': path, 'version': version, 'old': 'needle', 'new': 'changed'}
    assert call('edit_file', edit) == {'ok': True, 'replacedCount': 1}
    assert call('edit_file', edit) == {'ok': False, 'code': 'EDIT_CONFLICT'}
    assert call('write_file', {'path': 'log', 'content': 'first\nsecond\n'})['ok']
    selection = call('read_file', {'path': 'log', 'offset': 2, 'limit': 1})
    assert selection['ok'] and selection['content'] == 'second', selection
    appended = call('exec', {'command': "echo third >> log"})
    assert appended['ok'], appended
    stale = call('edit_file', {'path': 'log', 'version': selection['version'], 'old': 'first', 'new': 'lost'})
    assert stale == {'ok': False, 'code': 'EDIT_CONFLICT'}, stale
    retained = call('read_file', {'path': 'log'})
    assert retained['ok'] and retained['content'].splitlines() == ['first', 'second', 'third'], retained
    listed = call('list_dir', {'path': 'notes'})
    assert listed['ok'] and [row['path'] for row in listed['entries']] == [path], listed
    found = call('search', {'pattern': '*.txt', 'contains': 'changed'})
    assert found['ok'] and [row['path'] for row in found['entries']] == [path], found
    assert call('read_file', {'path': '../outside'}) == {'ok': False, 'code': 'INVALID_ARGUMENTS'}
    assert call('write_file', {'path': 'large', 'content': 'x' * 20000})['ok']
    clipped = call('read_file', {'path': 'large'})
    assert clipped['ok'] and clipped['truncated'] and clipped['content'].endswith('[truncated]'), clipped.keys()


def check(directory, language, *, mcp=False):
    root = Path(__file__).resolve().parent
    key = 'sdk-check-' + uuid.uuid4().hex
    if mcp:
        command = [directory / '.venv/bin/sandcrab-mcp', '--workspace', key, '--profile', 'default']
    elif language == 'python':
        command = [directory / '.venv/bin/python', '-u', root / 'workspace_client.py', key]
    else:
        script = directory / 'workspace_client.mjs'
        shutil.copyfile(root / script.name, script)
        command = ['node', script, key]
    if not mcp:
        archive = directory / 'seed.tar'
        with tarfile.open(archive, 'w') as output:
            entry = tarfile.TarInfo('seed')
            entry.size = len(key)
            output.addfile(entry, io.BytesIO(key.encode()))
        command.append(str(archive))
    env = {'SANDCRAB_ENDPOINT': 'http://127.0.0.1:9011',
           'SANDCRAB_TOKEN_FILE': '/etc/sandcrab-client/token', **os.environ}
    process = subprocess.Popen(command, cwd=directory, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               text=True, encoding='utf-8')
    def send(data):
        process.stdin.write(json.dumps(data) + '\n')
        process.stdin.flush()
        line = process.stdout.readline()
        if not line:
            raise RuntimeError(f'{language} workspace client exited during the request')
        return json.loads(line)
    sequence = 0
    def rpc(method, params):
        nonlocal sequence
        sequence += 1
        return send({'jsonrpc': '2.0', 'id': sequence, 'method': method, 'params': params})['result']
    try:
        if mcp:
            rpc('initialize', {'protocolVersion': '2025-03-26', 'capabilities': {}, 'clientInfo': {'name':'check','version':'1'}})
            schemas = rpc('tools/list', {})['tools']
            def call(name, args):
                reply = rpc('tools/call', {'name': name, 'arguments': args})
                value = json.loads(reply['content'][0]['text'])
                assert reply['isError'] == (not value['ok'])
                return value
        else:
            schemas = json.loads(process.stdout.readline())
            def call(name, args):
                return send({'name': name, 'arguments': args})
        assert {s['name'] for s in schemas} == {'exec','read_file','write_file','edit_file','list_dir','search'}
        cases(call, None if mcp else key)
        if not mcp:
            data = base64.b64decode(send({'name': 'checkpoint'}), validate=True)
            with tarfile.open(fileobj=io.BytesIO(data)) as delta:
                assert delta.extractfile('notes/work.txt').read() == b'one\r\nchanged\nthree\n'
                assert 'seed' not in delta.getnames()
            assert send({'name': 'dispose'}) is True
    finally:
        process.stdin.close()
        try:
            status = process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise
        if mcp:
            subprocess.run([directory / '.venv/bin/python', '-c',
                            'import sys\nfrom sandcrab import open_workspace_tools\n'
                            'with open_workspace_tools(sys.argv[1]) as tools: tools.dispose()', key],
                           cwd=directory, env=env, timeout=90, check=True)
    if status:
        raise RuntimeError(f'{language} workspace client exited with {status}')
    print(('MCP' if mcp else language) + ' workspace tools passed')
