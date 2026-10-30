#!/usr/bin/env python3
"""Exercise the published OpenSandbox Python SDK against an actual service."""
import argparse
import asyncio
from datetime import timedelta
import importlib.metadata
import io
import json
from pathlib import Path
import sys

from opensandbox import Sandbox
from opensandbox.config import ConnectionConfig
from opensandbox.exceptions import SandboxApiException
from opensandbox.manager import SandboxManager
from opensandbox.models.execd import RunCommandOpts
from opensandbox.models.sandboxes import SandboxFilter
from opensandbox.models.filesystem import ContentReplaceEntry, DirectoryListEntry, MoveEntry, SearchEntry, SetPermissionEntry, WriteEntry


def output(execution, stream='stdout'):
    return ''.join(item.text for item in getattr(execution.logs, stream))


async def files(sandbox, commands, checks):
    data = bytes(range(256)) * 513
    await sandbox.files.write_files([
        WriteEntry(path='/workspace/文件; name=odd.bin', data=data, mode=640),
        WriteEntry(path='/workspace/empty', data=b''),
        WriteEntry(path='/workspace/text', data='hello 世界\n')])
    assert await sandbox.files.read_bytes('/workspace/文件; name=odd.bin') == data
    assert await sandbox.files.read_bytes('/workspace/empty') == b''
    assert await sandbox.files.read_file('/workspace/text') == 'hello 世界\n'
    stream = await sandbox.files.read_bytes_stream('/workspace/文件; name=odd.bin', chunk_size=8191)
    assert b''.join([chunk async for chunk in stream]) == data
    await sandbox.files.write_file('/workspace/文件; name=odd.bin', io.BytesIO(data[::-1]), mode=600)
    assert await sandbox.files.read_bytes('/workspace/文件; name=odd.bin') == data[::-1]
    execution = await sandbox.commands.run(['python3', '-c',
        "from pathlib import Path; import stat; p=Path('/workspace/文件; name=odd.bin'); "
        "assert p.read_bytes()==(bytes(range(256))*513)[::-1]; "
        "assert stat.S_IMODE(p.stat().st_mode)==0o600; print('files verified')"])
    commands.append(execution.id)
    assert execution.exit_code == 0 and output(execution) == 'files verified\n'
    checks.append('chunked-multipart-binary-text-empty-stream-and-replacement-mode')


async def replacements(sandbox, checks):
    data = b'A' * 32767 + b'abcabc\xff\0'
    await sandbox.files.write_file('project/replace.bin', data, mode=640)
    result = await sandbox.files.replace_contents_detailed([
        ContentReplaceEntry(path='project/replace.bin', old_content='abc', new_content='x')])
    assert len(result) == 1 and result[0].path == 'project/replace.bin' and result[0].replaced_count == 2
    assert await sandbox.files.read_bytes('project/replace.bin') == b'A' * 32767 + b'xx\xff\0'
    result = await sandbox.files.replace_contents_detailed([
        ContentReplaceEntry(path='project/replace.bin', old_content='missing', new_content='unused')])
    assert result[0].replaced_count == 0
    await sandbox.files.replace_contents([
        ContentReplaceEntry(path='project/replace.bin', old_content='x', new_content='X')])
    assert await sandbox.files.read_bytes('project/replace.bin') == b'A' * 32767 + b'XX\xff\0'
    assert (await sandbox.files.get_file_info(['project/replace.bin']))['project/replace.bin'].mode == 640
    checks.append('streamed-literal-replacement-counts-binary-preservation-and-mode')


async def searches(sandbox, checks):
    await sandbox.files.create_directories([WriteEntry(path='project/src/nested')])
    await sandbox.files.write_files([WriteEntry(path=path, data='source') for path in
        ['project/src/中.rs', 'project/src/a.py', 'project/src/nested/deep.rs']])
    matches = await sandbox.files.search(SearchEntry(path='project', pattern='*.rs'))
    assert [item.path for item in matches] == ['/workspace/project/src/nested/deep.rs', '/workspace/project/src/中.rs']
    matches = await sandbox.files.search(SearchEntry(path='project', pattern='?.rs'))
    assert [item.path for item in matches] == ['/workspace/project/src/中.rs']
    matches = await sandbox.files.search(SearchEntry(path='project', pattern='{*.rs,*.py}'))
    assert len(matches) == 3
    assert await sandbox.files.search(SearchEntry(path='project', pattern='src/*.rs')) == []
    matches = await sandbox.files.search(SearchEntry(path='project', pattern='!(main.txt)'))
    assert len(matches) == 6 and all(not item.path.endswith('/main.txt') for item in matches)
    assert next(item for item in matches if item.path.endswith('/link')).entry_type == 'symlink'
    checks.append('recursive-basename-globs-unicode-alternatives-and-link-boundaries')


async def downloads(sandbox, checks):
    data = bytes(range(16))
    await sandbox.files.write_file('project/range.bin', data)
    for header, expected in [('bytes=0-0', data[:1]), ('bytes=3-7', data[3:8]),
                             ('bytes=12-', data[12:]), ('bytes=-4', data[-4:]), ('bytes=3-999', data[3:])]:
        assert await sandbox.files.read_bytes('project/range.bin', range_header=header) == expected
    stream = await sandbox.files.read_bytes_stream('project/range.bin', range_header='bytes=2-5', chunk_size=2)
    assert b''.join([chunk async for chunk in stream]) == data[2:6]
    await sandbox.files.write_file('project/lines.log', b'one\r\n\r\nthree\r\nfour\rlast\n')
    assert await sandbox.files.read_file('project/lines.log', offset=2, limit=2) == '\nthree'
    assert await sandbox.files.read_file('project/lines.log', limit=2) == 'one\n'
    assert await sandbox.files.read_file('project/lines.log', offset=4) == 'four\rlast'
    assert await sandbox.files.read_file('project/lines.log', offset=99) == ''
    try:
        await sandbox.files.read_bytes('/workspace/empty', range_header='bytes=0-0')
    except SandboxApiException as error:
        assert error.status_code == 416
    else:
        raise AssertionError('Empty file accepted a byte range')
    checks.append('byte-range-prefix-suffix-streams-and-normalized-line-selection')


async def directories(sandbox, commands, checks):
    await sandbox.files.create_directories([
        WriteEntry(path='/workspace/project/src', mode=700), WriteEntry(path='project', mode=750)])
    await sandbox.files.write_files([WriteEntry(path='project/src/main.txt', data='original', mode=600),
                                     WriteEntry(path='project/keep', data='keep')])
    info = await sandbox.files.get_file_info(['project', '/workspace/project/src', 'project/src/main.txt'])
    assert info['project'].path == '/workspace/project' and info['project'].mode == 750
    assert info['project'].size == 0 and info['project'].entry_type == 'directory'
    assert info['/workspace/project/src'].mode == 700 and info['project/src/main.txt'].size == 8
    listing = await sandbox.files.list_directory(DirectoryListEntry(path='/workspace/project', depth=2))
    assert [item.path for item in listing] == ['/workspace/project/keep', '/workspace/project/src',
                                              '/workspace/project/src/main.txt']
    assert await sandbox.files.list_directory(DirectoryListEntry(path='project', depth=0)) == []
    execution = await sandbox.commands.run('ln -s /etc /workspace/project/link')
    commands.append(execution.id)
    assert execution.exit_code == 0
    listing = await sandbox.files.list_directory(DirectoryListEntry(path='project', depth=5))
    assert next(item for item in listing if item.path.endswith('/link')).entry_type == 'symlink'
    assert len(listing) == 4
    await replacements(sandbox, checks)
    await searches(sandbox, checks)
    await downloads(sandbox, checks)
    await sandbox.files.set_permissions([SetPermissionEntry(path='project/src/main.txt', mode=640)])
    await sandbox.files.move_files([MoveEntry(src='project/src', dest='project/renamed')])
    await sandbox.files.move_files([MoveEntry(src='project/renamed/main.txt', dest='project/renamed/run.txt')])
    execution = await sandbox.commands.run(['python3', '-c',
        "from pathlib import Path; import os,stat; p=Path('project/renamed/run.txt'); "
        "assert p.read_text()=='original'; assert stat.S_IMODE(p.stat().st_mode)==0o640; "
        "assert p.stat().st_uid==os.getuid(); print('metadata verified')"])
    commands.append(execution.id)
    assert execution.exit_code == 0 and output(execution) == 'metadata verified\n'
    await sandbox.files.delete_files(['project/keep', 'project/link'])
    await sandbox.files.delete_directories(['project'])
    execution = await sandbox.commands.run('test ! -e /workspace/project && test -f /workspace/text')
    commands.append(execution.id)
    assert execution.exit_code == 0
    checks.append('directory-creation-metadata-depth-links-mode-move-and-recursive-deletion')


async def exercise(args):
    assert importlib.metadata.version('opensandbox') == '1.1.0'
    token = args.token_file.read_text().strip()
    config = ConnectionConfig(domain=args.endpoint, protocol='http', api_key=token,
                              request_timeout=timedelta(seconds=15))
    checks, commands, identities = [], [], []
    manager = await SandboxManager.create(connection_config=config)
    sandbox = None
    expired = False
    try:
        metadata = {'name': 'SDK proof 汉字 & +', 'client': 'python'}
        sandbox = await Sandbox.create(args.profile, connection_config=config,
                                       timeout=timedelta(seconds=60),
                                       resource={'cpu': '0.25', 'memory': '32Mi'},
                                       env={'SDK_VALUE': "base ' quoted"}, metadata=metadata)
        identities.append(sandbox.id)
        if args.barrier:
            print(json.dumps({'created': sandbox.id}), flush=True)
            assert sys.stdin.readline().strip() == 'continue'
        info = await sandbox.get_info()
        assert info.id == sandbox.id and info.status.state == 'Running'
        assert info.metadata == metadata
        assert await sandbox.is_healthy()
        endpoint = await sandbox.get_endpoint(44772)
        assert endpoint.endpoint == args.endpoint + '/opensandbox/' + sandbox.id
        assert len(endpoint.headers['X-EXECD-ACCESS-TOKEN']) == 64
        assert endpoint.headers['X-EXECD-ACCESS-TOKEN'] != token
        policy = await sandbox.get_egress_policy()
        assert policy.default_action == 'deny' and policy.egress == []
        page = await manager.list_sandbox_infos(SandboxFilter(states=['Running'], metadata=metadata,
                                                             page=1, page_size=5))
        assert [item.id for item in page.sandbox_infos] == [sandbox.id]
        assert page.pagination.total_items == 1
        checks.append('create-discover-filter-and-scope-endpoint-credentials')

        execution = await sandbox.commands.run(['python3', '-c',
            "import os,sys; print(os.environ['SDK_VALUE']); print(os.environ['SDK_OVERRIDE']); sys.stderr.write('diagnostic\\n')"],
            opts=RunCommandOpts(envs={'SDK_OVERRIDE': 'per-command'}))
        commands.append(execution.id)
        assert execution.complete is not None and execution.exit_code == 0
        assert output(execution) == "base ' quoted\nper-command\n"
        assert output(execution, 'stderr') == 'diagnostic\n'
        status = await sandbox.commands.get_command_status(execution.id)
        assert status.id == execution.id and not status.running and status.exit_code == 0
        checks.append('foreground-argv-environment-output-and-retained-status')

        execution = await sandbox.commands.run(['python3', '-c',
            "import sys; sys.stdout.buffer.write(b'A'*4095+'中'.encode()+b'\\xffX')"])
        commands.append(execution.id)
        assert execution.exit_code == 0 and output(execution) == 'A' * 4095 + '中\ufffdX'
        literal = "a'; touch /tmp/sdk-escape; ' $(uname) &"
        execution = await sandbox.commands.run(['printf', '%s', literal])
        commands.append(execution.id)
        assert execution.exit_code == 0 and output(execution) == literal
        execution = await sandbox.commands.run('test ! -e /tmp/sdk-escape; printf failed; exit 7')
        commands.append(execution.id)
        assert execution.complete is not None and execution.exit_code == 7 and execution.error is not None
        assert output(execution) == 'failed'
        checks.append('split-unicode-invalid-bytes-literal-arguments-and-failed-exit')

        execution = await sandbox.commands.run('mkdir -p /workspace/dir; cd /workspace/dir; export SDK_CHILD=temporary')
        commands.append(execution.id)
        assert execution.exit_code == 0
        execution = await sandbox.commands.run('pwd; test -z "${SDK_CHILD:-}"')
        commands.append(execution.id)
        assert execution.exit_code == 0 and output(execution) == '/workspace\n'
        for index in range(16):
            execution = await sandbox.commands.run(['printf', '%s', str(index)])
            commands.append(execution.id)
            assert execution.complete is not None and execution.exit_code == 0 and output(execution) == str(index)
        checks.append('independent-commands-and-bounded-native-result-reclamation')

        try:
            await sandbox.commands.run('touch /workspace/forbidden-background', opts=RunCommandOpts(background=True))
        except SandboxApiException as error:
            assert error.status_code == 400
        else:
            raise AssertionError('Unsupported background request was accepted')
        execution = await sandbox.commands.run('test ! -e /workspace/forbidden-background')
        commands.append(execution.id)
        assert execution.exit_code == 0
        checks.append('unsupported-execution-option-refuses-without-side-effects')
        await files(sandbox, commands, checks)
        await directories(sandbox, commands, checks)

        before = (await sandbox.get_info()).expires_at
        await sandbox.renew(timedelta(seconds=90))
        assert (await sandbox.get_info()).expires_at > before
        await sandbox.kill()
        expired = True
        try:
            await manager.get_sandbox_info(sandbox.id)
        except SandboxApiException as error:
            assert error.status_code == 404
        else:
            raise AssertionError('Deleted sandbox remains available')
        checks.append('renew-and-explicit-delete')
    finally:
        if sandbox is not None:
            try:
                if not expired:
                    await sandbox.kill()
            finally:
                await sandbox.close()
        await manager.close()
    return {'result': 'PASS', 'client': 'python', 'sdkVersion': importlib.metadata.version('opensandbox'),
            'checks': checks, 'sandboxIds': identities, 'commandIds': commands,
            'packages': {name: importlib.metadata.version(name) for name in ['opensandbox', 'httpx', 'pydantic']}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--endpoint', required=True)
    parser.add_argument('--token-file', type=Path, required=True)
    parser.add_argument('--profile', default='python')
    parser.add_argument('--barrier', action='store_true')
    args = parser.parse_args()
    print(json.dumps(asyncio.run(exercise(args)), ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
