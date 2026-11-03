#!/usr/bin/env python3
"""Published Python SDK smoke against an imported template root filesystem."""
import argparse
import asyncio
from datetime import timedelta
import importlib.metadata
import json
from pathlib import Path

from opensandbox import Sandbox
from opensandbox.config import ConnectionConfig
from opensandbox.models.filesystem import WriteEntry


async def exercise(args):
    assert importlib.metadata.version('opensandbox') == '1.1.0'
    config = ConnectionConfig(domain=args.endpoint, protocol='http',
        api_key=args.token_file.read_text().strip(), request_timeout=timedelta(seconds=15))
    sandbox = await Sandbox.create(args.image, connection_config=config,
        timeout=timedelta(seconds=60), resource={'cpu': '0.25', 'memory': '32Mi'})
    commands = []
    try:
        assert (await sandbox.get_info()).image.image == args.image
        execution = await sandbox.commands.run('cat /opt/base; test ! -e /usr/bin/python3')
        commands.append(execution.id)
        assert execution.exit_code == 0, execution.model_dump()
        assert ''.join(item.text for item in execution.logs.stdout) == 'template environment'
        await sandbox.files.write_files([WriteEntry(path='/workspace/sdk-file', data='python rootfs')])
        assert await sandbox.files.read_file('/workspace/sdk-file') == 'python rootfs'
        context = await sandbox.commands.create_session()
        execution = await sandbox.commands.run_in_session(context, 'cat sdk-file')
        commands.append(execution.id)
        assert execution.exit_code == 0
        assert ''.join(item.text for item in execution.logs.stdout) == 'python rootfs'
        await sandbox.commands.delete_session(context)
    finally:
        try:
            await sandbox.kill()
        finally:
            await sandbox.close()
    return {'result': 'PASS', 'client': 'python', 'sdkVersion': '1.1.0',
            'sandboxId': sandbox.id, 'commandIds': commands}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--endpoint', required=True)
    parser.add_argument('--token-file', type=Path, required=True)
    parser.add_argument('--image', required=True)
    print(json.dumps(asyncio.run(exercise(parser.parse_args()))))
