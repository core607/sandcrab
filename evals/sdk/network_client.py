#!/usr/bin/env python3
"""Published Python SDK policy and HTTPS acceptance against the owned egress fixture."""
import argparse
import asyncio
from datetime import timedelta
import importlib.metadata
import json
from pathlib import Path
import shlex

from opensandbox import Sandbox
from opensandbox.config import ConnectionConfig


async def exercise(args):
    assert importlib.metadata.version('opensandbox') == '1.1.0'
    config = ConnectionConfig(domain=args.endpoint, protocol='http',
        api_key=args.token_file.read_text().strip(), request_timeout=timedelta(seconds=15))
    sandbox = await Sandbox.create('egress', connection_config=config,
        timeout=timedelta(seconds=60), resource={'cpu': '0.25', 'memory': '32Mi'})
    commands = []
    try:
        policy = await sandbox.get_egress_policy()
        assert policy.default_action == 'deny'
        assert {rule.target for rule in policy.egress} == {
            'allowed.example', 'tcp.example', 'private.example', 'rebind.example', 'slow.example'}
        assert all(rule.action == 'allow' for rule in policy.egress)
        source = (f'import ssl,urllib.request; context=ssl.create_default_context(cadata={args.certificate.read_text()!r}); '
                  f'print(urllib.request.urlopen("https://allowed.example:{args.port}/",context=context,timeout=4).read().decode(),end="")')
        execution = await sandbox.commands.run('python3 -c ' + shlex.quote(source))
        commands.append(execution.id)
        assert execution.exit_code == 0, execution.model_dump()
        assert ''.join(item.text for item in execution.logs.stdout) == 'sandcrab-egress-fixture\n'
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
    parser.add_argument('--token-file', required=True, type=Path)
    parser.add_argument('--certificate', required=True, type=Path)
    parser.add_argument('--port', required=True, type=int)
    print(json.dumps(asyncio.run(exercise(parser.parse_args()))))
