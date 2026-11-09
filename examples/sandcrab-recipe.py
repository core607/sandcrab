"""Compose independently published rootfs layers and validate two private instances."""
import argparse
import asyncio
from datetime import timedelta
import json
from pathlib import Path
import time
import uuid

from opensandbox import Sandbox
from opensandbox.config import ConnectionConfig
from sandcrab_templates import TemplateClient


async def exercise(args):
    token = args.token_file.read_text().strip()
    config = ConnectionConfig(domain=args.endpoint, protocol='http', api_key=token)
    started = time.perf_counter()
    async with TemplateClient('http://' + args.endpoint, token) as templates:
        recipe = await templates.compose(args.layers)
    costs = {'composeSeconds': time.perf_counter() - started}
    instances = []
    marker = '/workspace/.recipe-example-' + uuid.uuid4().hex
    for index in range(2):
        started = time.perf_counter()
        sandbox = await Sandbox.create(args.profile + '@sha256:' + recipe['id'], connection_config=config,
            timeout=timedelta(seconds=60), resource={'cpu': '0.25', 'memory': '32Mi'})
        try:
            validation = await sandbox.commands.run(args.validate)
            if validation.exit_code != 0:
                raise RuntimeError('Recipe validation failed')
            result = await sandbox.commands.run(f'test ! -e {marker} && printf private > {marker}')
            if result.exit_code != 0 or await sandbox.files.read_file(marker) != 'private':
                raise RuntimeError('Independent writable layer check failed')
            instances.append(sandbox.id)
            costs[f'instance{index + 1}StartAndTestSeconds'] = time.perf_counter() - started
        finally:
            try:
                await sandbox.kill()
            finally:
                await sandbox.close()
    return {'result': 'PASS', 'templateId': recipe['id'], 'layers': recipe['layers'],
            'instanceIds': instances, 'timings': costs,
            'scope': 'Single recipe example; timings include validation and make no latency-SLO claim'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint', default='127.0.0.1:9011')
    parser.add_argument('--token-file', type=Path, default=Path('/etc/sandcrab/token'))
    parser.add_argument('--profile', default='default')
    parser.add_argument('--validate', default='printf ready', help='A validation command inside each instance')
    parser.add_argument('layers', nargs='+', help='Immutable tree IDs, base first and workspace last')
    print(json.dumps(asyncio.run(exercise(parser.parse_args()))))
