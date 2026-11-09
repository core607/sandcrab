"""Build, validate and publish a reusable rootfs with the published OpenSandbox SDK."""
import argparse
import asyncio
from datetime import timedelta
import json
import os
from pathlib import Path
import time

from opensandbox import Sandbox
from opensandbox.config import ConnectionConfig
from sandcrab_templates import TemplateClient


async def close(sandbox):
    try:
        await sandbox.kill()
    finally:
        await sandbox.close()


async def command(sandbox, source):
    result = await sandbox.commands.run(source)
    if result.exit_code != 0:
        raise RuntimeError('The environment build or validation command failed')
    return ''.join(item.text for item in result.logs.stdout)


async def prepare(args):
    if args.archive.exists() or args.receipt.exists():
        raise ValueError('Use new archive and receipt paths')
    token = args.token_file.read_text().strip()
    config = ConnectionConfig(domain=args.endpoint, protocol='http', api_key=token)
    options = dict(connection_config=config, timeout=timedelta(seconds=60),
                   resource={'cpu': '0.25', 'memory': '32Mi'})
    costs, instances = {}, []
    async with TemplateClient('http://' + args.endpoint, token) as templates:
        started = time.perf_counter()
        builder = await Sandbox.create(args.base_image, **options)
        try:
            await builder.files.write_file('/workspace/multiply.sh', '#!/bin/bash\nprintf "%s\\n" "$(( $1 * $2 ))"\n')
            output = await command(builder, 'cat /workspace/multiply.sh > /opt/multiply; bash /opt/multiply 6 7')
            if output != '42\n':
                raise RuntimeError('The built tool did not pass validation')
            costs['prepareAndValidateSeconds'] = time.perf_counter() - started
            started = time.perf_counter()
            checkpoint = await templates.capture(builder.id, args.archive)
            costs['captureSeconds'] = time.perf_counter() - started
        finally:
            await close(builder)
        descriptor = os.open(args.receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            output.write(json.dumps(checkpoint.to_dict(), indent=2) + '\n')
            output.flush()
            os.fsync(output.fileno())
        started = time.perf_counter()
        published = await templates.publish(checkpoint)
        costs['publishSeconds'] = time.perf_counter() - started
        for index in range(2):
            started = time.perf_counter()
            sandbox = await Sandbox.create(checkpoint.image, **options)
            try:
                output = await command(sandbox, 'test ! -e /workspace/instance; bash /opt/multiply 6 7')
                if output != '42\n':
                    raise RuntimeError('An independent instance failed validation')
                await sandbox.files.write_file('/workspace/instance', str(index))
                instances.append(sandbox.id)
                costs[f'instance{index + 1}StartAndTestSeconds'] = time.perf_counter() - started
            finally:
                await close(sandbox)
    return {'result': 'PASS', 'templateId': published['id'], 'image': checkpoint.image,
            'builderId': builder.id, 'instanceIds': instances, 'archiveBytes': checkpoint.bytes,
            'timings': costs, 'scope': 'Single build/test example; no capacity or latency-SLO claim'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint', default='127.0.0.1:9011')
    parser.add_argument('--token-file', type=Path, default=Path('/etc/sandcrab/token'))
    parser.add_argument('--base-image', required=True, help='PROFILE@sha256:ID of a rootfs with bash, cat and env')
    parser.add_argument('--archive', type=Path, required=True, help='A new local archive path')
    parser.add_argument('--receipt', type=Path, required=True, help='Local publication recovery receipt')
    print(json.dumps(asyncio.run(prepare(parser.parse_args()))))
