#!/usr/bin/env python3
"""Published Python SDK commands wait in both default and named shell contexts."""
import argparse
import asyncio
from datetime import timedelta
import importlib.metadata
import json
from pathlib import Path

from opensandbox import Sandbox
from opensandbox.config import ConnectionConfig
from opensandbox.models.execd import ExecutionHandlers


def output(execution):
    return ''.join(item.text for item in execution.logs.stdout)


async def exercise(args):
    assert importlib.metadata.version('opensandbox') == '1.1.0'
    config = ConnectionConfig(domain=args.endpoint, protocol='http',
        api_key=args.token_file.read_text().strip(), request_timeout=timedelta(seconds=15))
    sandbox = await Sandbox.create('python', connection_config=config,
        timeout=timedelta(seconds=60), resource={'cpu': '0.25', 'memory': '32Mi'})
    commands, checks, tasks = [], [], []
    try:
        named = await sandbox.commands.create_session()
        for context in (None, named):
            async def execute(source, handlers=None):
                if context is None:
                    return await sandbox.commands.run(source, handlers=handlers)
                return await sandbox.commands.run_in_session(context, source, handlers=handlers)

            started = asyncio.Event()

            async def on_stdout(message):
                if 'active' in message.text:
                    started.set()

            first = asyncio.create_task(execute('printf active; sleep 3; printf first >> sdk-order',
                ExecutionHandlers(on_stdout=on_stdout)))
            tasks.append(first)
            await asyncio.wait_for(started.wait(), 5)
            refused = await execute('touch sdk-forbidden')
            commands.append(refused.id)
            assert refused.error is not None and refused.error.name == 'QUEUE_TIMEOUT', refused.model_dump()
            assert output(refused) == ''
            completed = await first
            commands.append(completed.id)
            assert completed.exit_code == 0
            verified = await execute('test ! -e sdk-forbidden; cat sdk-order; rm sdk-order')
            commands.append(verified.id)
            assert verified.exit_code == 0 and output(verified) == 'first'

            started.clear()
            first = asyncio.create_task(execute('printf active; sleep .5; printf 1 >> sdk-order',
                ExecutionHandlers(on_stdout=on_stdout)))
            tasks.append(first)
            await asyncio.wait_for(started.wait(), 5)
            second = await execute('printf 2 >> sdk-order; cat sdk-order')
            commands.append(second.id)
            completed = await first
            commands.append(completed.id)
            assert completed.exit_code == 0 and second.exit_code == 0 and output(second) == '12'
            cleared = await execute('rm sdk-order')
            commands.append(cleared.id)
            assert cleared.exit_code == 0

            started.clear()
            first = asyncio.create_task(execute('printf active; sleep .8; printf completed',
                ExecutionHandlers(on_stdout=on_stdout)))
            tasks.append(first)
            await asyncio.wait_for(started.wait(), 5)
            admitted = asyncio.Future()

            async def on_init(message):
                admitted.set_result(message.id)

            waiting = asyncio.create_task(execute('touch sdk-cancelled', ExecutionHandlers(on_init=on_init)))
            tasks.append(waiting)
            identity = await asyncio.wait_for(admitted, 5)
            assert (await sandbox.commands.get_command_status(identity)).running
            await sandbox.commands.interrupt(identity)
            cancelled = await waiting
            commands.append(cancelled.id)
            assert cancelled.error is not None and cancelled.error.name == 'COMMAND_CANCELLED', cancelled.model_dump()
            completed = await first
            commands.append(completed.id)
            assert completed.exit_code == 0 and output(completed) == 'activecompleted', completed.model_dump()
            verified = await execute('test ! -e sdk-cancelled; printf preserved')
            commands.append(verified.id)
            assert verified.exit_code == 0 and output(verified) == 'preserved'
            checks.append(('default' if context is None else 'named') + '-fifo-timeout-and-queued-cancel-preserves-active-command')
        await sandbox.commands.delete_session(named)
    finally:
        try:
            await sandbox.kill()
        finally:
            await asyncio.gather(*tasks, return_exceptions=True)
            await sandbox.close()
    return {'result': 'PASS', 'client': 'python', 'sdkVersion': '1.1.0', 'checks': checks,
            'sandboxId': sandbox.id, 'commandIds': commands}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--endpoint', required=True)
    parser.add_argument('--token-file', required=True, type=Path)
    print(json.dumps(asyncio.run(exercise(parser.parse_args()))))
