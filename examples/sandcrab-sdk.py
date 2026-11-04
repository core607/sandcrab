"""Write and test a program using the published OpenSandbox Python SDK."""
import asyncio
import os
from datetime import timedelta
from pathlib import Path

from opensandbox import Sandbox
from opensandbox.config import ConnectionConfig


async def main():
    token = Path(os.environ.get('SANDCRAB_TOKEN_FILE', '/etc/sandcrab/token')).read_text().strip()
    connection = ConnectionConfig(domain=os.environ.get('SANDCRAB_ENDPOINT', '127.0.0.1:9011'),
                                  protocol='http', api_key=token)
    sandbox = await Sandbox.create(os.environ.get('SANDCRAB_PROFILE', 'default'), connection_config=connection,
                                   timeout=timedelta(seconds=60), resource={'cpu': '0.25', 'memory': '32Mi'})
    try:
        await sandbox.files.write_file('answer.py', "from pathlib import Path\nPath('answer.txt').write_text(str(6 * 7))\n")
        result = await sandbox.commands.run(['python3', 'answer.py'])
        if result.exit_code != 0:
            raise RuntimeError('The sandbox command failed')
        print(await sandbox.files.read_file('answer.txt'))
    finally:
        try:
            await sandbox.kill()
        finally:
            await sandbox.close()


if __name__ == '__main__':
    asyncio.run(main())
