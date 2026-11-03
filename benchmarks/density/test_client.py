import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest

from client import Client, ProtocolError


@unittest.skipUnless(os.name == 'posix', 'Native Unix peer checks require Linux')
class ClientTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / 'control.sock'
        self.requests = []
        self.reply = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
        self.delay = 0
        self.active = set()
        self.loop_errors = []
        self.previous_handler = asyncio.get_running_loop().get_exception_handler()
        asyncio.get_running_loop().set_exception_handler(lambda loop, context: self.loop_errors.append(context))

        async def serve(reader, writer):
            task = asyncio.current_task()
            self.active.add(task)
            try:
                headers = await reader.readuntil(b'\r\n\r\n')
                content = next(line.split(b':', 1)[1].strip() for line in headers.split(b'\r\n')
                               if line.lower().startswith(b'content-length:'))
                body = await reader.readexactly(int(content))
                value = body if b'Content-Type: application/x-tar\r\n' in headers else (json.loads(body) if body else None)
                self.requests.append((headers.split(b'\r\n')[0], value))
                await asyncio.sleep(self.delay)
                writer.write(self.reply)
                await writer.drain()
            except (OSError, asyncio.IncompleteReadError):
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
                self.active.discard(task)

        self.server = await asyncio.start_unix_server(serve, str(self.path))
        self.client = Client(self.path, peer_uid=os.geteuid())

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        tasks = list(self.active)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.temporary.cleanup()
        asyncio.get_running_loop().set_exception_handler(self.previous_handler)
        self.assertEqual(self.loop_errors, [])

    async def test_lost_post_acknowledgement_is_not_replayed(self):
        self.reply = b''
        with self.assertRaises(asyncio.IncompleteReadError):
            await self.client.request('POST', '/v1/runs', {'id': 'original-operation'})
        self.assertEqual(self.requests, [(b'POST /v1/runs HTTP/1.1', {'id': 'original-operation'})])

    async def test_oversized_duplicate_and_chunked_framing_are_refused(self):
        for headers in (b'Content-Length: 999999999', b'Content-Length: 2\r\nContent-Length: 2',
                        b'Transfer-Encoding: chunked\r\nContent-Length: 2'):
            self.reply = b'HTTP/1.1 200 OK\r\n' + headers + b'\r\n\r\n{}'
            with self.assertRaises(ProtocolError):
                await self.client.request('GET', '/v1/info')
        self.assertEqual(len(self.requests), 3)

    async def test_refusal_is_returned_with_its_original_code(self):
        body = b'{"error":{"code":"SESSION_CAPACITY"}}'
        self.reply = b'HTTP/1.1 429 Refused\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
        status, value = await self.client.request('POST', '/v1/sessions', {'id': 'new-session'})
        self.assertEqual(status, 429)
        self.assertEqual(value['error']['code'], 'SESSION_CAPACITY')

    async def test_timeout_closes_the_request_without_retrying_it(self):
        self.client.timeout, self.delay = .02, .2
        with self.assertRaises(TimeoutError):
            await self.client.request('POST', '/v1/runs', {'id': 'timed-request'})
        self.assertEqual(len(self.requests), 1)

    async def test_wrong_peer_is_refused_before_request_bytes_are_sent(self):
        self.client.peer_uid = os.geteuid() + 1
        with self.assertRaises(ProtocolError):
            await self.client.request('POST', '/v1/runs', {'id': 'wrong-peer'})
        await asyncio.sleep(.01)
        self.assertEqual(self.requests, [])

    async def test_template_import_sends_binary_bytes_once_even_when_ack_is_lost(self):
        self.reply = b''
        body = b'fixture\0tar\xff'
        with self.assertRaises(asyncio.IncompleteReadError):
            await self.client.import_template(body)
        self.assertEqual(self.requests, [(b'POST /v1/templates?profile=python HTTP/1.1', body)])

    async def test_template_deletion_uses_the_public_delete_method(self):
        await self.client.request('DELETE', '/v1/templates/' + 'a' * 64)
        self.assertEqual(self.requests[0][0], b'DELETE /v1/templates/' + b'a' * 64 + b' HTTP/1.1')


if __name__ == '__main__':
    unittest.main()
