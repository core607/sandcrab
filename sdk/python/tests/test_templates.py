"""Client guarantees must hold across response loss, cancellation and local file races."""
import asyncio
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import httpx

from sandcrab_templates import Checkpoint, PublicationUncertain, TemplateClient, TemplateError, recipe_id

SESSION = '00000000-0000-0000-0000-000000000001'
EPOCH = '00000000-0000-0000-0000-000000000002'
TEMPLATE = 'a' * 64
TOKEN = 'b' * 64
PAYLOAD = b'fixed archive'


def response_headers():
    return {'content-length': str(len(PAYLOAD)), 'etag': '"' + hashlib.sha256(PAYLOAD).hexdigest() + '"',
            'x-sandcrab-server-id': EPOCH, 'x-sandcrab-template-id': TEMPLATE,
            'x-sandcrab-profile': 'default', 'x-sandcrab-rootfs': 'true'}


def checkpoint(path):
    path.write_bytes(PAYLOAD)
    return Checkpoint(path, len(PAYLOAD), hashlib.sha256(PAYLOAD).hexdigest(), TEMPLATE, 'default', True)


class TemplateTests(unittest.IsolatedAsyncioTestCase):
    async def test_recipe_order_and_bounds_are_checked_before_sending(self):
        layers = ['a' * 64, 'b' * 64]
        self.assertNotEqual(recipe_id(layers), recipe_id(list(reversed(layers))))
        for invalid in ([], ['a'], [layers[0]] * 2, layers[0], [f'{i:064x}' for i in range(17)]):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                recipe_id(invalid)
        methods, published = [], False
        expected = recipe_id(layers)
        def handler(request):
            nonlocal published
            methods.append(request.method)
            if request.method == 'POST':
                self.assertEqual('/v1/templates/compose', request.url.path)
                self.assertEqual({'layers': layers}, json.loads(request.content))
                published = True
                raise httpx.ReadError('committed reply lost', request=request)
            self.assertEqual('/v1/templates/' + expected, request.url.path)
            return (httpx.Response(200, json={'id': expected, 'layers': layers}) if published
                    else httpx.Response(404, json={'error': {'code': 'TEMPLATE_NOT_FOUND'}}))
        async with TemplateClient('http://127.0.0.1:9011', TOKEN, transport=httpx.MockTransport(handler)) as client:
            self.assertEqual(expected, (await client.compose(layers))['id'])
            self.assertEqual(expected, (await client.compose(layers))['id'])
        self.assertEqual(['GET', 'POST', 'GET', 'GET'], methods)

    async def test_recipe_lost_reply_and_cancellation_never_repost(self):
        layers = ['a' * 64, 'b' * 64]
        for cancel in (False, True):
            methods, started = [], asyncio.Event()
            async def handler(request):
                methods.append(request.method)
                if request.method == 'GET':
                    return httpx.Response(404, json={'error': {'code': 'TEMPLATE_NOT_FOUND'}})
                started.set()
                if cancel:
                    await asyncio.Event().wait()
                raise httpx.ReadError('reply lost', request=request)
            async with TemplateClient('http://127.0.0.1:9011', TOKEN, transport=httpx.MockTransport(handler)) as client:
                task = asyncio.create_task(client.compose(layers))
                await asyncio.wait_for(started.wait(), 2)
                if cancel:
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                else:
                    with self.assertRaises(PublicationUncertain) as raised:
                        await task
                    self.assertEqual(recipe_id(layers), raised.exception.template_id)
            self.assertEqual(['GET', 'POST'] if cancel else ['GET', 'POST', 'GET'], methods)

    async def test_recipe_rejects_a_response_with_another_layer_order(self):
        layers = ['a' * 64, 'b' * 64]
        def handler(request):
            return httpx.Response(200, json={'id': recipe_id(layers), 'layers': list(reversed(layers))})
        async with TemplateClient('http://127.0.0.1:9011', TOKEN, transport=httpx.MockTransport(handler)) as client:
            with self.assertRaises(ValueError):
                await client.compose(layers)

    async def test_capture_can_be_reused_by_opensandbox_without_replacement(self):
        requests = []
        def handler(request):
            requests.append(request)
            self.assertEqual('Bearer ' + TOKEN, request.headers['authorization'])
            if request.method == 'GET':
                return httpx.Response(200, json={'serverId': EPOCH, 'profile': 'default', 'rootfs': True})
            self.assertEqual({'path': '.', 'format': 'tar', 'frozen': True, 'scope': 'filesystem'},
                             json.loads(request.content))
            return httpx.Response(200, headers=response_headers(), content=PAYLOAD)
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'prepared.tar'
            async with TemplateClient('http://127.0.0.1:9011', TOKEN, transport=httpx.MockTransport(handler)) as client:
                captured = await client.capture(SESSION, target)
                self.assertEqual(PAYLOAD, target.read_bytes())
                self.assertEqual('default@sha256:' + TEMPLATE, captured.image)
                self.assertEqual(captured, Checkpoint.from_dict(captured.to_dict()))
                target.write_bytes(b'existing file')
                with self.assertRaises(FileExistsError):
                    await client.capture(SESSION, target)
            self.assertEqual(b'existing file', target.read_bytes())
            self.assertFalse(list(Path(folder).glob('*.part')))
        self.assertEqual(['GET', 'POST', 'GET', 'POST'], [r.method for r in requests])

    async def test_capture_refuses_epoch_hash_length_and_profile_changes(self):
        for field, value in [('x-sandcrab-server-id', SESSION), ('etag', '"' + '0' * 64 + '"'),
                             ('content-length', str(len(PAYLOAD) + 1)), ('x-sandcrab-profile', 'other'),
                             ('x-sandcrab-rootfs', 'false'), ('x-sandcrab-template-id', 'invalid')]:
            headers = {**response_headers(), field: value}
            def handler(request):
                if request.method == 'GET':
                    return httpx.Response(200, json={'serverId': EPOCH, 'profile': 'default', 'rootfs': True})
                return httpx.Response(200, headers=headers, content=PAYLOAD)
            with self.subTest(field=field), tempfile.TemporaryDirectory() as folder:
                target = Path(folder) / 'prepared.tar'
                async with TemplateClient('http://127.0.0.1:9011', TOKEN, transport=httpx.MockTransport(handler)) as client:
                    with self.assertRaises(ValueError):
                        await client.capture(SESSION, target)
                self.assertFalse(list(Path(folder).iterdir()))

    async def test_lost_publish_reply_uses_only_a_read_to_reconcile(self):
        methods, published = [], False
        async def handler(request):
            nonlocal published
            methods.append(request.method)
            if request.method == 'POST':
                self.assertEqual(TEMPLATE, request.url.params['expectedId'])
                self.assertEqual('default', request.url.params['profile'])
                self.assertEqual(PAYLOAD, await request.aread())
                published = True
                raise httpx.ReadError('reply lost', request=request)
            if published:
                return httpx.Response(200, json={'id': TEMPLATE})
            return httpx.Response(404, json={'error': {'code': 'TEMPLATE_NOT_FOUND'}})
        with tempfile.TemporaryDirectory() as folder:
            captured = checkpoint(Path(folder) / 'prepared.tar')
            async with TemplateClient('http://127.0.0.1:9011', TOKEN, transport=httpx.MockTransport(handler)) as client:
                self.assertEqual({'id': TEMPLATE}, await client.publish(captured))
                captured.path.unlink()
                self.assertEqual({'id': TEMPLATE}, await client.reconcile(captured))
        self.assertEqual(['GET', 'POST', 'GET', 'GET'], methods)

    async def test_unconfirmed_publish_has_no_automatic_post_retry(self):
        methods = []
        def handler(request):
            methods.append(request.method)
            if request.method == 'POST':
                raise httpx.ReadError('reply lost', request=request)
            return httpx.Response(404, json={'error': {'code': 'TEMPLATE_NOT_FOUND'}})
        with tempfile.TemporaryDirectory() as folder:
            captured = checkpoint(Path(folder) / 'prepared.tar')
            async with TemplateClient('http://127.0.0.1:9011', TOKEN, transport=httpx.MockTransport(handler)) as client:
                with self.assertRaises(PublicationUncertain) as raised:
                    await client.publish(captured)
                self.assertEqual(TEMPLATE, raised.exception.template_id)
        self.assertEqual(['GET', 'POST', 'GET'], methods)

    async def test_changed_archive_and_server_refusal_do_not_publish_other_content(self):
        methods = []
        def handler(request):
            methods.append(request.method)
            if request.method == 'GET':
                return httpx.Response(404, json={'error': {'code': 'TEMPLATE_NOT_FOUND'}})
            return httpx.Response(409, json={'error': {'code': 'TEMPLATE_ID_MISMATCH'}})
        with tempfile.TemporaryDirectory() as folder:
            captured = checkpoint(Path(folder) / 'prepared.tar')
            async with TemplateClient('http://127.0.0.1:9011', TOKEN, transport=httpx.MockTransport(handler)) as client:
                captured.path.write_bytes(b'changed bytes')
                with self.assertRaises(ValueError):
                    await client.publish(captured)
                self.assertEqual(['GET'], methods)
                captured.path.write_bytes(PAYLOAD)
                with self.assertRaises(TemplateError) as raised:
                    await client.publish(captured)
                self.assertEqual('TEMPLATE_ID_MISMATCH', raised.exception.code)
        self.assertEqual(['GET', 'GET', 'POST'], methods)

    async def test_cancelled_capture_closes_stream_and_removes_partial_file(self):
        started, closed = asyncio.Event(), asyncio.Event()
        class Slow(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield PAYLOAD[:2]
                started.set()
                await asyncio.Event().wait()
            async def aclose(self):
                closed.set()
        def handler(request):
            if request.method == 'GET':
                return httpx.Response(200, json={'serverId': EPOCH, 'profile': 'default', 'rootfs': True})
            return httpx.Response(200, headers=response_headers(), stream=Slow())
        with tempfile.TemporaryDirectory() as folder:
            async with TemplateClient('http://127.0.0.1:9011', TOKEN, transport=httpx.MockTransport(handler)) as client:
                task = asyncio.create_task(client.capture(SESSION, Path(folder) / 'prepared.tar'))
                await asyncio.wait_for(started.wait(), 2)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
            self.assertTrue(closed.is_set())
            self.assertFalse(list(Path(folder).iterdir()))

    async def test_only_explicit_loopback_endpoints_receive_credentials(self):
        for endpoint in ['https://127.0.0.1:9011', 'http://example.test:9011', 'http://127.0.0.1',
                         'http://127.0.0.1:9011/private', 'http://name:secret@127.0.0.1:9011',
                         'http://127.0.0.1:9011/?query=x', 'http://0.0.0.0:9011']:
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                TemplateClient(endpoint, TOKEN)

    async def test_cancelled_publication_closes_archive_without_reposting(self):
        started, methods = asyncio.Event(), []
        async def handler(request):
            methods.append(request.method)
            if request.method == 'GET':
                return httpx.Response(404, json={'error': {'code': 'TEMPLATE_NOT_FOUND'}})
            started.set()
            await asyncio.Event().wait()
        with tempfile.TemporaryDirectory() as folder:
            captured = checkpoint(Path(folder) / 'prepared.tar')
            async with TemplateClient('http://127.0.0.1:9011', TOKEN, transport=httpx.MockTransport(handler)) as client:
                task = asyncio.create_task(client.publish(captured))
                await asyncio.wait_for(started.wait(), 2)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                captured.path.unlink()
        self.assertEqual(['GET', 'POST'], methods)


if __name__ == '__main__':
    unittest.main()
