"""SDK fault accounting and export bounds; real-service acceptance runs separately."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import httpx
from opensandbox.sync.adapters.command_adapter import CommandsAdapterSync
from opensandbox.models.sandboxes import SandboxEndpoint

from sandcrab import sandcrab_native
from sdk_archive import SOURCE
from sdk_transport import ResponseLimit, Transport
from workspace_cases import MAX_ARTIFACT
from workspace_client import Rejected
from workspace_sdk import SdkWorkspace


class TransportFaults(unittest.TestCase):
    def transport(self, response):
        self.rows = []
        return Transport('http://127.0.0.1:1234', self.rows, lambda: 'agent', httpx.MockTransport(lambda request: response))

    def request(self, transport, path='/opensandbox/box/files/download'):
        return transport.handle_request(httpx.Request('GET', 'http://127.0.0.1:1234' + path,
                                                      headers={'authorization': 'Bearer fixture-secret'}))

    def test_download_has_verified_framing_and_digest_without_credentials(self):
        data = b'archive bytes'
        digest = hashlib.sha256(data).hexdigest()
        transport = self.transport(httpx.Response(200, content=data, headers={'etag': '"' + digest + '"'}))
        self.assertEqual(data, self.request(transport).content)
        self.assertEqual(1, len(self.rows))
        self.assertEqual({'bytes': len(data), 'sha256': digest}, {k: self.rows[0][k] for k in ('bytes', 'sha256')})
        self.assertNotIn('fixture-secret', json.dumps(self.rows))
        self.assertNotIn('archive bytes', json.dumps(self.rows))
        self.assertNotIn('127.0.0.1', json.dumps(self.rows))

    def test_download_rejects_tamper_truncation_and_ambiguous_framing(self):
        digest = '"' + hashlib.sha256(b'ab').hexdigest() + '"'
        for headers in [[('etag', 'wrong')], [('etag', digest), ('content-length', '3')],
                        [('etag', digest), ('content-length', '2'), ('content-length', '2')],
                        [('etag', digest), ('content-length', '2'), ('transfer-encoding', 'chunked')]]:
            with self.subTest(headers=headers):
                transport = self.transport(httpx.Response(200, stream=httpx.ByteStream(b'ab'), headers=headers))
                with self.assertRaises(ValueError):
                    self.request(transport)
                self.assertTrue(self.rows[0]['error'])

    def test_response_limits_and_endpoint_authority_precede_unbounded_consumption(self):
        transport = self.transport(httpx.Response(200, stream=httpx.ByteStream(b'x' * (MAX_ARTIFACT + 1)),
                                                   headers={'content-length': str(MAX_ARTIFACT + 1)}))
        with self.assertRaises(ResponseLimit):
            self.request(transport)
        self.assertEqual('response_limit', self.rows[0]['error'])
        for url in ['http://127.0.0.1:1235/', 'http://example.invalid/', 'http://user@127.0.0.1:1234/']:
            with self.assertRaises(ValueError):
                transport.handle_request(httpx.Request('GET', url))
        self.assertEqual(1, len(self.rows), 'Rejected origins must not dispatch requests')

    def test_stream_transport_failure_is_one_observation_without_retry(self):
        count = 0
        def fail(request):
            nonlocal count
            count += 1
            raise httpx.ReadError('sensitive transport diagnostic')
        transport = Transport('http://127.0.0.1:1234', [], lambda: 'agent', httpx.MockTransport(fail))
        with self.assertRaises(httpx.ReadError):
            self.request(transport, '/opensandbox/box/session/ctx/run')
        self.assertEqual(1, count)
        self.assertEqual('ReadError', transport.observations[0]['error'])
        self.assertNotIn('sensitive', json.dumps(transport.observations))

    def test_sdk_unlimited_stream_read_is_bounded_before_dispatch(self):
        timeouts = []
        def receive(request):
            timeouts.append(request.extensions['timeout'])
            return httpx.Response(200, content=b'')
        transport = Transport('http://127.0.0.1:1234', [], lambda: 'agent', httpx.MockTransport(receive))
        transport.handle_request(httpx.Request('POST', 'http://127.0.0.1:1234/opensandbox/box/command',
            extensions={'timeout': {'connect': 15, 'read': None, 'write': 300, 'pool': None}}))
        self.assertEqual([{'connect': 15, 'read': 75, 'write': 75, 'pool': 75}], timeouts)


class ConsumerFaults(unittest.TestCase):
    def client(self, directory):
        return SdkWorkspace('native-fixture', Path(directory) / 'artifacts', {'observations': []},
                            {'domain': '127.0.0.1:1234', 'token': 'fixture-secret'})

    def test_published_sdk_silent_delete_error_cannot_confirm_containment(self):
        with tempfile.TemporaryDirectory() as directory:
            client = self.client(directory)
            client.transport.inner.close()
            client.transport.inner = httpx.MockTransport(lambda request: httpx.Response(503,
                json={'code': 'CONTAINMENT_UNCONFIRMED', 'message': 'not stopped'}))
            commands = CommandsAdapterSync(client.connection, SandboxEndpoint(endpoint='127.0.0.1:1234/opensandbox/box'))
            client.box = SimpleNamespace(commands=commands)
            client.context = 'retained-context'
            with self.assertRaisesRegex(RuntimeError, 'SDK operation failed'):
                client.close_context()
            self.assertEqual('retained-context', client.context)
            self.assertTrue(client.agent_closed.is_set())
            self.assertEqual(503, client.state['observations'][0]['status'])
            client.transport.close()

    def test_recoverable_refusal_and_uncertain_mutation_have_different_outcomes(self):
        with tempfile.TemporaryDirectory() as directory:
            client = self.client(directory)
            client.phase = 'agent'
            def refuse():
                client.state['observations'].append({'status': 400})
            with self.assertRaises(Rejected):
                client.sdk(refuse)
            self.assertFalse(client.agent_closed.is_set())
            def unknown():
                client.state['observations'].append({'status': None, 'error': 'ReadError'})
                raise ValueError('private path and credentials')
            with self.assertRaisesRegex(RuntimeError, 'retained ownership') as raised:
                client.sdk(unknown)
            self.assertNotIn('private', str(raised.exception))
            self.assertTrue(client.agent_closed.is_set())
            client.transport.close()

    def test_unacknowledged_root_creation_fails_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            client = self.client(directory)
            client.creation_unknown = True
            with self.assertRaisesRegex(RuntimeError, 'creation was not acknowledged'):
                client.cleanup()

    def test_only_creation_health_polls_may_transition_from_503_to_ready(self):
        for readiness, status, route, accepted in [(True, 503, '/opensandbox/box/ping', True),
                                                  (False, 503, '/opensandbox/box/ping', False),
                                                  (True, 500, '/opensandbox/box/ping', False),
                                                  (True, 503, '/opensandbox/other/ping', False)]:
            with self.subTest(readiness=readiness, status=status, route=route), tempfile.TemporaryDirectory() as directory:
                client = self.client(directory)
                def create():
                    client.state['observations'].extend([
                        {'method': 'GET', 'path': route, 'status': status},
                        {'method': 'GET', 'path': '/opensandbox/box/ping', 'status': 200}])
                    return SimpleNamespace(id='box')
                if accepted:
                    self.assertEqual('box', client.sdk(create, readiness=True).id)
                    self.assertEqual(2, len(client.state['observations']))
                else:
                    with self.assertRaises(RuntimeError):
                        client.sdk(create, readiness=readiness)
                client.transport.close()

    def test_export_seals_a_visible_artifact_for_workflow_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            client = self.client(directory)
            client.directory.mkdir()
            data = b'bounded fixture archive'
            info = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
            deleted = []
            client.box = SimpleNamespace(files=SimpleNamespace(read_bytes=lambda name: data,
                delete_files=lambda names: deleted.extend(names)))
            with patch.object(client, 'helper', return_value={'state': 'succeeded', 'stdout': json.dumps(info)}):
                self.assertTrue(client.export()['exported'])
            name = client.state['artifact']['name']
            self.assertFalse(name.startswith('.'), 'Workflow artifact collection excludes hidden files')
            self.assertEqual(data, (client.directory / name).read_bytes())
            self.assertEqual(['/workspace/' + name], deleted)
            client.transport.close()

    def test_identical_corpus_runs_through_both_clients_with_unique_sample_ids(self):
        native = sandcrab_native('fixture', baseline=True, suite='workspace', artifacts='artifacts')
        sdk = sandcrab_native('fixture', baseline=True, suite='workspace', artifacts='artifacts', workspace_client='sdk', sdk_config='fixture-config')
        both = sandcrab_native('fixture', baseline=True, suite='all', artifacts='artifacts', workspace_client='both', sdk_config='fixture-config')
        self.assertEqual(native.metadata['corpusSha256'], sdk.metadata['corpusSha256'])
        self.assertEqual([s.input for s in native.dataset], [s.input for s in sdk.dataset])
        self.assertEqual(22, len(both.dataset))
        self.assertEqual(22, len({s.id for s in both.dataset}))
        self.assertEqual({'native', 'sdk'}, {s.metadata['workspaceClient'] for s in both.dataset if s.metadata['kind'] == 'workspace'})


class ExportProgram(unittest.TestCase):
    def export(self, directory):
        # Only the committed helper and synthetic fixture execute on the test host.
        return subprocess.run([sys.executable, '-I', '-c', SOURCE, '.sdk-export-test.tar'], cwd=directory,
                              capture_output=True, text=True, timeout=10)

    def test_archive_contains_exact_sources_and_excludes_itself(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, 'main.py')
            source.write_bytes(b'print("fixture")\n')
            result = self.export(directory)
            self.assertEqual(0, result.returncode, result.stderr)
            raw = Path(directory, '.sdk-export-test.tar').read_bytes()
            self.assertEqual({'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}, json.loads(result.stdout))
            with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
                self.assertEqual(['main.py'], archive.getnames())
                self.assertEqual(source.read_bytes(), archive.extractfile('main.py').read())

    def test_oversized_workspace_never_produces_a_success_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'large').write_bytes(b'x' * MAX_ARTIFACT)
            result = self.export(directory)
            self.assertNotEqual(0, result.returncode)
            self.assertEqual('', result.stdout)
            self.assertLessEqual(Path(directory, '.sdk-export-test.tar').stat().st_size, MAX_ARTIFACT)


if __name__ == '__main__':
    unittest.main()
