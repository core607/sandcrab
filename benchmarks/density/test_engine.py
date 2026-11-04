import asyncio
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from engine import Engine


class EngineTests(unittest.IsolatedAsyncioTestCase):
    def engine(self, replies):
        events, requests = [], []
        engine = Engine('/unused', 'epoch', lambda phase, row: events.append((phase, dict(row))))

        async def request(method, route, body=None):
            requests.append((method, route, body))
            reply = replies.pop(0)
            if isinstance(reply, BaseException):
                raise reply
            return reply

        engine.client.request = request
        return engine, events, requests

    async def test_refusal_is_counted_and_reconciled_without_resubmission(self):
        engine, events, requests = self.engine([(429, {'error': {'code': 'RESULT_CAPACITY'}})])
        row = await engine.execute('session', 'touch /workspace/once')
        self.assertEqual(row['outcome'], 'REFUSED')
        self.assertFalse(row['fatal'])
        self.assertIn(row['id'], engine.runs)
        self.assertEqual(engine.executing, {})
        self.assertEqual(len(requests), 1)
        self.assertEqual([event for event, _ in events], ['created', 'completed'])

    async def test_lost_ack_keeps_identity_pending_for_cleanup(self):
        engine, events, requests = self.engine([ConnectionResetError()])
        pending = []
        row = await engine.execute('session', 'touch /workspace/once', on_start=lambda value: pending.append(dict(value)))
        self.assertEqual(row['outcome'], 'TRANSPORT')
        self.assertTrue(row['fatal'])
        self.assertEqual(pending[0]['outcome'], 'PENDING')
        self.assertEqual(pending[0]['id'], row['id'])
        self.assertEqual(engine.executing, {row['id']: 'unknown'})
        self.assertEqual(len(requests), 1)

    async def test_observation_refusal_after_acceptance_is_not_submission_refusal(self):
        engine, _, requests = self.engine([(202, {'state': 'running'}), (404, {'error': {'code': 'NOT_FOUND'}})])
        row = await engine.execute('session', 'true')
        self.assertEqual(row['outcome'], 'ERROR')
        self.assertTrue(row['fatal'])
        self.assertEqual([method for method, _, _ in requests], ['POST', 'GET'])

    async def test_forget_failure_preserves_the_executed_result(self):
        engine, _, _ = self.engine([
            (202, {'state': 'running'}),
            (200, {'state': 'succeeded', 'result': {'exitCode': 0, 'stdout': '42\n', 'stderr': ''}}),
            ConnectionResetError(),
        ])
        row = await engine.execute('session', 'echo 42')
        self.assertEqual(row['outcome'], 'OK')
        self.assertEqual(row['stdout'], '42\n')
        self.assertTrue(row['fatal'])
        self.assertEqual(row['cleanupFailure'], 'ConnectionResetError')
        self.assertIn(row['id'], engine.runs)
        self.assertEqual(engine.executing, {})

    async def test_unknown_state_cannot_be_scored_as_an_ordinary_command_failure(self):
        engine, _, requests = self.engine([(202, {'state': 'running'}), (200, {'state': 'unrecognized'})])
        row = await engine.execute('session', 'true')
        self.assertEqual(row['outcome'], 'TRANSPORT')
        self.assertEqual(row['code'], 'ProtocolError')
        self.assertTrue(row['fatal'])
        self.assertEqual(len(requests), 2)

    async def test_runtime_failure_without_output_retains_native_failure_code(self):
        engine, _, _ = self.engine([(202, {'state': 'running'}),
                                   (200, {'state': 'failed', 'result': {'code': 'RUN_FAILED'}}), (200, {})])
        row = await engine.execute('session', 'true')
        self.assertEqual(row['outcome'], 'COMMAND_FAILED')
        self.assertEqual(row['code'], 'RUN_FAILED')
        self.assertNotIn('stdout', row)
        self.assertNotIn('fatal', row)
        self.assertEqual(engine.runs, set())

    async def test_finite_run_uses_the_public_argv_contract_and_same_cleanup(self):
        engine, _, requests = self.engine([
            (202, {'state': 'running'}),
            (200, {'state': 'succeeded', 'result': {'exitCode': 0, 'stdout': '', 'stderr': ''}}), (200, {}),
        ])
        row = await engine.execute(None, ['/bin/sleep', '1'], kind='finite')
        self.assertEqual(requests[0][0:2], ('POST', '/v1/runs'))
        self.assertEqual(requests[0][2]['command'], ['/bin/sleep', '1'])
        self.assertEqual(requests[0][2]['profile'], 'python')
        self.assertEqual(row['outcome'], 'OK')
        self.assertEqual(engine.runs, set())

    async def test_queued_refusal_is_measured_and_forgotten_without_resubmission(self):
        engine, _, requests = self.engine([
            (202, {'state': 'queued'}), (200, {'state': 'queued'}),
            (200, {'state': 'refused', 'queueWaitMillis': 2002,
                   'result': {'code': 'QUEUE_TIMEOUT', 'executed': False}}), (200, {}),
        ])
        row = await engine.execute('session', 'touch once')
        self.assertEqual((row['outcome'], row['code'], row['queueWaitMillis']), ('REFUSED', 'QUEUE_TIMEOUT', 2002))
        self.assertNotIn('fatal', row)
        self.assertEqual(engine.executing, {})
        self.assertEqual(engine.runs, set())
        self.assertEqual([method for method, _, _ in requests], ['POST', 'GET', 'GET', 'POST'])
        self.assertTrue(requests[-1][1].endswith('/forget'))

    async def test_refused_state_without_no_execution_receipt_is_fatal(self):
        for result in ({'code': 'QUEUE_TIMEOUT'}, {'code': 'QUEUE_TIMEOUT', 'executed': True},
                       {'exitCode': 0, 'stdout': '', 'stderr': '', 'executed': False}):
            engine, _, requests = self.engine([
                (202, {'state': 'queued'}), (200, {'state': 'refused', 'result': result}),
            ])
            row = await engine.execute('session', 'touch once')
            self.assertEqual((row['outcome'], row['code']), ('TRANSPORT', 'ProtocolError'))
            self.assertTrue(row['fatal'])
            self.assertIn(row['id'], engine.runs)
            self.assertEqual(len(requests), 2)

    async def test_cancelled_observation_retains_attempt_and_resource_identity(self):
        engine, events, _ = self.engine([asyncio.CancelledError()])
        with self.assertRaises(asyncio.CancelledError):
            await engine.execute('session', 'sleep 10')
        self.assertEqual(len(events), 1)
        self.assertIn(events[0][1]['id'], engine.runs)

    async def test_cleanup_reconciles_uncertain_run_and_checks_all_inventories(self):
        engine, _, requests = self.engine([
            (200, {'state': 'running'}), (200, {}),
            (200, {'state': 'cancelled'}), (200, {'forgotten': True}),
            (200, {'ids': []}), (200, {'ids': []}), (200, {'volumes': [{'id': 'base'}]}),
        ])
        engine.runs.add('uncertain')
        engine.volumes.add('base')
        result = await engine.cleanup(keep_volumes=('base',))
        self.assertEqual(result, {'result': 'PASS', 'failures': []})
        self.assertEqual(engine.runs, set())
        self.assertEqual(engine.volumes, {'base'})
        self.assertEqual([route for method, route, _ in requests if method == 'POST'],
                         ['/v1/runs/uncertain/cancel', '/v1/runs/uncertain/forget'])

    async def test_cleanup_does_not_claim_success_with_unowned_resources_or_more_pages(self):
        engine, _, _ = self.engine([(200, {'ids': ['unowned']}),
                                   (200, {'ids': [], 'nextAfter': 'unseen'}), (200, {'volumes': []})])
        result = await engine.cleanup()
        self.assertEqual(result['result'], 'FAIL')
        self.assertEqual(result['failures'], ['INVENTORY_NOT_EMPTY', 'INVENTORY_NOT_EMPTY'])

    async def test_template_session_requires_readback_of_the_same_base(self):
        identity = 'a' * 64
        engine, _, requests = self.engine([(202, {'state': 'starting'}),
                                           (200, {'state': 'ready', 'templateId': 'b' * 64})])
        with self.assertRaisesRegex(RuntimeError, 'requested template'):
            await engine.session(template=identity)
        self.assertEqual(requests[0][2]['templateId'], identity)
        self.assertNotIn('volumeId', requests[0][2])
        self.assertEqual(len(engine.sessions), 1)

    async def test_import_uses_relative_tar_and_cleanup_deletes_only_owned_templates(self):
        identity = 'a' * 64
        engine, events, requests = self.engine([(200, {'deleted': True}), (200, {'ids': []}),
                                               (200, {'ids': []}), (200, {'volumes': []}), (200, {'templates': []})])
        async def upload(body):
            with tarfile.open(fileobj=io.BytesIO(body)) as archive:
                self.assertEqual(archive.getnames(), ['data.txt'])
                self.assertEqual(archive.extractfile('data.txt').read(), b'fixture')
            return 200, {'id': identity}
        engine.client.import_template = upload
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / 'data.txt').write_bytes(b'fixture')
            self.assertEqual(await engine.template(source), identity)
        self.assertEqual(engine.templates, {identity})
        self.assertEqual((await engine.cleanup())['result'], 'PASS')
        self.assertEqual(requests[0][:2], ('DELETE', '/v1/templates/' + identity))
        self.assertEqual(engine.templates, set())
        self.assertEqual([event for event, _ in events], ['template-import-created', 'template-import-completed'])

    async def test_lost_import_ack_does_not_adopt_or_delete_an_unknown_catalog_object(self):
        engine, _, requests = self.engine([(200, {'ids': []}), (200, {'ids': []}),
                                           (200, {'volumes': []}), (200, {'templates': [{'id': 'a' * 64}]})])
        async def upload(body):
            raise ConnectionResetError()
        engine.client.import_template = upload
        with self.assertRaises(ConnectionResetError):
            await engine.template()
        self.assertEqual((await engine.cleanup())['failures'], ['INVENTORY_NOT_EMPTY'])
        self.assertTrue(all(method == 'GET' for method, _, _ in requests))


if __name__ == '__main__':
    unittest.main()
