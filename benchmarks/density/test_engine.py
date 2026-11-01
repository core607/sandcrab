import asyncio
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


if __name__ == '__main__':
    unittest.main()
