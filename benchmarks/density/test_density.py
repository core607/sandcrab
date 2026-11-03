import os
import asyncio
import time
import unittest
from unittest.mock import AsyncMock

if os.name == 'posix':
    from density import stage
    from engine import NativeFailure
    from protocol import load


@unittest.skipUnless(os.name == 'posix', 'The native controller imports Linux host APIs')
class StageTests(unittest.IsolatedAsyncioTestCase):
    async def test_timed_commands_do_not_share_the_loop_with_full_receipt_checkpoints(self):
        engine = AsyncMock()
        engine.volume.return_value = 'volume'
        engine.session.return_value = ('session', 20)
        engine.cleanup.return_value = {'result': 'PASS', 'failures': []}
        engine.executing = {}
        events = []
        engine.emit = lambda phase, row: events.append((phase, row))

        async def storage_read(method, route):
            events.append(('storage-read', route))
            return 200, ({'storage': {'poolUsage': {'state': 'complete'}}}
                         if route == '/v1/info' else {'storageUsage': {'state': 'complete'}})

        engine.call.side_effect = storage_read

        async def execute(session, command, *, kind, on_start, timeout_ms):
            row = {'id': str(len(events)), 'session': session, 'kind': kind,
                   'startedAbsoluteNs': time.monotonic_ns(), 'outcome': 'PENDING', 'elapsedNs': None}
            on_start(row)
            await asyncio.sleep(.001)
            row.update(outcome='OK', elapsedNs=time.monotonic_ns() - row['startedAbsoluteNs'], stdout='', stderr='')
            return row

        engine.execute.side_effect = execute

        class Metrics:
            def sample(self, executing=0):
                return {'oomKills': 0, 'hostAvailableBytes': 1024**3, 'monotonicNs': time.monotonic_ns()}

        checkpoints = []
        def publish(value):
            if value is not None:
                checkpoints.append(value)
            self.assertNotEqual(checkpoints[0]['status'], 'RUNNING', 'full receipt write inside timed workload')

        settings = {**load(), 'durationSeconds': .08, 'warmupSeconds': 0,
                    'sampleIntervalSeconds': .01, 'thinkSeconds': [.001, .002]}
        result = await stage(engine, Metrics(), 'base', 1, 0, settings, 400, publish, 'plain')
        self.assertEqual(result['score']['verdict'], 'PASS')
        self.assertTrue(any(phase == 'kernel-sample' for phase, _ in events))
        observed = [index for index, (phase, _) in enumerate(events) if phase == 'storage-read']
        samples = [index for index, (phase, _) in enumerate(events) if phase == 'kernel-sample']
        self.assertEqual(len(observed), 4)
        self.assertLess(observed[1], samples[0])
        self.assertGreater(observed[2], samples[-1])
        self.assertEqual(result['storageAfterCommands']['sessions'][0]['usage']['state'], 'complete')

    async def test_partial_admission_cannot_become_a_smaller_successful_stage(self):
        engine = AsyncMock()
        engine.volume.return_value = 'volume'
        engine.session.side_effect = [('one-session', 20), NativeFailure(429, {'error': {'code': 'SESSION_CAPACITY'}})]
        engine.cleanup.return_value = {'result': 'PASS', 'failures': []}
        engine.executing = {}

        class Metrics:
            def sample(self, executing=0):
                return {'oomKills': 0}

        stages = []
        result = await stage(engine, Metrics(), 'base', 3, 0, load(), 400,
                             lambda value: stages.append(value) if value is not None else None)
        self.assertEqual(result['score']['verdict'], 'FAIL')
        self.assertEqual(result['score']['agentsRequested'], 3)
        self.assertEqual(result['score']['agentsAdmitted'], 1)
        self.assertIn('ADMISSION_INCOMPLETE', result['score']['reasons'])
        self.assertEqual(result['admissionFailure']['code'], 'SESSION_CAPACITY')
        engine.execute.assert_not_awaited()
        engine.cleanup.assert_awaited_once_with(keep_volumes=('base',))
        self.assertIs(stages[0], result)

    async def test_bad_request_is_an_experiment_error_not_a_capacity_result(self):
        engine = AsyncMock()
        engine.volume.side_effect = NativeFailure(400, {'error': {'code': 'INVALID_REQUEST'}})

        class Metrics:
            def sample(self):
                return {'oomKills': 0}

        retained = []
        with self.assertRaises(NativeFailure):
            await stage(engine, Metrics(), 'base', 25, 0, load(), 400, retained.append)
        self.assertEqual(retained[0]['status'], 'SETTING_UP')
        self.assertNotIn('score', retained[0])

    async def test_template_stage_attaches_one_base_without_cloning_volumes(self):
        engine = AsyncMock()
        engine.session.side_effect = [('one-session', 20), NativeFailure(429, {'error': {'code': 'SESSION_CAPACITY'}})]
        engine.cleanup.return_value = {'result': 'PASS', 'failures': []}
        engine.executing = {}
        async def observe(method, route):
            return 200, ({'storage': {'poolUsage': {}}} if route == '/v1/info'
                         else {'templates': [{'id': 'base'}]} if route == '/v1/templates'
                         else {'storageUsage': {'allocatedBytes': 4096}})
        engine.call.side_effect = observe
        class Metrics:
            def sample(self, executing=0):
                return {'oomKills': 0}
        result = await stage(engine, Metrics(), 'base', 3, 0, load(), 400, lambda value: None,
                             workspace_mode='template')
        self.assertEqual(result['score']['verdict'], 'FAIL')
        self.assertEqual(result['score']['agentsAdmitted'], 1)
        engine.volume.assert_not_awaited()
        engine.session.assert_any_await(template='base')
        engine.cleanup.assert_awaited_once_with(keep_templates=('base',))
        self.assertEqual(result['storageAfterCommands']['templates']['templates'], [{'id': 'base'}])


if __name__ == '__main__':
    unittest.main()
