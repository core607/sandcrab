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
        result = await stage(engine, Metrics(), 'base', 1, 0, settings, 400, publish)
        self.assertEqual(result['score']['verdict'], 'PASS')
        self.assertTrue(any(phase == 'kernel-sample' for phase, _ in events))

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


if __name__ == '__main__':
    unittest.main()
