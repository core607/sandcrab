"""Check case rejection, independent grading, and complete failed-attempt reporting offline."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from inspect_ai import eval

from cases import load
from report import summarize
from sandcrab import CASES, grade, sandcrab_native


class CasesAndGrades(unittest.TestCase):
    def test_all_cases_load_and_unknown_checks_fail(self):
        cases, digest = load(CASES)
        self.assertEqual(10, len(cases))
        self.assertEqual(64, len(digest))
        with tempfile.TemporaryDirectory() as directory:
            case = (CASES / 'arithmetic.yaml').read_text(encoding='utf-8').replace('"exitCode":0', '"invented":0')
            Path(directory, 'case.yaml').write_text(case, encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'unknown expected-state'):
                load(Path(directory))

    def test_agent_claim_cannot_replace_readback(self):
        self.assertTrue(grade({'state': 'succeeded', 'stdout': '17\n'}, (404, {}), [], 'run-id'))
        good = (200, {'state': 'succeeded', 'result': {'stdout': '17\n'}})
        self.assertFalse(grade({'state': 'succeeded', 'stdout': '17\n'}, good, [], 'run-id'))
        wrong = copy.deepcopy(good)
        wrong[1]['result']['stdout'] = 'I succeeded'
        self.assertIn('stdout', grade({'state': 'succeeded', 'stdout': '17\n'}, wrong, [], 'run-id'))

    def test_forget_requires_observed_terminal_state_and_absent_record(self):
        expected = {'state': 'succeeded', 'stdout': 'saved', 'forgotten': True}
        missing = (404, {'error': {'code': 'RUN_NOT_FOUND'}})
        self.assertTrue(grade(expected, missing, [], 'id'))
        observed = [{'method': 'GET', 'path': '/v1/runs/id', 'status': 200,
                     'response': {'state': 'succeeded', 'result': {'stdout': 'saved'}}}]
        self.assertFalse(grade(expected, missing, observed, 'id'))
        self.assertTrue(grade(expected, (200, observed[0]['response']), observed, 'id'))

    def test_refusal_and_replay_need_daemon_evidence(self):
        expected = {'state': 'succeeded', 'errors': ['ID_CONFLICT'], 'replay': True}
        actual = (200, {'id': 'id', 'state': 'succeeded'})
        self.assertEqual(2, len(grade(expected, actual, [], 'id')))
        observations = [{'method': 'POST', 'path': '/v1/runs', 'status': 200, 'response': actual[1]},
                        {'method': 'POST', 'path': '/v1/runs', 'status': 409, 'response': {'error': {'code': 'ID_CONFLICT'}}}]
        self.assertFalse(grade(expected, actual, observations, 'id'))

    def test_recovery_requires_refusal_before_successful_admission(self):
        expected = {'state': 'succeeded', 'refusalBeforeRun': 'PROFILE_NOT_FOUND'}
        result = {'id': 'id', 'state': 'succeeded'}
        admission = {'method': 'POST', 'path': '/v1/runs', 'status': 202, 'response': result}
        refusal = {'method': 'POST', 'path': '/v1/runs', 'status': 400, 'response': {'error': {'code': 'PROFILE_NOT_FOUND'}}}
        self.assertFalse(grade(expected, (200, result), [refusal, admission], 'id'))
        self.assertTrue(grade(expected, (200, result), [admission, refusal], 'id'))

    def test_real_inspect_retains_infrastructure_failures_without_model_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            task = sandcrab_native(str(Path(directory) / 'missing.sock'), baseline=True)
            logs = eval(task, model='mockllm/model', limit=1, epochs=3, max_samples=1,
                        log_dir=directory, display='none', log_model_api=False, retry_on_error=0)
            result = summarize(logs[0])
            attempts = next(iter(result['cases'].values()))
            self.assertEqual(3, len(attempts))
            self.assertTrue(all(not a['passed'] and a['error'] for a in attempts))
            self.assertTrue(all(a['inputTokens'] == a['outputTokens'] == 0 for a in attempts))

    def test_inspect_tool_transcript_and_cleanup_failure_are_observable(self):
        cleanup_status = 503
        def exchange(endpoint, method, route, body=None):
            if route == '/v1/info':
                return 200, {'serverId': '00000000-0000-4000-8000-000000000001'}
            if route.endswith('/forget'):
                return cleanup_status, {'error': {'code': 'STOPPING'}} if cleanup_status != 200 else {'forgotten': True}
            return 200, {'id': (body or {}).get('id', route.rsplit('/', 1)[-1]), 'state': 'succeeded',
                         'result': {'stdout': '17\n', 'exitCode': 0}}

        for cleanup_status in [503, 200]:
            with self.subTest(status=cleanup_status), tempfile.TemporaryDirectory() as directory, patch('sandcrab.request', side_effect=exchange):
                logs = eval(sandcrab_native('fixture', baseline=True), model='mockllm/model', sample_id='arithmetic',
                            epochs=1, max_samples=1, log_dir=directory, display='none', retry_on_error=0)
                attempt = summarize(logs[0])['cases']['arithmetic'][0]
                self.assertEqual(3, attempt['toolCalls'])
                self.assertEqual(3, attempt['apiCalls'])
                self.assertEqual(cleanup_status == 200, attempt['passed'])
                self.assertEqual('PASS' if cleanup_status == 200 else 'PENDING', attempt['cleanup'])
                self.assertEqual('C', next(iter(logs[0].samples[0].scores.values())).value)


if __name__ == '__main__':
    unittest.main()
