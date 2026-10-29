"""Artifact grading, ambiguous writes, cancellation and framing without host execution."""
import asyncio
from contextlib import contextmanager
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch

from inspect_ai import eval
from inspect_ai.model import ChatMessageAssistant
from inspect_ai.solver import solver
import yaml

import native_http
from report import summarize
from sandcrab import sandcrab_native
from workspace_cases import MAX_ARTIFACT, content, load, same_json, strict_json, submitted
from workspace_client import Rejected, Workspace

CASES = Path(__file__).parent / 'cases' / 'workspace'


def archive(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as target:
        for name, value in entries:
            member = tarfile.TarInfo(name)
            if isinstance(value, bytes):
                member.size = len(value)
                target.addfile(member, io.BytesIO(value))
            elif value is None:
                member.type = tarfile.DIRTYPE
                target.addfile(member)
            else:
                member.type, member.linkname = tarfile.SYMTYPE, value
                target.addfile(member)
    return output.getvalue()


class HttpFraming(unittest.TestCase):
    def exchange(self, response, **options):
        class Stream:
            def makefile(self, mode):
                return io.BytesIO(response)
            def sendall(self, request):
                pass
        @contextmanager
        def connect(*args):
            yield Stream()
        with patch('native_http.connect', connect):
            return native_http.exchange('fixture', 'GET', '/v1/info', b'', **options)

    def test_short_body_is_rejected_even_if_it_is_valid_json(self):
        with self.assertRaisesRegex(ValueError, 'Incomplete response'):
            self.exchange(b'HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n{}')
        self.assertEqual(b'{}', self.exchange(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}')[2])

    def test_ambiguous_and_oversized_responses_are_rejected(self):
        for headers in [b'Content-Length: 2\r\ncontent-length: 2',
                        b'Content-Length: 2\r\nTransfer-Encoding: chunked', b'Connection: close']:
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                self.exchange(b'HTTP/1.1 200 OK\r\n' + headers + b'\r\n\r\n{}')
        with self.assertRaises(native_http.ResponseTooLarge):
            self.exchange(b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n', response_limit=2)


class CasesAndArtifacts(unittest.TestCase):
    def test_cases_load_but_unknown_checks_and_source_replacement_do_not(self):
        cases, digest = load(CASES)
        self.assertEqual(6, len(cases))
        self.assertEqual(64, len(digest))
        for change in [lambda c: c['expected'].update(invented=True),
                       lambda c: c['expected']['steps'][0].update(files={c['expected']['artifacts'][0]: 'replacement'}),
                       lambda c: c['expected']['steps'][0].update(reset=[c['expected']['artifacts'][0]]),
                       lambda c: c['expected']['steps'][0].update(exitCode=True),
                       lambda c: c['expected']['steps'][0].update(exitCode=256),
                       lambda c: c['fixture'].update(files={'../escape': 'x'})]:
            with tempfile.TemporaryDirectory() as directory:
                case = copy.deepcopy(cases[0])
                change(case)
                Path(directory, 'case.yaml').write_text(yaml.safe_dump(case), encoding='utf-8')
                with self.assertRaises(ValueError):
                    load(Path(directory))

    def test_artifact_requires_real_sources_and_unchanged_inputs_without_extracting_links(self):
        case = next(c for c in load(CASES)[0] if c['id'] == 'workspace-range-repair')
        sources = {p: content(v) for p, v in case['reference']['files'].items()}
        inputs = {p: content(case['fixture']['files'][p]) for p in case['expected']['preserve']}
        good = list((sources | inputs).items())
        self.assertEqual(sources, submitted(archive(good + [('unused-link', '/unavailable/host-file')]), case))
        invalid = [good + [good[0]], good + [('../escape', b'x')],
                   [(p, b'changed') for p, v in good], [(p, '/host/source') for p, v in good],
                   [(p, b'x' * 65537) for p, v in good]]
        for entries in invalid:
            with self.subTest(entries=[p for p, v in entries]), self.assertRaises(ValueError):
                submitted(archive(entries), case)

    def test_strict_comparison_rejects_boolean_numbers_duplicate_keys_and_nonfinite_values(self):
        self.assertFalse(same_json(True, 1))
        self.assertFalse(same_json(1.0, 1))
        for raw in ['{"a":1,"a":1}', 'NaN', '{"a":Infinity}']:
            with self.assertRaises(ValueError):
                strict_json(raw)

    def test_draft_files_within_export_byte_limit_do_not_invalidate_required_sources(self):
        case = next(c for c in load(CASES)[0] if c['id'] == 'workspace-range-repair')
        sources = {p: content(v) for p, v in case['reference']['files'].items()}
        inputs = {p: content(case['fixture']['files'][p]) for p in case['expected']['preserve']}
        drafts = [('drafts', None)] + [(f'drafts/attempt-{i}.txt', b'scratch') for i in range(192)]
        raw = archive(drafts + list((sources | inputs).items()))
        self.assertLess(len(raw), MAX_ARTIFACT)
        self.assertEqual(sources, submitted(raw, case))
        with self.assertRaisesRegex(ValueError, 'Preserved input changed'):
            submitted(archive(drafts + list(sources.items()) + [(p, b'changed') for p in inputs]), case)
        with self.assertRaisesRegex(ValueError, 'exceeds 2 MiB'):
            submitted(archive(list((sources | inputs).items()) + [('oversized-draft', b'x' * MAX_ARTIFACT)]), case)


class ConsumerLifecycle(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.client = Workspace('fixture', Path(self.temporary.name), {'observations': []})

    def test_unanswered_create_cannot_be_cleared_by_an_early_404(self):
        with patch.object(self.client, 'api', side_effect=RuntimeError('lost response')):
            with self.assertRaises(RuntimeError):
                self.client.create('volumes', 'owned-id', '/v1/volumes', {}, (202,))
        self.assertEqual(['owned-id'], self.client.state['volumes'])
        with patch.object(self.client, 'api', return_value=(404, {})):
            with self.assertRaisesRegex(RuntimeError, 'before containment'):
                self.client.cleanup()
            self.client.finished('volumes', 'owned-id')
            self.client.cleanup()
        self.assertEqual([], self.client.state['volumes'])

    def test_acknowledged_command_result_survives_housekeeping_failure(self):
        terminal = {'state': 'succeeded', 'result': {'stdout': 'written', 'exitCode': 0}}
        with patch.object(self.client, 'api', return_value=(202, {})) as api, \
                patch.object(self.client, 'poll', return_value=terminal), \
                patch.object(self.client, 'forget', side_effect=RuntimeError('lost forget response')):
            result = self.client.execute('session', 'write once')
        self.assertEqual(terminal['result'], result['result'])
        self.assertEqual([result['retainedRecord']], self.client.state['runs'])
        self.assertEqual(1, api.call_count)

    def test_upload_response_loss_queries_original_identity_without_replaying_bytes(self):
        terminal = {'state': 'succeeded'}
        def request(endpoint, method, route, body=None):
            if route == '/v1/uploads':
                return 201, {'state': 'waiting'}
            return 200, {} if route.endswith('/forget') else terminal
        with patch('native_http.request', side_effect=request) as api, \
                patch('native_http.exchange', side_effect=TimeoutError('private socket path')) as transfer:
            result = self.client.put('session', 'file', b'payload')
        self.assertEqual('succeeded', result['state'])
        self.assertIn('transportRecovery', result)
        self.assertEqual(1, transfer.call_count)
        identity = api.call_args_list[0].args[3]['id']
        self.assertEqual('/v1/uploads/' + identity, api.call_args_list[1].args[2])
        self.assertEqual([], self.client.state['uploads'])

    def test_snapshot_hash_mismatch_is_not_an_export(self):
        with patch('native_http.exchange', return_value=(200, {'etag': '"wrong"'}, b'archive')):
            with self.assertRaisesRegex(RuntimeError, 'Native transport failed'):
                self.client.export()
        self.assertIsNone(self.client.state['artifact'])

    def test_file_readback_can_fail_even_when_stdout_claims_success(self):
        raw = archive([('program.py', b'print("claim")')])
        target = self.client.directory / 'submission.tar'
        target.write_bytes(raw)
        self.client.state['artifact'] = {'name': target.name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        case = {'fixture': {'files': {}}, 'expected': {'artifacts': ['program.py'], 'preserve': [], 'steps': [
            {'argv': ['python3', 'program.py'], 'stdin': '', 'stdoutJson': {'ok': True}, 'filesJson': {'state.json': {'value': 2}}}]}}
        for stored, passed in [(b'{"value":1}', False), (b'{"value":2}', True)]:
            with self.subTest(stored=stored), patch.object(self.client, 'open_session', return_value='grader'), \
                    patch.object(self.client, 'populate'), \
                    patch.object(self.client, 'execute', return_value={'state': 'succeeded', 'result': {'exitCode': 0, 'stdout': '{"ok":true}'}}), \
                    patch.object(self.client, 'capture', return_value=(200, {}, stored)):
                self.assertEqual(passed, not self.client.grade(case))

    def test_cleanup_joins_a_cancelled_thread_before_releasing_resources(self):
        started, release, entered, finished = (threading.Event() for _ in range(4))
        self.client.state['sessions'].append('session')
        def operation(*args):
            started.set()
            if not release.wait(5):
                raise RuntimeError('Test did not release the operation')
            finished.set()
            return {'state': 'succeeded'}
        def close(identity):
            self.assertTrue(finished.is_set())
            self.client.state['sessions'].remove(identity)
        def cleanup():
            entered.set()
            self.client.cleanup()
        async def run():
            work = asyncio.create_task(asyncio.to_thread(self.client.shell, 'command'))
            self.assertTrue(await asyncio.to_thread(started.wait, 3))
            work.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await work
            clean = asyncio.create_task(asyncio.to_thread(cleanup))
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 3))
                self.assertFalse(clean.done())
            finally:
                release.set()
            await asyncio.wait_for(clean, 3)
        with patch.object(self.client, 'execute', side_effect=operation), patch.object(self.client, 'close_session', side_effect=close):
            asyncio.run(run())
        self.assertEqual([], self.client.state['sessions'])
        with self.assertRaises(Rejected):
            self.client.shell('too late')

    def test_expected_domain_error_may_exit_nonzero_but_must_preserve_state(self):
        raw = archive([('program.py', b'# submitted source')])
        target = self.client.directory / 'submission.tar'
        target.write_bytes(raw)
        self.client.state['artifact'] = {'name': target.name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        step = {'argv': ['python3', 'program.py'], 'stdin': '', 'stdoutJson': {'error': 'INSUFFICIENT_STOCK'},
                'exitCode': None, 'unchangedFiles': ['state.json']}
        case = {'fixture': {'files': {}}, 'expected': {'artifacts': ['program.py'], 'preserve': [], 'steps': [step]}}
        unchanged = (200, {}, b'{"A":2}')
        for state, code, after, expected, passed in [
                ('succeeded', 0, unchanged, None, True), ('failed', 1, unchanged, None, True),
                ('failed', 2, unchanged, None, True), ('failed', 1, unchanged, 0, False),
                ('failed', 1, (200, {}, b'{"A":1}'), None, False),
                ('timed_out', 1, unchanged, None, False), ('resource_limit', 1, unchanged, None, False),
                ('output_limit', 1, unchanged, None, False), ('cancelled', 1, unchanged, None, False)]:
            step['exitCode'] = expected
            with self.subTest(state=state, code=code, after=after, expected=expected), \
                    patch.object(self.client, 'open_session', return_value='grader'), patch.object(self.client, 'populate'), \
                    patch.object(self.client, 'execute', return_value={'state': state, 'result': {
                        'exitCode': code, 'stdout': '{"error":"INSUFFICIENT_STOCK"}', 'truncated': False}}), \
                    patch.object(self.client, 'capture', side_effect=[unchanged, after]):
                self.assertEqual(passed, not self.client.grade(case))


class InspectWorkspace(unittest.TestCase):
    def test_final_answer_is_not_a_submission_and_phase_metrics_remain_separate(self):
        @solver
        def claim():
            async def solve(state, generate):
                state.messages.append(ChatMessageAssistant(content='All files are complete and every test passed.'))
                state.completed = True
                return state
            return solve
        def prepare(client, case):
            client.state['observations'].extend([
                {'phase': 'setup', 'method': 'POST', 'path': '/v1/volumes', 'status': 202},
                {'phase': 'agent', 'method': 'PUT', 'path': '/v1/uploads/id/content', 'status': None, 'error': 'TimeoutError'}])
        def cleanup(client):
            client.state['observations'].append({'phase': 'cleanup', 'method': 'POST', 'path': '/v1/volumes/id/delete', 'status': 200})
        with tempfile.TemporaryDirectory() as directory, patch.object(Workspace, 'prepare', prepare), patch.object(Workspace, 'cleanup', cleanup):
            task = sandcrab_native('fixture', baseline=True, suite='workspace', artifacts=directory)
            task.solver = claim()
            logs = eval(task, model='mockllm/model', limit=1, epochs=2, max_samples=1,
                        log_dir=directory, display='none', log_model_api=False, retry_on_error=0)
            attempts = next(iter(summarize(logs[0])['cases'].values()))
            self.assertEqual(2, len(attempts))
            for attempt in attempts:
                self.assertFalse(attempt['passed'])
                self.assertEqual(['No artifact was exported'], attempt['failedChecks'])
                self.assertIsNone(attempt['error'])
                self.assertEqual('PASS', attempt['cleanup'])
                self.assertEqual(1, attempt['apiCalls'])
                self.assertEqual(1, attempt['transportFailures'])
                self.assertEqual({'setup': 1, 'grading': 0, 'cleanup': 1}, attempt['harnessApiCalls'])


if __name__ == '__main__':
    unittest.main()
