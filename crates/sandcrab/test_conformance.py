"""The shared controller must preserve failed attempts and fail on uncertain cleanup."""
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sandcrab_conformance.runner import execute_fixture, run_suites, single


class Fixture:
    def __init__(self, root, *, test_failure=False, cleanup_failure=False, confirm=True):
        self.report = root / 'case.json'
        self.receipt = {'result': 'NOT_RUN', 'cleanup': 'NOT_RUN', 'checks': []}
        self.order = []
        self.test_failure, self.cleanup_failure, self.confirm = test_failure, cleanup_failure, confirm

    def setup(self):
        self.order.append('setup')

    def tests(self):
        self.order.append('test')
        if self.test_failure:
            raise ValueError('original test failure')

    def cleanup(self):
        self.order.append('cleanup')
        if self.cleanup_failure:
            raise OSError('cleanup failure')
        if self.confirm:
            self.receipt['cleanup'] = 'PASS'

    def save(self):
        self.order.append('save')
        self.report.write_text(json.dumps(self.receipt), encoding='utf-8')


class ConformanceLifecycle(unittest.TestCase):
    def test_failure_keeps_its_cause_and_runs_cleanup_before_saving(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory), test_failure=True)
            with self.assertRaisesRegex(ValueError, 'original test failure'):
                execute_fixture('queue', fixture, Path(directory))
            self.assertEqual(fixture.order, ['setup', 'test', 'cleanup', 'save'])
            receipt = json.loads(fixture.report.read_text())
            self.assertEqual((receipt['result'], receipt['cleanup']), ('FAIL', 'PASS'))
            self.assertEqual(receipt['failureType'], 'ValueError')

    def test_successful_test_body_cannot_hide_failed_or_unconfirmed_cleanup(self):
        for options in ({'cleanup_failure': True}, {'confirm': False}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(Path(directory), **options)
                with self.assertRaises((OSError, RuntimeError)):
                    execute_fixture('queue', fixture, Path(directory))
                receipt = json.loads(fixture.report.read_text())
                self.assertEqual((receipt['result'], receipt['cleanup']), ('FAIL', 'FAIL'))
                self.assertEqual(fixture.order.count('cleanup'), 1)

    def test_secondary_cleanup_failure_does_not_replace_the_original_test_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory), test_failure=True, cleanup_failure=True)
            with self.assertRaisesRegex(ValueError, 'original test failure'):
                execute_fixture('queue', fixture, Path(directory))
            self.assertEqual(fixture.receipt['failureType'], 'ValueError')
            self.assertEqual(fixture.receipt['cleanupFailureType'], 'OSError')
            diagnostic = fixture.report.with_suffix('.diagnostic.txt').read_text()
            self.assertIn('original test failure', diagnostic)
            self.assertIn('cleanup failure', diagnostic)

    def test_failed_dispatch_keeps_the_attempt_even_if_cleanup_reports_success(self):
        for raw in (None, {'result': 'PASS', 'cleanup': 'PASS', 'checks': ['observed']}):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                args = SimpleNamespace(output=root / 'artifacts', binary=Path(__file__))
                def fail(name, args, report):
                    pending = json.loads((args.output / 'summary.json').read_text())
                    self.assertEqual(pending['suites'], [{'name': name, 'result': 'RUNNING'}])
                    if raw is not None:
                        report.write_text(json.dumps(raw), encoding='utf-8')
                    raise subprocess.TimeoutExpired('fixture', 360)
                with patch('sandcrab_conformance.runner.validate'), patch('sandcrab_conformance.runner.run_case', fail):
                    with self.assertRaises(subprocess.TimeoutExpired):
                        run_suites(args, ['queue', 'sdk'])
                summary = json.loads((args.output / 'summary.json').read_text())
                self.assertEqual((summary['result'], summary['failureType']), ('FAIL', 'TimeoutExpired'))
                row, = summary['suites']
                self.assertEqual((row['name'], row['result']), ('queue', 'FAIL'))
                self.assertEqual(row['cleanup'], 'PASS' if raw else 'UNCONFIRMED')
                self.assertEqual(row['checks'], 1 if raw else 0)

    def test_existing_receipt_is_refused_before_creating_a_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / 'prior.json'
            report.write_text('retained attempt')
            with patch('sandcrab_conformance.runner.create_fixture') as create:
                with self.assertRaisesRegex(RuntimeError, 'Preserve earlier'):
                    single('queue', SimpleNamespace(), report)
                create.assert_not_called()
            self.assertEqual(report.read_text(), 'retained attempt')


if __name__ == '__main__':
    unittest.main()
