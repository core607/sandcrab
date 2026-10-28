import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class RunContextTests(unittest.TestCase):
    def test_only_first_main_attempt_passes_before_the_paid_job(self):
        for ref, attempt, expected in [('refs/heads/main', '1', 0), ('refs/heads/main', '2', 1),
                                       ('refs/heads/feature', '1', 1), ('', '', 1)]:
            with self.subTest(ref=ref, attempt=attempt), tempfile.TemporaryDirectory() as directory:
                summary = Path(directory) / 'summary.md'
                result = subprocess.run([sys.executable, str(Path(__file__).with_name('check_run.py'))],
                                        env={**os.environ, 'GITHUB_REF': ref, 'GITHUB_RUN_ATTEMPT': attempt,
                                             'GITHUB_STEP_SUMMARY': str(summary)}, capture_output=True, text=True)
                self.assertEqual(expected, result.returncode)
                if expected:
                    self.assertIn('::error::', result.stdout)
                    self.assertIn('No model request was sent by this attempt.', summary.read_text())
                else:
                    self.assertFalse(summary.exists())


if __name__ == '__main__':
    unittest.main()
