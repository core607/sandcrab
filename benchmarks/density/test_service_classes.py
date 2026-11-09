import hashlib
import json
import os
import subprocess
import unittest

if os.name == 'posix':
    from service_classes import build_program, quantiles


@unittest.skipUnless(os.name == 'posix', 'Service-class collector runs on Linux')
class ServiceClassTests(unittest.TestCase):
    def test_build_replay_reports_real_progress_and_the_fixed_input_digest(self):
        program = build_program(1)
        self.assertLess(len(program.encode()), 16384)
        value = json.loads(subprocess.check_output(['python3', '-c', program], text=True, timeout=5))
        source = '\n'.join(f'def function_{index}(value): return value * {index}' for index in range(256))
        self.assertEqual(value['sourceSha256'], hashlib.sha256(source.encode()).hexdigest())
        self.assertEqual(value['compiled'], sum(value['perSecond']))
        self.assertGreater(value['compiled'], 0)
        self.assertGreaterEqual(value['finishedNs'] - value['startedNs'], 1_000_000_000)
        self.assertEqual(quantiles([9, 1, 5, 3]), {'p50Ns': 3, 'p95Ns': 9, 'p99Ns': 9})


if __name__ == '__main__':
    unittest.main()
