import unittest

from scoring import summarize


def attempt(index, *, outcome='OK', elapsed=100_000_000, started=1_000_000_000):
    return {'startedNs': started + index, 'elapsedNs': elapsed, 'outcome': outcome,
            'kind': 'rg', 'code': 'SESSION_CAPACITY' if outcome == 'REFUSED' else None}


class ScoringTests(unittest.TestCase):
    def score(self, rows, **changes):
        return summarize(rows, **{'warmup_ns': 0, 'duration_ns': 10_000_000_000,
                                  'oom_kills': 0, 'admitted': 25, 'requested': 25, **changes})

    def test_refusals_stay_in_the_denominator_and_keep_their_code(self):
        rows = [attempt(i) for i in range(98)] + [attempt(i, outcome='REFUSED') for i in (98, 99)]
        result = self.score(rows)
        self.assertEqual(result['verdict'], 'FAIL')
        self.assertEqual(result['okRate'], .98)
        self.assertEqual(result['refusalsByCode'], {'SESSION_CAPACITY': 2})
        rows[-1] = attempt(99)
        self.assertEqual(self.score(rows)['verdict'], 'PASS')

    def test_one_second_is_inclusive_but_rounding_cannot_hide_a_failure(self):
        self.assertEqual(self.score([attempt(0, elapsed=1_000_000_000)])['verdict'], 'PASS')
        self.assertEqual(self.score([attempt(0, elapsed=1_000_000_001)])['reasons'], ['P95'])

    def test_slow_tail_and_transport_failures_are_not_dropped(self):
        rows = [attempt(i) for i in range(94)] + [attempt(i, outcome='TRANSPORT', elapsed=30_000_000_000)
                                                for i in range(94, 100)]
        result = self.score(rows)
        self.assertEqual(result['latencyNs']['p95'], 30_000_000_000)
        self.assertEqual(result['reasons'], ['OK_RATE', 'P95'])

    def test_judging_uses_submission_time_and_keeps_late_completions(self):
        rows = [attempt(0, started=0, elapsed=40_000_000_000),
                attempt(1, started=2_000_000_000, elapsed=20_000_000_000),
                attempt(2, started=10_000_000_000)]
        result = self.score(rows, warmup_ns=1_000_000_000)
        self.assertEqual(result['judgedAttempts'], 1)
        self.assertEqual(result['latencyNs']['p95'], 20_000_000_000)

    def test_missing_oom_observation_incomplete_admission_and_empty_windows_fail(self):
        self.assertEqual(self.score([attempt(0)], oom_kills=None)['reasons'], ['OOM_OBSERVATION_MISSING'])
        self.assertEqual(self.score([attempt(0)], oom_kills=1)['reasons'], ['OOM_KILL'])
        self.assertEqual(self.score([attempt(0)], admitted=24)['reasons'], ['ADMISSION_INCOMPLETE'])
        self.assertEqual(self.score([])['reasons'], ['NO_JUDGED_ATTEMPTS'])

    def test_invalid_raw_observations_cannot_be_scored_as_fast_successes(self):
        for row in [attempt(0, elapsed=-1), attempt(0, elapsed=0.5), attempt(0, started=-1)]:
            with self.assertRaises(ValueError):
                self.score([row])


if __name__ == '__main__':
    unittest.main()
