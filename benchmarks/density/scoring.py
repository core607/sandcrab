"""Stage scoring includes every judged attempt and compares unrounded durations."""
from collections import Counter
from fractions import Fraction
import math

from protocol import load


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def summarize(attempts, warmup_ns, duration_ns, oom_kills, admitted, requested):
    settings = load()
    if not 0 <= warmup_ns < duration_ns or not 0 <= admitted <= requested or requested < 1:
        raise ValueError('Invalid stage dimensions')
    if any(type(row['startedNs']) is not int or row['startedNs'] < 0
           or type(row['elapsedNs']) is not int or row['elapsedNs'] < 0 for row in attempts):
        raise ValueError('Invalid observation timestamps')
    judged = [row for row in attempts if warmup_ns <= row['startedNs'] < duration_ns]
    outcomes = Counter(row['outcome'] for row in judged)
    latencies = [row['elapsedNs'] for row in judged]
    successes = outcomes['OK']
    p95 = percentile(latencies, .95)
    failures = []
    if admitted != requested:
        failures.append('ADMISSION_INCOMPLETE')
    if not judged:
        failures.append('NO_JUDGED_ATTEMPTS')
    else:
        minimum = Fraction(str(settings['minimumOkRate']))
        if successes * minimum.denominator < len(judged) * minimum.numerator:
            failures.append('OK_RATE')
    if p95 is not None and p95 > settings['maximumP95Nanoseconds']:
        failures.append('P95')
    if type(oom_kills) is not int or oom_kills < 0:
        failures.append('OOM_OBSERVATION_MISSING')
    elif oom_kills:
        failures.append('OOM_KILL')
    return {'verdict': 'FAIL' if failures else 'PASS', 'reasons': failures,
            'agentsRequested': requested, 'agentsAdmitted': admitted, 'judgedAttempts': len(judged),
            'okRate': successes / len(judged) if judged else None, 'outcomes': dict(outcomes),
            'latencyNs': {name: percentile(latencies, fraction) for name, fraction in
                          (('p50', .5), ('p95', .95), ('p99', .99))},
            'percentileMethod': settings['percentileMethod'], 'oomKills': oom_kills,
            'commandMix': dict(Counter(row['kind'] for row in judged)),
            'refusalsByCode': dict(Counter(row['code'] for row in judged if row['outcome'] == 'REFUSED'))}
