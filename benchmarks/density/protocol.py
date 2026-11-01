"""The recorded protocol is the source for workload timing and scoring parameters."""
import json
from pathlib import Path


def load():
    value = json.loads(Path(__file__).with_suffix('.json').read_text())
    if value['schema'] != 1 or value['percentileMethod'] != 'nearest-rank':
        raise ValueError('Unsupported density protocol')
    if (not 0 < value['minimumOkRate'] <= 1 or value['maximumP95Nanoseconds'] < 1
            or value['maximumOomKills'] != 0 or value['observationPollSeconds'] <= 0
            or value['httpTimeoutSeconds'] <= 0
            or not 0 <= value['warmupSeconds'] < value['durationSeconds']
            or not 0 < value['thinkSeconds'][0] <= value['thinkSeconds'][1]):
        raise ValueError('Invalid density protocol bounds')
    return value
