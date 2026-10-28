"""Persist a maximum-request reservation before dispatch; uncertain calls never refund it."""
from datetime import date, datetime, timezone
from decimal import Decimal, ROUND_CEILING
import json
import os
from pathlib import Path
import threading
import uuid

import yaml


class BudgetStopped(RuntimeError):
    pass


class Prices:
    def __init__(self, path: Path = Path(__file__).with_name('pricing.yaml')):
        self.data = yaml.safe_load(path.read_text(encoding='utf-8'))
        if set(self.data) != {'model', 'advertised_release', 'verified_on', 'source', 'context_tokens', 'max_output_tokens', 'usd_per_million'}:
            raise ValueError('Invalid pricing catalog')
        if self.data['model'] != 'deepseek-flash' or self.data['source'] != 'https://api-docs.deepseek.com/quick_start/pricing/':
            raise ValueError('Only the verified DeepSeek Flash catalog is supported')
        self.input_limit = self.data['context_tokens']
        self.output_limit = self.data['max_output_tokens']
        if type(self.input_limit) is not int or self.input_limit != 1100000 or type(self.output_limit) is not int or not 1 <= self.output_limit <= 2048:
            raise ValueError('Invalid model token ceiling')
        rates = self.data['usd_per_million']
        if set(rates) != {'input', 'output'}:
            raise ValueError('Invalid pricing fields')
        self.input_rate, self.output_rate = [Decimal(str(rates[k])) for k in ['input', 'output']]
        if any(not r.is_finite() or r <= 0 for r in [self.input_rate, self.output_rate]):
            raise ValueError('Prices must be finite and positive')

    def require_current(self, today: date | None = None):
        age = ((today or datetime.now(timezone.utc).date()) - date.fromisoformat(self.data['verified_on'])).days
        if not 0 <= age <= 30:
            raise ValueError('Reverify provider prices and context limits before a paid run; the catalog is older than 30 days')

    def micros(self, input_tokens: int, output_tokens: int) -> int:
        if any(type(n) is not int or n < 0 for n in [input_tokens, output_tokens]):
            raise ValueError('Missing or invalid model usage')
        if input_tokens > self.input_limit or output_tokens > self.output_limit:
            raise ValueError('Model usage exceeds the reserved token ceilings')
        return int((input_tokens * self.input_rate + output_tokens * self.output_rate).to_integral_value(rounding=ROUND_CEILING))

    @property
    def reservation(self) -> int:
        return self.micros(self.input_limit, self.output_limit)


def dollars(micros: int) -> str:
    return format(Decimal(micros) / 1000000, '.6f')


class Ledger:
    def __init__(self, path: Path, limit_usd: str, prices: Prices):
        value = Decimal(limit_usd)
        if not value.is_finite() or not 0 < value <= 5 or value * 1000000 != (value * 1000000).to_integral_value():
            raise ValueError('The batch budget must be positive, at most USD 5, and precise to microdollars')
        self.limit = int(value * 1000000)
        if self.limit < prices.reservation:
            raise ValueError('The batch budget must cover one maximum-sized request: USD ' + dollars(prices.reservation))
        self.prices, self.path = prices, path
        self.spent, self.pending, self.stopped = 0, {}, None
        self.lock = threading.Lock()
        # Existing ledgers are never reopened for paid work, including after a crash.
        with path.open('x', encoding='utf-8') as file:
            file.write(json.dumps({'event': 'budget', 'limitMicros': self.limit, 'prices': prices.data,
                                   'costBasis': 'peak-rate upper estimate, all input treated as uncached'}) + '\n')
            file.flush()
            os.fsync(file.fileno())

    def append(self, event: dict):
        event['at'] = datetime.now(timezone.utc).isoformat()
        with self.path.open('a', encoding='utf-8') as file:
            file.write(json.dumps(event, allow_nan=False) + '\n')
            file.flush()
            os.fsync(file.fileno())

    def reserve(self, sample: str, request_sha256: str) -> str:
        with self.lock:
            if self.stopped:
                raise BudgetStopped('Batch stopped: ' + self.stopped)
            amount = self.prices.reservation
            if self.spent + sum(self.pending.values()) + amount > self.limit:
                self.stopped = 'insufficient budget for a maximum-sized request'
                self.append({'event': 'stopped', 'reason': self.stopped})
                raise BudgetStopped('Batch stopped: ' + self.stopped)
            identifier = str(uuid.uuid4())
            self.append({'event': 'reserved', 'requestId': identifier, 'sample': sample,
                         'reservationMicros': amount, 'requestSha256': request_sha256})
            self.pending[identifier] = amount
            return identifier

    def settle(self, identifier: str, input_tokens: int, output_tokens: int):
        charge = self.prices.micros(input_tokens, output_tokens)
        with self.lock:
            if charge > self.pending[identifier]:
                raise ValueError('Charge exceeds reservation')
            self.append({'event': 'settled', 'requestId': identifier, 'inputTokens': input_tokens,
                         'outputTokens': output_tokens, 'upperEstimateMicros': charge})
            del self.pending[identifier]
            self.spent += charge
        return charge

    def uncertain(self, identifier: str, classification: str = 'unknown'):
        with self.lock:
            self.stopped = 'upstream outcome or usage is uncertain; no automatic retry'
            self.append({'event': 'uncertain', 'requestId': identifier, 'reason': self.stopped, 'classification': classification})

    def summary(self) -> dict:
        return {'limitUsd': dollars(self.limit), 'knownUpperEstimateUsd': dollars(self.spent),
                'unresolvedReservationUsd': dollars(sum(self.pending.values())),
                'maximumAccountedUsd': dollars(self.spent + sum(self.pending.values())),
                'unresolvedRequests': len(self.pending), 'stopped': self.stopped, 'prices': self.prices.data}
