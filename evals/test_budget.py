"""No-network tests for pre-dispatch accounting, uncertain calls and the real Inspect loop."""
import asyncio
from datetime import date, timedelta
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import httpx
from inspect_ai import eval
from inspect_ai.model import GenerateConfig, Model, ChatMessageUser

from budget import BudgetStopped, Ledger, Prices
from model import BoundedDeepSeek
from report import summarize
from sandcrab import sandcrab_native


class BudgetTests(unittest.TestCase):
    def test_reservation_is_written_before_dispatch_and_cannot_overdraw(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'budget.jsonl'
            ledger = Ledger(path, '.50', Prices())
            identifier = ledger.reserve('case:1', 'a' * 64)
            self.assertEqual('reserved', json.loads(path.read_text().splitlines()[-1])['event'])
            with self.assertRaises(BudgetStopped):
                ledger.reserve('case:2', 'b' * 64)
            self.assertEqual(332458, sum(ledger.pending.values()))
            ledger.uncertain(identifier)
            self.assertEqual('0.332458', ledger.summary()['maximumAccountedUsd'])
            with self.assertRaises(FileExistsError):
                Ledger(path, '.50', Prices())

    def test_valid_usage_releases_only_unused_reservation(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = Ledger(Path(directory) / 'budget.jsonl', '.50', Prices())
            identifier = ledger.reserve('one', 'a' * 64)
            self.assertEqual(3012, ledger.settle(identifier, 10000, 10))
            self.assertFalse(ledger.pending)
            ledger.reserve('two', 'b' * 64)
            self.assertLessEqual(ledger.spent + sum(ledger.pending.values()), ledger.limit)
            with self.assertRaises(ValueError):
                ledger.prices.micros(True, 1)
            with self.assertRaises(ValueError):
                ledger.prices.micros(1100001, 1)

    def test_invalid_budgets_and_stale_prices_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            for value in ['NaN', 'Infinity', '0', '-1', '6', '.000001', '1.0000001']:
                with self.subTest(value=value), self.assertRaises(ValueError):
                    Ledger(Path(directory) / 'budget.jsonl', value, Prices())
        prices = Prices()
        verified = date.fromisoformat(prices.data['verified_on'])
        prices.require_current(verified + timedelta(days=30))
        with self.assertRaises(ValueError):
            prices.require_current(verified + timedelta(days=31))

    def test_uncertain_transport_is_not_retried_or_refunded(self):
        calls = []
        def fail(request):
            calls.append(request)
            raise httpx.ReadTimeout('private-provider-detail-and-secret')
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'DEEPSEEK_API_KEY': 'fixture-secret'}), patch('model.store') as store:
            store.return_value.get.return_value = 'case:1'
            ledger = Ledger(Path(directory) / 'budget.jsonl', '1', Prices())
            api = BoundedDeepSeek('deepseek-flash', ledger, httpx.MockTransport(fail))
            for _ in range(2):
                with self.assertRaises(BudgetStopped) as caught:
                    asyncio.run(api.generate([ChatMessageUser(content='hello')], [], 'auto', GenerateConfig(max_tokens=10)))
                self.assertNotIn('fixture-secret', str(caught.exception))
                self.assertNotIn('private-provider', str(caught.exception))
            self.assertEqual(1, len(calls))
            self.assertEqual(1, len(ledger.pending))
            self.assertNotIn('fixture-secret', ledger.path.read_text())

    def test_model_response_and_usage_must_fit_reserved_contract(self):
        for bad in [{'usage': {}}, {'usage': {'prompt_tokens': 1, 'completion_tokens': 2049}},
                    {'model': 'another-model'}, {'choices': []}]:
            response = {'id': 'fixture-response', 'model': 'deepseek-flash',
                        'usage': {'prompt_tokens': 100, 'completion_tokens': 10},
                        'choices': [{'message': {'role': 'assistant', 'content': 'done'}, 'finish_reason': 'stop'}], **bad}
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'DEEPSEEK_API_KEY': 'fixture-secret'}), patch('model.store') as store:
                store.return_value.get.return_value = 'case:1'
                ledger = Ledger(Path(directory) / 'budget.jsonl', '1', Prices())
                api = BoundedDeepSeek('deepseek-flash', ledger, httpx.MockTransport(lambda request: httpx.Response(200, json=response)))
                with self.assertRaises(BudgetStopped):
                    asyncio.run(api.generate([ChatMessageUser(content='hello')], [], 'auto', GenerateConfig(max_tokens=100)))
                self.assertEqual(1, len(ledger.pending))

    def test_inspect_cannot_retry_an_uncertain_call_across_epochs(self):
        calls = []
        def redirect(request):
            calls.append(request)
            return httpx.Response(302, headers={'Location': 'https://unapproved.invalid/'}, content=b'fixture-secret')
        def native(endpoint, method, path, body=None):
            return 404, {'error': {'code': 'RUN_NOT_FOUND'}}
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'DEEPSEEK_API_KEY': 'fixture-secret'}), patch('sandcrab.request', side_effect=native):
            ledger = Ledger(Path(directory) / 'budget.jsonl', '1', Prices())
            task = sandcrab_native('fixture')
            model = Model(BoundedDeepSeek('deepseek-flash', ledger, httpx.MockTransport(redirect)), task.config)
            logs = eval(task, model=model, sample_id='arithmetic', epochs=3, max_samples=1,
                        log_dir=directory, display='none', retry_on_error=0, log_model_api=False)
            attempts = summarize(logs[0])['cases']['arithmetic']
            self.assertEqual(3, len(attempts))
            self.assertTrue(all(a['error'] and not a['passed'] for a in attempts))
            self.assertEqual(1, len(calls))
            self.assertEqual('api.deepseek.com', calls[0].url.host)
            self.assertEqual('0.332458', ledger.summary()['unresolvedReservationUsd'])
            self.assertIn('http_302', ledger.path.read_text())
            self.assertNotIn('fixture-secret', ledger.path.read_text())

    def test_inspect_generation_executes_tools_and_records_cached_input(self):
        wire = []
        def exchange(request):
            payload = json.loads(request.content)
            wire.append(payload)
            self.assertEqual('disabled', payload['thinking']['type'])
            self.assertEqual('Bearer fixture-secret', request.headers['authorization'])
            if len(wire) == 1:
                message = {'role': 'assistant', 'content': '', 'tool_calls': [{'id': 'tool-1', 'type': 'function',
                           'function': {'name': 'native_api', 'arguments': json.dumps({'method': 'GET', 'path': '/v1/info'})}}]}
                finish = 'tool_calls'
            else:
                self.assertEqual('tool', payload['messages'][-1]['role'])
                message, finish = {'role': 'assistant', 'content': 'I claim success without running the command'}, 'stop'
            return httpx.Response(200, json={'id': 'fixture-response', 'model': 'deepseek-flash',
                'usage': {'prompt_tokens': 100, 'prompt_cache_hit_tokens': 80, 'completion_tokens': 10},
                'choices': [{'message': message, 'finish_reason': finish}]})
        def native(endpoint, method, path, body=None):
            if path == '/v1/info':
                return 200, {'serverId': 'fixture'}
            return 404, {'error': {'code': 'RUN_NOT_FOUND'}}
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'DEEPSEEK_API_KEY': 'fixture-secret'}), patch('sandcrab.request', side_effect=native):
            root = Path(directory)
            ledger = Ledger(root / 'budget.jsonl', '1', Prices())
            task = sandcrab_native('fixture')
            model = Model(BoundedDeepSeek('deepseek-flash', ledger, httpx.MockTransport(exchange)), task.config)
            logs = eval(task, model=model, sample_id='arithmetic', epochs=1, max_samples=1,
                        log_dir=directory, log_format='json', display='none', retry_on_error=0, log_model_api=False)
            sample = summarize(logs[0])['cases']['arithmetic'][0]
            self.assertEqual(2, len(wire))
            self.assertEqual(200, sample['inputTokens'])
            self.assertEqual(20, sample['outputTokens'])
            self.assertEqual(1, sample['toolCalls'])
            self.assertFalse(sample['passed'])
            self.assertFalse(ledger.pending)
            self.assertEqual(84, ledger.spent)
            self.assertNotIn('fixture-secret', Path(logs[0].location).read_text(encoding='utf-8'))

    def test_unbudgeted_inspect_entry_fails_before_model_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            logs = eval(sandcrab_native('unused'), model='mockllm/model', sample_id='arithmetic', epochs=1,
                        log_dir=directory, display='none', retry_on_error=0, log_model_api=False)
            sample = logs[0].samples[0]
            self.assertIn('require the budgeted runner', sample.error.message)
            self.assertFalse(sample.model_usage)


if __name__ == '__main__':
    unittest.main()
