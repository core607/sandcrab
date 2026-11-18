"""Exercise Luna's actual tool-calling payload, credential boundary and accounting."""
import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import httpx
from inspect_ai.model import ChatMessageUser, GenerateConfig
from inspect_ai.tool import ToolInfo, ToolParams

from budget import Ledger, Prices
from model import BoundedOpenAI
from providers import take_model_key


class OpenAIModelTests(unittest.TestCase):
    def test_controller_removes_both_keys_before_starting_fixture_processes(self):
        env = {'OPENAI_API_KEY': 'openai-fixture', 'DEEPSEEK_API_KEY': 'deepseek-fixture', 'LANG': 'C'}
        self.assertEqual(take_model_key('gpt-6-luna', env), 'openai-fixture')
        self.assertEqual(env, {'LANG': 'C'})
        env = {'DEEPSEEK_API_KEY': 'deepseek-fixture'}
        self.assertEqual(take_model_key('gpt-6-luna', env), '')
        self.assertEqual(env, {})

    def test_luna_tools_use_openai_standard_pricing_and_one_budgeted_dispatch(self):
        requests = []
        def exchange(request):
            requests.append(request)
            return httpx.Response(200, json={
                'model': 'gpt-6-luna', 'service_tier': 'default',
                'usage': {'prompt_tokens': 100, 'prompt_tokens_details': {'cached_tokens': 20}, 'completion_tokens': 8},
                'choices': [{'finish_reason': 'tool_calls', 'message': {'role': 'assistant', 'content': None,
                    'tool_calls': [{'id': 'call-1', 'type': 'function', 'function': {'name': 'read', 'arguments': '{}'}}]}}]})
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
                'OPENAI_API_KEY': 'openai-fixture', 'DEEPSEEK_API_KEY': 'deepseek-fixture'}), patch('model.store') as state:
            state.return_value.get.return_value = 'sample'
            prices = Prices(model='gpt-6-luna')
            ledger = Ledger(Path(directory) / 'budget.jsonl', '1', prices)
            provider = BoundedOpenAI('gpt-6-luna', ledger, httpx.MockTransport(exchange))
            tool = ToolInfo(name='read', description='Read a test file', parameters=ToolParams(type='object', properties={}))
            answer = asyncio.run(provider.generate([ChatMessageUser(content='Read the file.')],
                                                   [tool], 'auto', GenerateConfig(max_tokens=100)))
            self.assertEqual(1, len(requests))
            request = requests[0]
            self.assertEqual(str(request.url), 'https://api.openai.com/v1/chat/completions')
            self.assertEqual(request.headers['authorization'], 'Bearer openai-fixture')
            body = json.loads(request.content)
            self.assertEqual((body['reasoning_effort'], body['service_tier'], body['max_completion_tokens']), ('none', 'default', 100))
            self.assertFalse(body['store'])
            self.assertFalse({'thinking', 'temperature', 'max_tokens'} & body.keys())
            self.assertEqual(body['tools'][0]['function']['name'], 'read')
            self.assertEqual(answer.choices[0].message.tool_calls[0].function, 'read')
            self.assertEqual(answer.usage.input_tokens_cache_read, 20)
            self.assertEqual(ledger.spent, prices.micros(100, 8))
            self.assertFalse(ledger.pending)
            self.assertTrue(provider.accepts_response({'model': 'gpt-6-luna-2026-09-21', 'service_tier': 'default'}))
            self.assertFalse(provider.accepts_response({'model': 'gpt-6-astra'}))
            self.assertFalse(provider.accepts_response({'model': 'gpt-6-luna', 'service_tier': 'priority'}))
            self.assertNotIn('fixture', ledger.path.read_text())
