"""Actual Inspect tool failures must survive the bounded provider's outbound request."""
import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import httpx
from inspect_ai import Task, eval
from inspect_ai.dataset import Sample
from inspect_ai.model import ChatMessageTool, GenerateConfig, Model
from inspect_ai.solver import generate, use_tools
from inspect_ai.tool import ToolCallError, ToolError, tool

from budget import BudgetStopped, Ledger, Prices
from model import BoundedDeepSeek, REQUEST_BYTES


@tool
def refused_operation():
    async def execute() -> str:
        """Attempt the fixture operation once."""
        raise ToolError('SDK operation refused with HTTP 404 (FILE_NOT_FOUND); no request was replayed')
    return execute


def response(message, finish='stop'):
    return httpx.Response(200, json={'id': 'fixture-response', 'model': 'deepseek-flash',
        'usage': {'prompt_tokens': 100, 'completion_tokens': 10},
        'choices': [{'message': message, 'finish_reason': finish}]})


class ModelMessageTests(unittest.TestCase):
    def test_real_inspect_tool_error_reaches_the_next_provider_request(self):
        wire = []
        def exchange(request):
            wire.append(json.loads(request.content))
            if len(wire) == 1:
                return response({'role': 'assistant', 'content': '', 'tool_calls': [
                    {'id': 'refused-1', 'type': 'function', 'function': {
                        'name': 'refused_operation', 'arguments': '{}'}}]}, 'tool_calls')
            return response({'role': 'assistant', 'content': 'The operation was refused.'})
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'DEEPSEEK_API_KEY': 'fixture-secret'}):
            ledger = Ledger(Path(directory) / 'budget.jsonl', '1', Prices())
            task = Task(dataset=[Sample(input='Attempt the fixture operation, then report its result.')],
                        solver=[use_tools(refused_operation()), generate()],
                        config=GenerateConfig(max_tokens=100, max_retries=0, cache=False), message_limit=8)
            model = Model(BoundedDeepSeek('deepseek-flash', ledger, httpx.MockTransport(exchange)), task.config)
            logs = eval(task, model=model, epochs=1, log_dir=directory, display='none',
                        retry_on_error=0, log_model_api=False)
            self.assertIsNone(logs[0].samples[0].error)
            self.assertEqual(2, len(wire))
            errors = [m for m in logs[0].samples[0].messages if m.role == 'tool' and m.error]
            self.assertEqual(1, len(errors))
            self.assertEqual('', errors[0].text)
            sent = wire[1]['messages'][-1]
            self.assertEqual('refused-1', sent['tool_call_id'])
            self.assertEqual('tool', sent['role'])
            self.assertIn('Tool error (unknown):', sent['content'])
            self.assertIn('HTTP 404 (FILE_NOT_FOUND)', sent['content'])
            self.assertIn('no request was replayed', sent['content'])
            self.assertFalse(ledger.pending)

    def test_partial_output_and_error_are_both_preserved_on_the_wire(self):
        sent = self.send(ChatMessageTool(content='partial output\n', tool_call_id='partial-1',
            error=ToolCallError(type='timeout', message='The operation timed out before completion')))
        self.assertTrue(sent['content'].startswith('partial output\n'))
        self.assertIn('Tool error (timeout): The operation timed out before completion', sent['content'])
        self.assertEqual('partial-1', sent['tool_call_id'])

    def test_successful_tool_content_is_unchanged(self):
        text = '{"state":"succeeded","stdout":"ok"}'
        self.assertEqual(text, self.send(ChatMessageTool(content=text, tool_call_id='ok-1'))['content'])

    def test_error_content_obeys_the_existing_request_bound_before_reservation(self):
        wire = []
        def exchange(request):
            wire.append(request)
            return response({'role': 'assistant', 'content': 'done'})
        message = ChatMessageTool(content='partial output', tool_call_id='large-1',
            error=ToolCallError(type='unknown', message='x' * REQUEST_BYTES))
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'DEEPSEEK_API_KEY': 'fixture-secret'}):
            ledger = Ledger(Path(directory) / 'budget.jsonl', '1', Prices())
            api = BoundedDeepSeek('deepseek-flash', ledger, httpx.MockTransport(exchange))
            with self.assertRaisesRegex(BudgetStopped, '64 KiB transport limit; no request sent'):
                asyncio.run(api.generate([message], [], 'auto', GenerateConfig(max_tokens=100)))
            self.assertEqual([], wire)
            self.assertFalse(ledger.pending)
            self.assertEqual(['budget'], [json.loads(line)['event'] for line in ledger.path.read_text().splitlines()])

    def send(self, message):
        wire = []
        def exchange(request):
            wire.append(json.loads(request.content))
            return response({'role': 'assistant', 'content': 'done'})
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'DEEPSEEK_API_KEY': 'fixture-secret'}), patch('model.store') as store:
            store.return_value.get.return_value = 'fixture:1'
            ledger = Ledger(Path(directory) / 'budget.jsonl', '1', Prices())
            api = BoundedDeepSeek('deepseek-flash', ledger, httpx.MockTransport(exchange))
            asyncio.run(api.generate([message], [], 'auto', GenerateConfig(max_tokens=100)))
            self.assertFalse(ledger.pending)
        self.assertEqual(1, len(wire))
        return wire[0]['messages'][0]


if __name__ == '__main__':
    unittest.main()
