"""Inspect task and independent readback grader for the native Sandcrab API."""
import asyncio
import json
from pathlib import Path
import time
import uuid

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.model import ChatMessageAssistant, ChatMessageUser, GenerateConfig, execute_tools, get_model
from inspect_ai.scorer import CORRECT, INCORRECT, Score, accuracy, scorer
from inspect_ai.solver import generate, solver
from inspect_ai.tool import ToolCall, ToolError, tool
from inspect_ai.util import store

from cases import load
from budget import Ledger
from native_http import request, wait

CASES = Path(__file__).parent / 'cases' / 'sandcrab'


def grade(expected: dict, readback: tuple[int, dict], observations: list[dict], run_id: str) -> list[str]:
    """Only daemon responses and independent final readback can satisfy a check."""
    status, actual = readback
    failures = []
    if expected.get('forgotten'):
        if status != 404 or actual.get('error', {}).get('code') != 'RUN_NOT_FOUND':
            failures.append('record was not forgotten')
        terminal_reads = [o['response'] for o in observations
                          if o['method'] == 'GET' and o['path'] == '/v1/runs/' + run_id
                          and o['status'] == 200 and o['response'].get('state') not in {'running', 'closing'}]
        actual = terminal_reads[-1] if terminal_reads else {}
    elif status != 200:
        failures.append('terminal record missing')
    if actual.get('state') != expected['state']:
        failures.append('state')
    result = actual.get('result') or {}
    for key in ['stdout', 'stderr', 'exitCode', 'truncated']:
        if key in expected and result.get(key) != expected[key]:
            failures.append(key)
    errors = {o['response'].get('error', {}).get('code') for o in observations if o['status'] >= 400}
    for code in expected.get('errors', []):
        if code not in errors:
            failures.append('missing refusal ' + code)
    if 'refusalBeforeRun' in expected:
        refusals = [i for i, o in enumerate(observations) if o['status'] >= 400
                    and o['response'].get('error', {}).get('code') == expected['refusalBeforeRun']]
        admissions = [i for i, o in enumerate(observations) if o['method'] == 'POST' and o['path'] == '/v1/runs'
                      and o['status'] == 202 and o['response'].get('id') == run_id]
        if not refusals or not admissions or min(refusals) >= min(admissions):
            failures.append('refusal did not precede successful admission')
    if expected.get('replay') and not any(o['method'] == 'POST' and o['path'] == '/v1/runs'
                                        and o['status'] == 200 and o['response'].get('id') == run_id
                                        for o in observations):
        failures.append('missing idempotent replay')
    return failures


@tool
def native_api(endpoint: str, run_id: str):
    async def execute(method: str, path: str, body: str = '', wait_for_terminal: bool = False) -> str:
        """Call the Sandcrab native API. Read GET /v1/info or /v1/openapi to discover it.

        Args:
            method: GET or POST.
            path: /v1/info, /v1/openapi, /v1/runs, or a path under your assigned run ID.
            body: A JSON object for POST; empty for GET.
            wait_for_terminal: For GET of your run, poll for at most 15 seconds.
        """
        allowed = ['/v1/info', '/v1/openapi', '/v1/runs', '/v1/runs/' + run_id,
                   '/v1/runs/' + run_id + '/cancel', '/v1/runs/' + run_id + '/forget']
        if path not in allowed or method not in {'GET', 'POST'}:
            raise ToolError('Only the native API and this sample\'s run ID are available')
        try:
            value = json.loads(body) if body else None
        except ValueError as error:
            raise ToolError('body must be a JSON object') from error
        if value is not None and not isinstance(value, dict):
            raise ToolError('body must be a JSON object')
        if method == 'POST' and path == '/v1/runs' and (value or {}).get('id') != run_id:
            raise ToolError('Use the assigned run ID')
        deadline = time.monotonic() + 15
        while True:
            status, result = await asyncio.to_thread(request, endpoint, method, path, value)
            store().get('native_observations').append({'method': method, 'path': path, 'status': status, 'response': result})
            if not (wait_for_terminal and method == 'GET' and path == '/v1/runs/' + run_id
                    and status == 200 and result.get('state') == 'running' and time.monotonic() < deadline):
                return json.dumps({'status': status, 'body': result})
            await asyncio.sleep(.05)
    return execute


@solver
def prepare(endpoint: str, baseline: bool):
    async def solve(state, generate):
        if not baseline and not isinstance(getattr(get_model().api, 'ledger', None), Ledger):
            raise ValueError('Model tasks require the budgeted runner; direct unbudgeted Inspect generation is disabled')
        run_id = str(uuid.uuid4())
        store().set('run_id', run_id)
        store().set('native_observations', [])
        store().set('cleanup', 'PENDING')
        store().set('sample_key', f'{state.sample_id}:{state.epoch}')
        state.messages.append(ChatMessageUser(content=f'Your assigned run ID is {run_id}. Use it for all requests. '
                                                     'Leave the result record for verification unless the task explicitly asks you to forget it.'))
        state.tools = [native_api(endpoint, run_id)]
        return state
    return solve


@solver
def scripted(endpoint: str):
    """Wiring baseline. This solver contains no model call and is labelled as scripted."""
    async def solve(state, generate):
        async def api(method, path, body='', wait_for_terminal=False):
            state.messages.append(ChatMessageAssistant(content='Scripted baseline action', tool_calls=[
                ToolCall(id=str(uuid.uuid4()), function='native_api',
                         arguments={'method': method, 'path': path, 'body': body, 'wait_for_terminal': wait_for_terminal})]))
            response = await execute_tools(state.messages, state.tools)
            state.messages.extend(response.messages)
            message = response.messages[-1]
            if getattr(message, 'error', None):
                raise RuntimeError('Native preflight tool failed: ' + message.error.message)
            return message.text

        fixture = state.metadata['fixture']
        run_id = store().get('run_id')
        info = json.loads(await api('GET', '/v1/info'))['body']
        body = {k: v for k, v in fixture.items() if k != 'exercise'}
        body.update(id=run_id, serverId=info['serverId'], profile='python')
        exercise = fixture.get('exercise', 'run')
        if exercise == 'profile-recovery':
            await api('POST', '/v1/runs', json.dumps({**body, 'profile': 'missing'}))
        await api('POST', '/v1/runs', json.dumps(body))
        if exercise == 'replay':
            await api('POST', '/v1/runs', json.dumps(body))
            await api('POST', '/v1/runs', json.dumps({**body, 'command': ['false']}))
        if exercise == 'cancel':
            await api('POST', f'/v1/runs/{run_id}/cancel', '{}')
        await api('GET', '/v1/runs/' + run_id, wait_for_terminal=True)
        if exercise == 'forget':
            await api('POST', f'/v1/runs/{run_id}/forget', '{}')
        state.completed = True
        return state
    return solve


@scorer(metrics=[accuracy()])
def native_state(endpoint: str):
    async def score(state, target):
        run_id = store().get('run_id')
        if not run_id:
            return Score(value=INCORRECT, explanation='Sample setup did not complete')
        readback = await asyncio.to_thread(request, endpoint, 'GET', '/v1/runs/' + run_id)
        failures = grade(state.metadata['expected'], readback, store().get('native_observations'), run_id)
        return Score(value=INCORRECT if failures else CORRECT,
                     explanation=', '.join(failures) if failures else 'Daemon state and output match all checks',
                     metadata={'readback': readback})
    return score


def cleanup(endpoint: str):
    async def clean(state):
        run_id = store().get('run_id')
        if not run_id:
            return
        status, value = await asyncio.to_thread(request, endpoint, 'GET', '/v1/runs/' + run_id)
        if status == 404:
            store().set('cleanup', 'PASS')
            return
        if status != 200:
            raise RuntimeError('Cleanup could not read the run')
        if value.get('state') == 'running':
            await asyncio.to_thread(request, endpoint, 'POST', f'/v1/runs/{run_id}/cancel', {})
            status, value = await asyncio.to_thread(wait, endpoint, run_id)
        if status != 200 or value.get('state') in {'running', 'closing'}:
            raise RuntimeError('Sample containment was not confirmed')
        status, _ = await asyncio.to_thread(request, endpoint, 'POST', f'/v1/runs/{run_id}/forget', {})
        if status != 200:
            raise RuntimeError('Sample record cleanup failed')
        store().set('cleanup', 'PASS')
    return clean


@task
def sandcrab_native(endpoint: str, baseline: bool = False):
    cases, digest = load(CASES)
    samples = [Sample(id=c['id'], input=c['task'] + '\nFixture: ' + json.dumps({k: v for k, v in c['fixture'].items() if k != 'exercise'}, ensure_ascii=False),
                      metadata={'fixture': c['fixture'], 'expected': c['expected']}) for c in cases]
    return Task(dataset=samples, setup=prepare(endpoint, baseline),
                solver=scripted(endpoint) if baseline else generate(),
                cleanup=cleanup(endpoint), scorer=native_state(endpoint), epochs=3,
                time_limit=180, message_limit=30, turn_limit=12, token_limit=32000,
                config=GenerateConfig(max_tokens=2048, max_retries=0, parallel_tool_calls=False, max_tool_output=20000, cache=False),
                fail_on_error=False, score_on_error=True,
                metadata={'suite': 'sandcrab-native', 'corpusSha256': digest,
                          'evidenceKind': 'scripted' if baseline else 'model-directed',
                          'clientVersion': 2, 'sampling': {'thinking': 'disabled', 'temperature': 0, 'maxOutputTokens': 2048}}, version=2)
