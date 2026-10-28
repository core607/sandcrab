"""Inspect provider with one bounded HTTP dispatch per persisted budget reservation."""
import hashlib
import json
import os

import httpx
from inspect_ai.model import ChatCompletionChoice, ChatMessageAssistant, ModelAPI, ModelOutput, ModelUsage, modelapi
from inspect_ai.tool import ToolCall
from inspect_ai.util import store

from budget import BudgetStopped, Ledger

URL = 'https://api.deepseek.com/chat/completions'
REQUEST_BYTES = 65536
RESPONSE_BYTES = 1048576


def messages(input):
    result = []
    for message in input:
        if not isinstance(message.content, str) and any(c.type != 'text' for c in message.content):
            raise ValueError('This evaluation provider accepts text only')
        value = {'role': message.role, 'content': message.text}
        if message.role == 'tool':
            value['tool_call_id'] = message.tool_call_id
        if message.role == 'assistant' and message.tool_calls:
            value['tool_calls'] = [{'id': call.id, 'type': 'function', 'function': {
                'name': call.function, 'arguments': json.dumps(call.arguments, ensure_ascii=False, allow_nan=False)}} for call in message.tool_calls]
        result.append(value)
    return result


def completion(value: dict, cost_micros: int, output_limit: int) -> ModelOutput:
    usage = value['usage']
    if type(usage['completion_tokens']) is not int or usage['completion_tokens'] > output_limit:
        raise ValueError('Invalid completion usage')
    choice = value['choices'][0]
    message = choice['message']
    calls = []
    for item in message.get('tool_calls') or []:
        function = item['function']
        error = None
        try:
            args = json.loads(function['arguments'])
            if not isinstance(args, dict):
                raise ValueError()
        except (ValueError, TypeError):
            args, error = {}, 'Tool arguments must be a JSON object'
        calls.append(ToolCall(id=item['id'], function=function['name'], arguments=args, parse_error=error))
    details = usage.get('prompt_tokens_details') or {}
    cached = usage.get('prompt_cache_hit_tokens', details.get('cached_tokens', 0))
    if type(cached) is not int or not 0 <= cached <= usage['prompt_tokens']:
        raise ValueError('Invalid cache usage')
    finish = {'stop': 'stop', 'tool_calls': 'tool_calls', 'length': 'max_tokens', 'content_filter': 'content_filter'}
    return ModelOutput(model=value['model'], response_id=value.get('id'),
                       choices=[ChatCompletionChoice(message=ChatMessageAssistant(content=message.get('content') or '', tool_calls=calls),
                                                     stop_reason=finish.get(choice.get('finish_reason'), 'unknown'))],
                       usage=ModelUsage(input_tokens=usage['prompt_tokens'] - cached, input_tokens_cache_read=cached,
                                        output_tokens=usage['completion_tokens'], total_tokens=usage['prompt_tokens'] + usage['completion_tokens'],
                                        total_cost=cost_micros / 1000000),
                       metadata={'servedModel': value['model'], 'systemFingerprint': value.get('system_fingerprint'),
                                 'costBasis': 'peak-rate upper estimate, all input uncached'})


@modelapi(name='bounded-deepseek')
class BoundedDeepSeek(ModelAPI):
    def __init__(self, model_name: str, ledger: Ledger, transport=None):
        super().__init__(model_name)
        if model_name != ledger.prices.data['model']:
            raise ValueError('The model has no approved pricing catalog')
        self.ledger, self.transport = ledger, transport
        self.key = os.environ.get('DEEPSEEK_API_KEY', '')
        if not self.key:
            raise ValueError('DEEPSEEK_API_KEY is required for a model-directed run')

    def max_connections(self):
        return 1

    async def generate(self, input, tools, tool_choice, config):
        output_limit = config.max_tokens or self.ledger.prices.output_limit
        if type(output_limit) is not int or not 1 <= output_limit <= self.ledger.prices.output_limit:
            raise ValueError('Invalid output token limit')
        if isinstance(tool_choice, str):
            choice = 'required' if tool_choice == 'any' else tool_choice
        else:
            choice = {'type': 'function', 'function': {'name': tool_choice.name}}
        payload = {'model': self.model_name, 'messages': messages(input), 'max_tokens': output_limit,
                   'stream': False, 'thinking': {'type': 'disabled'}, 'temperature': 0,
                   'tools': [{'type': 'function', 'function': {'name': t.name, 'description': t.description,
                             'parameters': t.parameters.model_dump(exclude_none=True, by_alias=True)}} for t in tools],
                   'tool_choice': choice, 'parallel_tool_calls': False}
        if not tools:
            del payload['tools'], payload['tool_choice'], payload['parallel_tool_calls']
        raw = json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode()
        if len(raw) > REQUEST_BYTES:
            raise BudgetStopped('Model request exceeds the 64 KiB transport limit; no request sent')
        sample = store().get('sample_key', 'unknown')
        identifier = self.ledger.reserve(sample, hashlib.sha256(raw).hexdigest())
        classification = 'transport'
        try:
            # No redirects, proxy inheritance, retry, streaming API or server-side tools.
            async with httpx.AsyncClient(transport=self.transport, timeout=45, trust_env=False, follow_redirects=False) as client:
                async with client.stream('POST', URL, content=raw,
                                         headers={'Authorization': 'Bearer ' + self.key, 'Content-Type': 'application/json'}) as response:
                    if response.status_code != 200:
                        classification = f'http_{response.status_code}'
                        raise ValueError('Upstream response rejected')
                    data = bytearray()
                    async for part in response.aiter_bytes():
                        data.extend(part)
                        if len(data) > RESPONSE_BYTES:
                            classification = 'response_size'
                            raise ValueError('Upstream response exceeds its bound')
            classification = 'response_format'
            value = json.loads(data)
            release = self.ledger.prices.data['advertised_release']
            if value.get('model') not in {self.model_name, release, release.lower()} or len(value.get('choices', [])) != 1:
                raise ValueError('Unexpected model response')
            classification = 'usage_or_reply_contract'
            usage = value['usage']
            self.ledger.prices.micros(usage['prompt_tokens'], usage['completion_tokens'])
            # Validate the entire reply before releasing the maximum reservation.
            output = completion(value, 0, output_limit)
            charge = self.ledger.settle(identifier, usage['prompt_tokens'], usage['completion_tokens'])
            output.usage.total_cost = charge / 1000000
            return output
        except BaseException:
            self.ledger.uncertain(identifier, classification)
            # Provider bodies and HTTP exception text can echo credentials. Logs retain only
            # this classification and the durable request ID, never the raw exception chain.
            raise BudgetStopped('Model request ' + identifier + ' has uncertain outcome or usage (' + classification + '); batch stopped') from None
