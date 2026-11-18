"""Closed model catalog shared by the controller and the metered client."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Provider:
    key_env: str
    endpoint: str
    pricing_file: str
    pricing_source: str
    context_tokens: int


PROVIDERS = {
    'deepseek-flash': Provider('DEEPSEEK_API_KEY', 'https://api.deepseek.com/chat/completions',
                               'pricing.yaml', 'https://api-docs.deepseek.com/quick_start/pricing/', 1100000),
    'gpt-6-luna': Provider('OPENAI_API_KEY', 'https://api.openai.com/v1/chat/completions',
                           'pricing-openai-luna.yaml', 'https://developers.openai.com/api/docs/models/gpt-6-luna', 1050000),
}


def take_model_key(model, environment):
    keys = {name: environment.pop(spec.key_env, '') for name, spec in PROVIDERS.items()}
    return keys[model]
