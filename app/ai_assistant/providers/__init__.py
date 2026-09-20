"""AI Providers - Multi-provider support for AI Assistant.

Each provider is a self-contained class with a simple interface:
    - generate_content(prompt: str) -> str

To add a new provider, create a new file in this folder and register
it in the PROVIDERS dict below.
"""
from app.ai_assistant.providers.gemini_provider import GeminiProvider
from app.ai_assistant.providers.openai_provider import OpenAIProvider
from app.ai_assistant.providers.claude_provider import ClaudeProvider
from app.ai_assistant.providers.deepseek_provider import DeepSeekProvider
from app.ai_assistant.providers.zai_provider import ZaiProvider

# Provider registry - maps provider ID to its class
PROVIDERS = {
    'gemini': {
        'name': 'Google Gemini',
        'class': GeminiProvider,
        'models': ['gemini-2.5-flash', 'gemini-1.5-flash', 'gemini-1.5-pro'],
        'default_model': 'gemini-2.5-flash',
        'key_prefix': 'AIza',
        'get_key_url': 'https://aistudio.google.com/app/apikey',
    },
    'openai': {
        'name': 'OpenAI (GPT)',
        'class': OpenAIProvider,
        'models': ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-3.5-turbo'],
        'default_model': 'gpt-4o-mini',
        'key_prefix': 'sk-',
        'get_key_url': 'https://platform.openai.com/api-keys',
    },
    'claude': {
        'name': 'Anthropic Claude',
        'class': ClaudeProvider,
        'models': ['claude-sonnet-4-20250514', 'claude-3-5-sonnet-20241022', 'claude-3-opus-20240229'],
        'default_model': 'claude-sonnet-4-20250514',
        'key_prefix': 'sk-ant',
        'get_key_url': 'https://console.anthropic.com/settings/keys',
    },
    'deepseek': {
        'name': 'DeepSeek',
        'class': DeepSeekProvider,
        'models': ['deepseek-chat', 'deepseek-reasoner'],
        'default_model': 'deepseek-chat',
        'key_prefix': 'sk-',
        'get_key_url': 'https://platform.deepseek.com/api_keys',
    },
    'zai': {
        'name': 'Z.ai (GLM)',
        'class': ZaiProvider,
        # Model names per Z.ai docs: https://docs.z.ai/guide/model/
        'models': [
            'glm-4-flash',        # FREE - fast, recommended for testing
            'glm-4-flashx',       # FREE - faster, lower quality
            'glm-4.5',             # Flagship - paid
            'glm-4.5-air',         # Lighter flagship - paid
            'glm-4.5v',            # Vision flagship - paid
            'glm-4',               # General - paid
            'glm-4-air',           # Lighter general - paid
            'glm-4-plus',          # General purpose - paid
            'glm-4-long',          # 200k context - paid
            'glm-zero-preview',    # Reasoning model - paid
        ],
        'default_model': 'glm-4-flash',  # FREE default
        'key_prefix': '',  # Z.ai keys have no fixed prefix (format: {id}.{secret})
        'get_key_url': 'https://z.ai/manage/apikey',
    },
}


def get_provider(provider_id, api_key, model=None):
    """Get a provider instance by ID.

    Args:
        provider_id: One of 'gemini', 'openai', 'claude', 'deepseek', 'zai'.
        api_key: The API key for the provider.
        model: Optional model name override.

    Returns:
        A provider instance, or None if the provider doesn't exist.
    """
    provider_info = PROVIDERS.get(provider_id)
    if not provider_info:
        return None

    if not model:
        model = provider_info['default_model']

    provider_class = provider_info['class']
    return provider_class(api_key=api_key, model=model)


def list_providers():
    """Return a list of all available providers with their info."""
    result = []
    for pid, info in PROVIDERS.items():
        result.append({
            'id': pid,
            'name': info['name'],
            'models': info['models'],
            'default_model': info['default_model'],
            'get_key_url': info['get_key_url'],
        })
    return result
