"""DeepSeek Provider - DeepSeek AI."""
import logging
import requests
from app.ai_assistant.providers.base_provider import BaseProvider

logger = logging.getLogger(__name__)


class DeepSeekProvider(BaseProvider):
    """DeepSeek AI provider.

    Uses the OpenAI-compatible API endpoint.
    No special library needed - uses requests directly.
    """

    API_URL = "https://api.deepseek.com/v1/chat/completions"

    def generate_content(self, prompt):
        """Generate content using DeepSeek API.

        Args:
            prompt: The input prompt string.

        Returns:
            The generated text string.
        """
        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 4096,
                "temperature": 0.7,
            }
            response = requests.post(self.API_URL, json=payload, headers=headers, timeout=60)
            response.raise_for_status()
            data = response.json()
            if data.get("choices") and len(data["choices"]) > 0:
                return data["choices"][0]["message"]["content"]
            return "No response from DeepSeek."
        except Exception as exc:
            logger.error(f"DeepSeek API error: {exc}")
            return f"DeepSeek API error: {exc}"
