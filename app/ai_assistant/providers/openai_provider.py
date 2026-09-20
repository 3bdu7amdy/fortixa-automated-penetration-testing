"""OpenAI Provider - GPT models."""
import logging
from app.ai_assistant.providers.base_provider import BaseProvider

logger = logging.getLogger(__name__)


class OpenAIProvider(BaseProvider):
    """OpenAI GPT provider."""

    def generate_content(self, prompt):
        """Generate content using OpenAI GPT.

        Args:
            prompt: The input prompt string.

        Returns:
            The generated text string.
        """
        try:
            import openai
            client = openai.OpenAI(api_key=self.api_key)
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                max_tokens=4096,
                temperature=0.7,
            )
            return response.choices[0].message.content
        except ImportError:
            error_msg = "openai library is not installed. Run: pip install openai"
            logger.error(error_msg)
            return f"Error: {error_msg}"
        except Exception as exc:
            logger.error(f"OpenAI API error: {exc}")
            return f"OpenAI API error: {exc}"
