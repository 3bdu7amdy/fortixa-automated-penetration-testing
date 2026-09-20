"""Claude Provider - Anthropic Claude AI."""
import logging
from app.ai_assistant.providers.base_provider import BaseProvider

logger = logging.getLogger(__name__)


class ClaudeProvider(BaseProvider):
    """Anthropic Claude AI provider."""

    def generate_content(self, prompt):
        """Generate content using Anthropic Claude.

        Args:
            prompt: The input prompt string.

        Returns:
            The generated text string.
        """
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=self.api_key)
            response = client.messages.create(
                model=self.model,
                max_tokens=4096,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            # Claude returns a list of content blocks
            if response.content and len(response.content) > 0:
                return response.content[0].text
            return "No response from Claude."
        except ImportError:
            error_msg = "anthropic library is not installed. Run: pip install anthropic"
            logger.error(error_msg)
            return f"Error: {error_msg}"
        except Exception as exc:
            logger.error(f"Claude API error: {exc}")
            return f"Claude API error: {exc}"
