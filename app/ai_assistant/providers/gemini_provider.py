"""Gemini Provider - Google Gemini AI."""
import logging
from app.ai_assistant.providers.base_provider import BaseProvider

logger = logging.getLogger(__name__)


class GeminiProvider(BaseProvider):
    """Google Gemini AI provider."""

    def generate_content(self, prompt):
        """Generate content using Google Gemini.

        Args:
            prompt: The input prompt string.

        Returns:
            The generated text string.
        """
        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            model = genai.GenerativeModel(self.model)
            response = model.generate_content(prompt)
            return response.text
        except ImportError:
            error_msg = "google-generativeai library is not installed. Run: pip install google-generativeai"
            logger.error(error_msg)
            return f"Error: {error_msg}"
        except Exception as exc:
            logger.error(f"Gemini API error: {exc}")
            return f"Gemini API error: {exc}"
