"""Z.ai Provider - GLM models (GLM-4.5, glm-4-flash, etc.).

Uses direct HTTP requests (via the `requests` library) to the Z.ai API
instead of the openai library, for maximum reliability and clearer error
messages.

Z.ai has two API endpoints (both accept the same key):
  - International: https://api.z.ai/api/paas/v4/
  - China:         https://open.bigmodel.cn/api/paas/v4/

Available models (per https://docs.z.ai/guide/model/):
  FREE:
    - glm-4-flash      (fast, recommended)
    - glm-4-flashx     (faster, lower quality)
  PAID:
    - glm-4.5 / glm-4.5-air / glm-4.5v
    - glm-4 / glm-4-air / glm-4-airx / glm-4-plus / glm-4-long
    - glm-zero-preview (reasoning)

Get API key: https://z.ai/manage/apikey
API key format: {API Key ID}.{secret}  — copy the FULL key from the
"API Key" column in the Z.ai dashboard.
"""
import json
import logging
import requests
from app.ai_assistant.providers.base_provider import BaseProvider

logger = logging.getLogger(__name__)

# Z.ai API endpoints (OpenAI-compatible chat completions path).
# We try the international endpoint first; if it fails with a network error
# we fall back to the Chinese endpoint.
ZAI_ENDPOINTS = [
    "https://api.z.ai/api/paas/v4/chat/completions",
    "https://open.bigmodel.cn/api/paas/v4/chat/completions",
]

# HTTP timeout for the API call (seconds).
# Z.ai can take 60-90s on the first request, so be generous.
ZAI_TIMEOUT = 180


class ZaiProvider(BaseProvider):
    """Z.ai provider for GLM models.

    Uses direct HTTP requests instead of the openai library so we have
    full control over the endpoint URL and error handling.
    """

    def generate_content(self, prompt):
        """Generate content using Z.ai GLM models.

        Args:
            prompt: The input prompt string.

        Returns:
            The generated text string.
        """
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "max_tokens": 4096,
            "temperature": 0.7,
        }

        last_error = None
        for url in ZAI_ENDPOINTS:
            try:
                logger.info(f"Z.ai: POST {url} (model={self.model})")
                response = requests.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=ZAI_TIMEOUT,
                )

                # Success
                if response.status_code == 200:
                    try:
                        data = response.json()
                        content = data["choices"][0]["message"]["content"]
                        logger.info(f"Z.ai: success, {len(content)} chars returned")
                        return content
                    except (KeyError, IndexError, json.JSONDecodeError) as e:
                        return (f"Z.ai API error: Unexpected response format. "
                                f"Raw: {response.text[:500]}")

                # Error — capture details
                error_text = response.text[:1000]
                last_error = f"HTTP {response.status_code}: {error_text}"

                # Parse the error for a friendlier message
                try:
                    err_data = response.json()
                    err_code = str(err_data.get("error", {}).get("code", ""))
                    err_msg = err_data.get("error", {}).get("message", error_text)
                except Exception:
                    err_code = ""
                    err_msg = error_text

                # 401/403 = auth error — don't try the other endpoint
                if response.status_code in (401, 403):
                    return (f"Z.ai API error: Authentication failed (HTTP {response.status_code}). "
                            f"Check your API key. Make sure you copied the FULL key "
                            f"in format {{id}}.{{secret}} from https://z.ai/manage/apikey. "
                            f"Details: {err_msg}")

                # 1211 = Unknown model — don't try the other endpoint,
                # the model name is wrong regardless of which URL we hit.
                if err_code == "1211" or "unknown model" in err_msg.lower():
                    return (f"Z.ai API error: Model '{self.model}' is not recognized "
                            f"(error code 1211). Valid models: glm-4-flash (FREE), "
                            f"glm-4-flashx (FREE), glm-4.5, glm-4-plus. "
                            f"Go to AI Provider Settings → Model and pick a valid name.")

                # 429 = rate limit — don't retry
                if response.status_code == 429:
                    return (f"Z.ai API error: Rate limit exceeded. "
                            f"Wait a moment and try again. Details: {err_msg}")

                # Other errors — log and try the next endpoint
                logger.warning(f"Z.ai endpoint {url} returned {response.status_code}: {err_msg}")
                continue

            except requests.exceptions.Timeout:
                last_error = f"Request timed out after {ZAI_TIMEOUT}s"
                logger.warning(f"Z.ai endpoint {url} timed out")
                continue
            except requests.exceptions.ConnectionError as e:
                last_error = f"Connection error: {e}"
                logger.warning(f"Z.ai endpoint {url} connection error: {e}")
                continue
            except Exception as e:
                last_error = f"Unexpected error: {e}"
                logger.error(f"Z.ai endpoint {url} error: {e}", exc_info=True)
                continue

        return f"Z.ai API error: All endpoints failed. Last error: {last_error}"
