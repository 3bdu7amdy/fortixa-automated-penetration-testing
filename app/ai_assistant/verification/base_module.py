"""Base Verification Module - Abstract interface for all verification plugins.

Each vulnerability type inherits from this class and implements:
  - generate_payloads() → list of test payloads
  - verify(param_name, location, method) → single verification result
  - collect_evidence(response, payload) → evidence string
  - calculate_confidence(evidence) → confidence score (0.0 to 1.0)
"""
import requests
import logging

logger = logging.getLogger(__name__)


class BaseVerificationModule:
    """Base class for all verification modules.

    Attributes:
        VULN_TYPE: The vulnerability type name (e.g., 'XSS', 'SQLi').
        KEYWORD: Keywords to match in skills text to trigger this module.
    """

    VULN_TYPE = "base"
    KEYWORD = ""

    def __init__(self, url, cookie_str=""):
        """Initialize the module.

        Args:
            url: The target URL.
            cookie_str: Optional cookie string.
        """
        self.url = url
        self.cookie_str = cookie_str
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
        }
        if cookie_str:
            self.headers["Cookie"] = cookie_str

    def generate_payloads(self):
        """Generate a list of test payloads for this vulnerability type.

        Returns:
            A list of payload strings.
        """
        raise NotImplementedError("Subclasses must implement generate_payloads()")

    def verify(self, param_name, location, method):
        """Run verification for a single parameter.

        Args:
            param_name: The parameter name to test.
            location: Where the parameter is ('URL', 'Form Input').
            method: HTTP method ('GET', 'POST').

        Returns:
            A result dict, or None if not vulnerable.
        """
        raise NotImplementedError("Subclasses must implement verify()")

    def collect_evidence(self, response, payload, baseline_response=None):
        """Collect evidence from the HTTP response.

        Args:
            response: The requests.Response object.
            payload: The payload that was sent.
            baseline_response: The original response without payload (for comparison).

        Returns:
            An evidence string describing what was detected.
        """
        raise NotImplementedError("Subclasses must implement collect_evidence()")

    def calculate_confidence(self, evidence):
        """Calculate a confidence score based on evidence.

        Args:
            evidence: The evidence string from collect_evidence().

        Returns:
            A float between 0.0 and 1.0.
        """
        raise NotImplementedError("Subclasses must implement calculate_confidence()")

    def _send_request(self, param_name, payload, method='GET'):
        """Send a test request with a payload injected into a parameter.

        Args:
            param_name: The parameter name to inject into.
            payload: The payload string.
            method: HTTP method ('GET' or 'POST').

        Returns:
            A requests.Response object, or None on error.
        """
        from urllib.parse import urlparse, urlencode, parse_qs
        import urllib.parse

        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            test_query = urlencode({k: v[0] if isinstance(v, list) else v for k, v in params.items()})
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"

            if method.upper() == 'POST':
                resp = requests.post(self.url, data={param_name: payload},
                                     headers=self.headers, timeout=10, verify=False,
                                     allow_redirects=False)
            else:
                resp = requests.get(test_url, headers=self.headers, timeout=10, verify=False,
                                    allow_redirects=False)
            return resp
        except Exception as exc:
            logger.warning(f"Request error for {param_name}={payload}: {exc}")
            return None

    def _build_result(self, status, param_name, location, method, payload,
                      evidence, confidence, technique, request_sent="", response_summary=""):
        """Build a standardized result dict.

        Args:
            status: 'verified', 'potential', 'not_tested', 'not_vulnerable'.
            param_name: The parameter name.
            location: 'URL Parameter' or 'Form Input'.
            method: HTTP method used.
            payload: The payload that was sent.
            evidence: Evidence description.
            confidence: Float 0.0 to 1.0.
            technique: Verification technique name.
            request_sent: The request URL or body.
            response_summary: Brief summary of the response.

        Returns:
            A result dict.
        """
        return {
            'vuln_type': self.VULN_TYPE,
            'status': status,
            'parameter': param_name,
            'location': location,
            'method': method,
            'payload': payload,
            'evidence': evidence,
            'confidence': confidence,
            'verification_technique': technique,
            'request_sent': request_sent[:500] if request_sent else '',
            'response_summary': response_summary[:500] if response_summary else '',
        }
