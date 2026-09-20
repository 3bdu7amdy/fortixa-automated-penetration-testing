"""CSRF Verification Module.

Tests for Cross-Site Request Forgery by checking if state-changing
operations can be performed without CSRF tokens.
"""
import logging
from app.ai_assistant.verification.base_module import BaseVerificationModule

logger = logging.getLogger(__name__)


class CSRFModule(BaseVerificationModule):
    """CSRF verification module."""

    VULN_TYPE = "CSRF"
    KEYWORD = "csrf"

    def generate_payloads(self):
        """CSRF doesn't use injection payloads — it checks for missing tokens."""
        return ['csrf_test_no_token']

    def verify(self, param_name, location, method):
        """Run CSRF verification by checking token presence."""
        import requests
        from urllib.parse import urlparse

        try:
            # 1. Fetch the page and look for CSRF tokens
            resp = requests.get(self.url, headers=self.headers, timeout=10, verify=False)
            page_html = resp.text.lower()

            # Check for common CSRF token patterns
            token_indicators = [
                'csrf_token', 'csrf-token', 'x-csrf-token',
                'xsrf-token', '__requestverificationtoken',
                'authenticity_token', 'user_token',
                'name="_token"', 'name="csrf"',
            ]

            found_tokens = []
            for indicator in token_indicators:
                if indicator in page_html:
                    found_tokens.append(indicator)

            # 2. If tokens found, check if they're properly validated
            if found_tokens:
                # Try submitting a request WITHOUT the token
                try:
                    if method.upper() == 'POST':
                        # Send POST without token
                        resp_no_token = requests.post(self.url, data={param_name: 'test'},
                                                      headers=self.headers, timeout=10,
                                                      verify=False, allow_redirects=False)
                    else:
                        resp_no_token = requests.get(self.url + '?' + param_name + '=test',
                                                     headers=self.headers, timeout=10,
                                                     verify=False, allow_redirects=False)

                    # If the request succeeds without token, CSRF protection is weak
                    if resp_no_token.status_code == 200 and len(resp_no_token.text) > 100:
                        evidence = (f"CSRF Potential: Token field '{found_tokens[0]}' found on page, "
                                   f"but POST request without token was accepted (Status: {resp_no_token.status_code}).")
                        return self._build_result(
                            status='potential',
                            param_name=param_name,
                            location=location,
                            method=method,
                            payload='POST without CSRF token',
                            evidence=evidence,
                            confidence=0.7,
                            technique='Token Validation Analysis',
                            request_sent=f'{method} {self.url} (no token)',
                            response_summary=f"Status: {resp_no_token.status_code}, Length: {len(resp_no_token.text)}",
                        )
                except Exception:
                    pass

                # Token found and properly validated
                return self._build_result(
                    status='not_vulnerable',
                    param_name=param_name,
                    location=location,
                    method=method,
                    payload='Token validation check',
                    evidence=f'CSRF token found ({found_tokens[0]}) and appears to be validated.',
                    confidence=0.0,
                    technique='Token Validation Analysis',
                )
            else:
                # 3. No token found — check if the endpoint accepts state-changing requests
                if method.upper() == 'POST':
                    evidence = (f"CSRF Potential: No CSRF token found on page. "
                               f"POST endpoint may be vulnerable to CSRF.")
                    return self._build_result(
                        status='potential',
                        param_name=param_name,
                        location=location,
                        method=method,
                        payload='POST without CSRF token',
                        evidence=evidence,
                        confidence=0.6,
                        technique='Token Presence Analysis',
                    )

                return self._build_result(
                    status='not_vulnerable',
                    param_name=param_name,
                    location=location,
                    method=method,
                    payload='Token presence check',
                    evidence='No CSRF token needed for this endpoint (GET request).',
                    confidence=0.0,
                    technique='Token Presence Analysis',
                )

        except Exception as exc:
            logger.warning(f"CSRF verification error: {exc}")
            return self._build_result(
                status='not_tested',
                param_name=param_name,
                location=location,
                method=method,
                payload='',
                evidence=f'Error during CSRF check: {exc}',
                confidence=0.0,
                technique='Token Presence Analysis',
            )

    def collect_evidence(self, response, payload, baseline_response=None):
        """Not used — CSRF uses custom verify logic."""
        return None

    def calculate_confidence(self, evidence):
        """Not used — CSRF uses custom confidence logic."""
        return 0.5
