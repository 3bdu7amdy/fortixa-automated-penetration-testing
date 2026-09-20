"""Open Redirect Verification Module.

Tests for Open Redirect by injecting external URLs and checking
if the response redirects to the injected URL.
"""
import logging
from app.ai_assistant.verification.base_module import BaseVerificationModule

logger = logging.getLogger(__name__)


class OpenRedirectModule(BaseVerificationModule):
    """Open Redirect verification module."""

    VULN_TYPE = "Open Redirect"
    KEYWORD = "redirect"

    TEST_DOMAINS = [
        'https://evil.com',
        'https://attacker-controlled.com',
        '//evil.com',
        'https://example.org',
    ]

    def generate_payloads(self):
        """Generate Open Redirect payloads."""
        return self.TEST_DOMAINS

    def verify(self, param_name, location, method):
        """Run Open Redirect verification."""
        payloads = self.generate_payloads()

        for payload in payloads:
            resp = self._send_request(param_name, payload, method)
            if not resp:
                continue

            evidence = self.collect_evidence(resp, payload)
            if evidence:
                confidence = self.calculate_confidence(evidence)

                return self._build_result(
                    status='verified' if confidence >= 0.8 else 'potential',
                    param_name=param_name,
                    location=location,
                    method=method,
                    payload=payload,
                    evidence=evidence,
                    confidence=confidence,
                    technique='HTTP Redirect Header Analysis',
                    request_sent=resp.url,
                    response_summary=f"Status: {resp.status_code}, Location: {resp.headers.get('Location', 'N/A')}",
                )

        return self._build_result(
            status='not_vulnerable',
            param_name=param_name,
            location=location,
            method=method,
            payload=payloads[0] if payloads else '',
            evidence='No redirect to external domain detected.',
            confidence=0.0,
            technique='HTTP Redirect Header Analysis',
        )

    def collect_evidence(self, response, payload, baseline_response=None):
        """Check if the response redirects to the injected external URL."""
        # Check Location header
        location = response.headers.get('Location', '')
        if location:
            # Check if the location points to our test domain
            for domain in self.TEST_DOMAINS:
                # Remove protocol for comparison
                clean_domain = domain.replace('https://', '').replace('http://', '').replace('//', '')
                clean_location = location.replace('https://', '').replace('http://', '').replace('//', '')

                if clean_domain in clean_location:
                    return f"Open Redirect confirmed: Response redirects to '{location}' (payload: {payload})."

        # Also check for meta refresh redirect in HTML
        if '<meta http-equiv="refresh"' in response.text.lower():
            if any(domain in response.text for domain in self.TEST_DOMAINS):
                return f"Open Redirect via meta refresh: HTML contains redirect to external domain."

        # Check for JavaScript-based redirect
        if 'window.location' in response.text or 'window.open' in response.text:
            if any(domain in response.text for domain in self.TEST_DOMAINS):
                return f"Open Redirect via JavaScript: Response contains JS redirect to external domain."

        return None

    def calculate_confidence(self, evidence):
        """Calculate confidence."""
        if 'location header' in evidence.lower() or 'response redirects' in evidence.lower():
            return 1.0
        if 'meta refresh' in evidence.lower():
            return 0.9
        if 'javascript' in evidence.lower():
            return 0.8
        return 0.3
