"""IDOR / Access Control Verification Module.

Tests for Insecure Direct Object Reference by modifying ID-like
parameters and comparing responses.
"""
import logging
from app.ai_assistant.verification.base_module import BaseVerificationModule

logger = logging.getLogger(__name__)


class IDORModule(BaseVerificationModule):
    """IDOR / Access Control verification module."""

    VULN_TYPE = "IDOR"
    KEYWORD = "idor"

    def generate_payloads(self):
        """IDOR doesn't use static payloads — it modifies existing values."""
        return ['1', '2', '0', '100', '999', 'admin']

    def verify(self, param_name, location, method):
        """Run IDOR verification by comparing responses for different IDs."""
        from urllib.parse import urlparse, urlencode, parse_qs

        # First, get the baseline response with the original value
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        if param_name not in params:
            # Try with '1' as a default
            test_value = '1'
        else:
            # Use the original value as baseline
            test_value = params[param_name][0] if isinstance(params[param_name], list) else params[param_name]

        # Get baseline response
        baseline_resp = self._send_request(param_name, test_value, method)
        if not baseline_resp:
            return self._build_result(
                status='not_tested',
                param_name=param_name,
                location=location,
                method=method,
                payload=test_value,
                evidence='Could not get baseline response for IDOR testing.',
                confidence=0.0,
                technique='Response Comparison Analysis',
            )

        baseline_text = baseline_resp.text
        baseline_len = len(baseline_text)

        # Test with different ID values
        test_values = ['2', '3', '0', '999', '100']
        differences = []

        for val in test_values:
            if val == test_value:
                continue

            resp = self._send_request(param_name, val, method)
            if not resp:
                continue

            resp_len = len(resp.text)

            # Check if we got a different response with a different ID
            # (meaning we might be accessing different user's data)
            if resp_len > 0 and abs(resp_len - baseline_len) > 100:
                # Check if the response contains user-specific data
                resp_lower = resp.text.lower()

                # Look for indicators of different user data
                user_indicators = ['email', 'phone', 'address', 'password',
                                   'username', 'user_id', 'account', 'profile',
                                   'balance', 'order', 'transaction']

                found_indicators = [ind for ind in user_indicators if ind in resp_lower]

                if found_indicators:
                    evidence = (f"IDOR Potential: Different response for {param_name}={val} "
                               f"(length: {resp_len} vs baseline: {baseline_len}). "
                               f"Response contains user data indicators: {', '.join(found_indicators)}.")
                    confidence = 0.7

                    return self._build_result(
                        status='potential',
                        param_name=param_name,
                        location=location,
                        method=method,
                        payload=f"{param_name}={val}",
                        evidence=evidence,
                        confidence=confidence,
                        technique='Response Comparison Analysis',
                        request_sent=resp.url,
                        response_summary=f"Status: {resp.status_code}, Length: {resp_len}",
                    )

                differences.append(f"{param_name}={val} → {resp_len} bytes")

        # If we got different response lengths but no user data indicators
        if differences:
            return self._build_result(
                status='potential',
                param_name=param_name,
                location=location,
                method=method,
                payload=f"Tested values: {', '.join(test_values)}",
                evidence=f"Different response lengths detected: {', '.join(differences)}. May indicate IDOR but no user data found.",
                confidence=0.4,
                technique='Response Comparison Analysis',
            )

        return self._build_result(
            status='not_vulnerable',
            param_name=param_name,
            location=location,
            method=method,
            payload=test_value,
            evidence='All ID values returned similar responses. No IDOR detected.',
            confidence=0.0,
            technique='Response Comparison Analysis',
        )

    def collect_evidence(self, response, payload, baseline_response=None):
        """Not used directly — IDOR uses custom verify logic."""
        return None

    def calculate_confidence(self, evidence):
        """Not used directly — IDOR uses custom confidence logic."""
        return 0.5
