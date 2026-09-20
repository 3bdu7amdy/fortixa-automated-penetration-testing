"""XSS Verification Module.

Tests for Reflected and Stored XSS by injecting script payloads
and checking if they appear unencoded in the HTTP response.
"""
import logging
from app.ai_assistant.verification.base_module import BaseVerificationModule

logger = logging.getLogger(__name__)


class XSSModule(BaseVerificationModule):
    """XSS verification module."""

    VULN_TYPE = "XSS"
    KEYWORD = "xss"

    # Unique marker to detect reflection even if encoded
    MARKER = "xss_verify_7x9k"

    def generate_payloads(self):
        """Generate XSS test payloads."""
        return [
            f'<script>alert("{self.MARKER}")</script>',
            f'"><script>alert("{self.MARKER}")</script>',
            f"'><script>alert('{self.MARKER}')</script>",
            f'<img src=x onerror=alert("{self.MARKER}")>',
            f'"><img src=x onerror=alert("{self.MARKER}")>',
            f"javascript:alert('{self.MARKER}')",
            f'<svg onload=alert("{self.MARKER}")>',
        ]

    def verify(self, param_name, location, method):
        """Run XSS verification for a parameter.

        Tests multiple payloads and checks for unencoded reflection.
        Strategy:
          1. Try every payload until one is VERIFIED (confidence >= 0.8).
             If verified, return immediately — we have proof.
          2. If a payload yields only POTENTIAL evidence (e.g. the
             application strips <script> but reflects the marker),
             KEEP TRYING the remaining payloads — bypass payloads like
             <img onerror> or <svg onload> may succeed where the
             classic <script> tag was filtered.
          3. If no payload is VERIFIED but at least one is POTENTIAL,
             return the best (highest-confidence) potential result.
          4. If no payload yields any evidence, return NOT_VULNERABLE.
        """
        payloads = self.generate_payloads()

        best_potential = None  # track best non-verified finding

        for payload in payloads:
            resp = self._send_request(param_name, payload, method)
            if not resp:
                continue

            evidence = self.collect_evidence(resp, payload)
            if not evidence:
                continue

            confidence = self.calculate_confidence(evidence)

            # VERIFIED = definitive proof → return immediately
            if confidence >= 0.8:
                return self._build_result(
                    status='verified',
                    param_name=param_name,
                    location=location,
                    method=method,
                    payload=payload,
                    evidence=evidence,
                    confidence=confidence,
                    technique='Payload Reflection Analysis',
                    request_sent=resp.url,
                    response_summary=f"Status: {resp.status_code}, Length: {len(resp.text)}",
                )

            # POTENTIAL = some reflection but no proof → remember and keep trying
            # (a bypass payload further down the list may succeed)
            if best_potential is None or confidence > best_potential['confidence']:
                best_potential = {
                    'payload': payload,
                    'evidence': evidence,
                    'confidence': confidence,
                    'resp': resp,
                }

        # No VERIFIED payload — return best POTENTIAL if we have one
        if best_potential is not None:
            return self._build_result(
                status='potential',
                param_name=param_name,
                location=location,
                method=method,
                payload=best_potential['payload'],
                evidence=best_potential['evidence'],
                confidence=best_potential['confidence'],
                technique='Payload Reflection Analysis (multi-payload; '
                          f'tried {len(payloads)} payloads, '
                          'none verified but reflection detected)',
                request_sent=best_potential['resp'].url,
                response_summary=f"Status: {best_potential['resp'].status_code}, "
                                 f"Length: {len(best_potential['resp'].text)}",
            )

        # No reflection found for any payload - not vulnerable
        return self._build_result(
            status='not_vulnerable',
            param_name=param_name,
            location=location,
            method=method,
            payload=payloads[0],
            evidence=f'No XSS payload was reflected unencoded in the response '
                     f'(tried {len(payloads)} payloads).',
            confidence=0.0,
            technique='Payload Reflection Analysis',
        )

    def collect_evidence(self, response, payload, baseline_response=None):
        """Check if the XSS payload is reflected unencoded in the response."""
        resp_text = response.text

        # Check if the full script tag appears unencoded
        if '<script>alert' in resp_text.lower():
            return f"Unencoded <script> tag reflected in response. Payload: {payload}"

        # Check for img onerror
        if '<img src=x onerror' in resp_text.lower():
            return f"Unencoded <img onerror> handler reflected in response. Payload: {payload}"

        # Check for svg onload
        if '<svg onload' in resp_text.lower():
            return f"Unencoded <svg onload> handler reflected. Payload: {payload}"

        # Check if the marker appears (even if tags are stripped)
        if self.MARKER in resp_text:
            # Check if it's inside a script context or attribute
            marker_pos = resp_text.find(self.MARKER)
            context = resp_text[max(0, marker_pos - 50):marker_pos + len(self.MARKER) + 50]
            return f"Payload marker reflected in response. Context: ...{context}..."

        # Check if payload is reflected but HTML-encoded
        if '&lt;script&gt;' in resp_text:
            return None  # Encoded = not vulnerable

        return None

    def calculate_confidence(self, evidence):
        """Calculate confidence based on evidence type."""
        if '<script>' in evidence.lower() or '<img' in evidence.lower() or '<svg' in evidence.lower():
            return 1.0  # Unencoded script tag = 100% confident
        if 'marker reflected' in evidence.lower():
            return 0.7  # Marker found but not in script context
        return 0.3
