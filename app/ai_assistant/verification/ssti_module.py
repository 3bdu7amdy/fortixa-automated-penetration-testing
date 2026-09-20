"""SSTI Verification Module.

Tests for Server-Side Template Injection by injecting template expressions
and checking if they are evaluated (e.g., {{7*7}} becomes 49).
"""
import logging
from app.ai_assistant.verification.base_module import BaseVerificationModule

logger = logging.getLogger(__name__)


class SSTIModule(BaseVerificationModule):
    """SSTI verification module."""

    VULN_TYPE = "SSTI"
    KEYWORD = "ssti"

    def generate_payloads(self):
        """Generate SSTI test payloads for various template engines."""
        return [
            '{{7*7}}',           # Jinja2, Twig
            '${7*7}',            # FreeMarker, Velocity
            '#{7*7}',            # Ruby ERB
            '<%=7*7%>',          # JSP, ASP
            '{7*7}',             # Smarty
            '{{7*\'7\'}}',       # Jinja2 string concat
            '${7*7}',            # Spring EL
        ]

    def verify(self, param_name, location, method):
        """Run SSTI verification."""
        payloads = self.generate_payloads()

        for payload in payloads:
            resp = self._send_request(param_name, payload, method)
            if not resp:
                continue

            evidence = self.collect_evidence(resp, payload)
            if evidence:
                confidence = self.calculate_confidence(evidence)
                status = 'verified' if confidence >= 0.8 else 'potential'

                return self._build_result(
                    status=status,
                    param_name=param_name,
                    location=location,
                    method=method,
                    payload=payload,
                    evidence=evidence,
                    confidence=confidence,
                    technique='Template Expression Evaluation',
                    request_sent=resp.url,
                    response_summary=f"Status: {resp.status_code}, Length: {len(resp.text)}",
                )

        return self._build_result(
            status='not_vulnerable',
            param_name=param_name,
            location=location,
            method=method,
            payload=payloads[0],
            evidence='No template expressions were evaluated.',
            confidence=0.0,
            technique='Template Expression Evaluation',
        )

    def collect_evidence(self, response, payload, baseline_response=None):
        """Check if the template expression was evaluated."""
        resp_text = response.text

        # {{7*7}} → 49
        if payload == '{{7*7}}' and '49' in resp_text and '{{7*7}}' not in resp_text:
            return f"Jinja2/Twig SSTI confirmed: {{7*7}} was evaluated to 49."

        # ${7*7} → 49
        if payload == '${7*7}' and '49' in resp_text and '${7*7}' not in resp_text:
            return f"FreeMarker/Spring SSTI confirmed: ${{7*7}} was evaluated to 49."

        # #{7*7} → 49
        if payload == '#{7*7}' and '49' in resp_text and '#{7*7}' not in resp_text:
            return f"Ruby ERB SSTI confirmed: #{{7*7}} was evaluated to 49."

        # <%=7*7%> → 49
        if payload == '<%=7*7%>' and '49' in resp_text and '<%=7*7%>' not in resp_text:
            return f"JSP/ASP SSTI confirmed: <%=7*7%> was evaluated to 49."

        # {7*7} → 49
        if payload == '{7*7}' and '49' in resp_text and '{7*7}' not in resp_text:
            return f"Smarty SSTI confirmed: {{7*7}} was evaluated to 49."

        # Jinja2 string concat: {{7*'7'}} → 7777777
        if payload == "{{7*'7'}}" and '7777777' in resp_text:
            return f"Jinja2 SSTI confirmed: {{7*'7'}} was evaluated to 7777777."

        return None

    def calculate_confidence(self, evidence):
        """Calculate confidence."""
        if 'confirmed' in evidence.lower():
            return 1.0
        return 0.5
