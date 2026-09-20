"""Command Injection Verification Module.

Tests for OS Command Injection by injecting commands and checking
for command execution evidence (e.g., 'uid=' in response).
"""
import logging
from app.ai_assistant.verification.base_module import BaseVerificationModule

logger = logging.getLogger(__name__)


class CmdInjectionModule(BaseVerificationModule):
    """Command Injection verification module."""

    VULN_TYPE = "Command Injection"
    KEYWORD = "command_injection"

    def generate_payloads(self):
        """Generate command injection payloads."""
        return [
            ';id',
            '|id',
            '&&id',
            '||id',
            '`id`',
            '$(id)',
            ';whoami',
            '|whoami',
            ';cat /etc/passwd',
            '|cat /etc/passwd',
        ]

    def verify(self, param_name, location, method):
        """Run command injection verification."""
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
                    technique='OS Command Execution Detection',
                    request_sent=resp.url,
                    response_summary=f"Status: {resp.status_code}, Length: {len(resp.text)}",
                )

        return self._build_result(
            status='not_vulnerable',
            param_name=param_name,
            location=location,
            method=method,
            payload=payloads[0],
            evidence='No command execution evidence detected.',
            confidence=0.0,
            technique='OS Command Execution Detection',
        )

    def collect_evidence(self, response, payload, baseline_response=None):
        """Check for command execution output in response."""
        resp_text = response.text

        # Check for 'id' command output: uid=0(root) gid=0(root)
        if 'uid=' in resp_text and 'gid=' in resp_text:
            pos = resp_text.find('uid=')
            context = resp_text[pos:pos + 100]
            return f"Command execution confirmed: 'id' output found: {context}"

        # Check for 'whoami' output (single word response)
        if payload in [';whoami', '|whoami'] and resp_text.strip():
            # whoami returns a single word - check if response has a username-like word
            lines = [l.strip() for l in resp_text.split('\n') if l.strip()]
            for line in lines:
                if line and not line.startswith('<') and not line.startswith('{') and len(line) < 50:
                    # Likely a username output
                    if line.isalpha() or '_' in line:
                        return f"Command execution confirmed: 'whoami' output: {line}"

        # Check for /etc/passwd content
        if 'root:x:' in resp_text or 'root:$' in resp_text:
            pos = resp_text.find('root:')
            context = resp_text[pos:pos + 50]
            return f"Command execution confirmed: /etc/passwd content: {context}"

        return None

    def calculate_confidence(self, evidence):
        """Calculate confidence."""
        if 'uid=' in evidence.lower():
            return 1.0
        if 'whoami' in evidence.lower():
            return 0.9
        if 'passwd' in evidence.lower():
            return 1.0
        return 0.3
