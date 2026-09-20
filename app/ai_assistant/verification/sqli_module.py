"""SQL Injection Verification Module.

Tests for SQLi by injecting payloads and checking for:
- Database error messages
- Boolean-based differences (true vs false)
- Time-based delays
- UNION-based response changes
"""
import logging
import time
from app.ai_assistant.verification.base_module import BaseVerificationModule

logger = logging.getLogger(__name__)


class SQLiModule(BaseVerificationModule):
    """SQL Injection verification module."""

    VULN_TYPE = "SQLi"
    KEYWORD = "sqli"

    # Database error indicators
    DB_ERRORS = [
        'sql syntax', 'mysql', 'oracle', 'postgresql', 'sqlite',
        'microsoft sql server', 'odbc', 'syntax error',
        'unclosed quotation', 'sqlstate', 'ORA-',
        'PLS-', 'SQL command not properly ended',
        'pg_query()', 'warning: pg_',
        'Microsoft OLE DB Provider for SQL Server',
        'Unclosed quotation mark after the character string',
        'You have an error in your SQL syntax',
    ]

    def generate_payloads(self):
        """Generate SQLi test payloads."""
        return [
            "'",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "1' OR '1'='1",
            "1 UNION SELECT NULL--",
            "1; SELECT pg_sleep(3)--",
            "' AND SLEEP(3)--",
            "admin'--",
        ]

    def verify(self, param_name, location, method):
        """Run SQLi verification for a parameter."""
        payloads = self.generate_payloads()

        # 1. Error-based detection
        for payload in payloads[:5]:
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
                    technique='Error-Based SQL Injection Detection',
                    request_sent=resp.url,
                    response_summary=f"Status: {resp.status_code}, Length: {len(resp.text)}",
                )

        # 2. Boolean-based detection
        true_resp = self._send_request(param_name, "1", method)
        false_resp = self._send_request(param_name, "0", method)

        if true_resp and false_resp:
            true_len = len(true_resp.text)
            false_len = len(false_resp.text)

            # Check if "OR 1=1" returns different content than baseline
            or_true_resp = self._send_request(param_name, "1 OR 1=1", method)
            or_false_resp = self._send_request(param_name, "1 OR 1=2", method)

            if or_true_resp and or_false_resp:
                # If OR 1=1 matches the true response but OR 1=2 doesn't
                if (abs(len(or_true_resp.text) - true_len) < 50 and
                    abs(len(or_false_resp.text) - false_len) < 50 and
                    abs(true_len - false_len) > 50):
                    evidence = (f"Boolean-based SQLi detected: "
                               f"TRUE payload length={len(or_true_resp.text)}, "
                               f"FALSE payload length={len(or_false_resp.text)}, "
                               f"baseline TRUE={true_len}, baseline FALSE={false_len}")
                    return self._build_result(
                        status='verified',
                        param_name=param_name,
                        location=location,
                        method=method,
                        payload="1 OR 1=1 / 1 OR 1=2",
                        evidence=evidence,
                        confidence=0.85,
                        technique='Boolean-Based SQL Injection Detection',
                        request_sent=or_true_resp.url,
                        response_summary=f"TRUE: {len(or_true_resp.text)} bytes, FALSE: {len(or_false_resp.text)} bytes",
                    )

        # 3. Time-based detection
        time_payloads = ["' AND SLEEP(3)--", "1; SELECT pg_sleep(3)--", "'; WAITFOR DELAY '0:0:3'--"]
        for payload in time_payloads:
            start = time.time()
            resp = self._send_request(param_name, payload, method)
            elapsed = time.time() - start

            if resp and elapsed > 2.5:
                evidence = f"Time-based SQLi detected: Response took {elapsed:.2f}s (expected <2s). Payload: {payload}"
                return self._build_result(
                    status='verified',
                    param_name=param_name,
                    location=location,
                    method=method,
                    payload=payload,
                    evidence=evidence,
                    confidence=0.9,
                    technique='Time-Based SQL Injection Detection',
                    request_sent=resp.url,
                    response_summary=f"Response time: {elapsed:.2f}s",
                )

        # Not vulnerable
        return self._build_result(
            status='not_vulnerable',
            param_name=param_name,
            location=location,
            method=method,
            payload=payloads[0],
            evidence='No SQL errors, boolean differences, or time delays detected.',
            confidence=0.0,
            technique='Error + Boolean + Time-Based Detection',
        )

    def collect_evidence(self, response, payload, baseline_response=None):
        """Check for SQL error messages in the response."""
        resp_lower = response.text.lower()

        for error in self.DB_ERRORS:
            if error.lower() in resp_lower:
                # Extract context around the error
                pos = resp_lower.find(error.lower())
                context = response.text[max(0, pos - 30):pos + len(error) + 50]
                return f"Database error detected: '{error}' in response. Context: {context}"

        return None

    def calculate_confidence(self, evidence):
        """Calculate confidence based on evidence."""
        if 'database error' in evidence.lower():
            return 0.95
        if 'boolean-based' in evidence.lower():
            return 0.85
        if 'time-based' in evidence.lower():
            return 0.9
        return 0.3
