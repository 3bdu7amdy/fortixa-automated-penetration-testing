"""JWT Analysis Verification Module.

Tests for JWT security issues by analyzing token structure,
algorithm confusion, and weak signing.
"""
import logging
import base64
import json
from app.ai_assistant.verification.base_module import BaseVerificationModule

logger = logging.getLogger(__name__)


class JWTModule(BaseVerificationModule):
    """JWT analysis verification module."""

    VULN_TYPE = "JWT Issues"
    KEYWORD = "jwt"

    def generate_payloads(self):
        """JWT analysis doesn't use standard payloads."""
        return ['jwt_analysis']

    def verify(self, param_name, location, method):
        """Run JWT analysis by looking for JWT tokens in response."""
        import requests

        try:
            # Fetch the page and look for JWT tokens
            resp = requests.get(self.url, headers=self.headers, timeout=10, verify=False)
            resp_text = resp.text

            # Also check cookies for JWT
            jwt_tokens = []

            # Check cookies
            for cookie in resp.cookies:
                if 'jwt' in cookie.name.lower() or 'token' in cookie.name.lower():
                    if len(cookie.value) > 50 and '.' in cookie.value:
                        jwt_tokens.append({'source': f'Cookie: {cookie.name}', 'token': cookie.value})

            # Check response body for JWT patterns (eyJ = base64 of {" )
            import re
            jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
            matches = jwt_pattern.findall(resp_text)

            for match in matches[:3]:  # Limit to first 3
                jwt_tokens.append({'source': 'Response Body', 'token': match})

            if not jwt_tokens:
                return self._build_result(
                    status='not_vulnerable',
                    param_name=param_name,
                    location=location,
                    method=method,
                    payload='JWT scan',
                    evidence='No JWT tokens found in response or cookies.',
                    confidence=0.0,
                    technique='JWT Token Analysis',
                )

            # Analyze each JWT token
            vulnerabilities = []
            for jwt_info in jwt_tokens:
                token = jwt_info['token']
                source = jwt_info['source']

                try:
                    # Decode header and payload (without verification)
                    parts = token.split('.')
                    if len(parts) < 2:
                        continue

                    # Add padding
                    header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
                    payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)

                    header = json.loads(base64.urlsafe_b64decode(header_b64))
                    payload = json.loads(base64.urlsafe_b64decode(payload_b64))

                    # Check for issues
                    issues = []

                    # 1. Algorithm = none (critical)
                    if header.get('alg', '').lower() == 'none':
                        issues.append("Algorithm 'none' — token can be forged without signature")

                    # 2. Weak algorithm (HS256 with weak secret)
                    if header.get('alg') == 'HS256':
                        issues.append("HS256 algorithm — vulnerable to brute force if weak secret")

                    # 3. No expiration
                    if 'exp' not in payload:
                        issues.append("No 'exp' claim — token never expires")

                    # 4. Sensitive data in payload
                    sensitive_keys = ['password', 'secret', 'key', 'credit', 'ssn']
                    for key in payload:
                        if any(s in key.lower() for s in sensitive_keys):
                            issues.append(f"Sensitive data in payload: '{key}'")

                    # 5. No 'iat' (issued at)
                    if 'iat' not in payload:
                        issues.append("No 'iat' claim — cannot track token age")

                    if issues:
                        vulnerabilities.append({
                            'source': source,
                            'header': header,
                            'payload_claims': list(payload.keys()),
                            'issues': issues,
                        })

                except Exception as exc:
                    logger.debug(f"JWT decode error: {exc}")
                    continue

            if vulnerabilities:
                all_issues = []
                for v in vulnerabilities:
                    all_issues.extend(v['issues'])

                evidence = f"JWT vulnerabilities found in {len(vulnerabilities)} token(s). Issues: {'; '.join(all_issues[:5])}"
                return self._build_result(
                    status='verified',
                    param_name=param_name,
                    location=location,
                    method=method,
                    payload='JWT analysis',
                    evidence=evidence,
                    confidence=0.8,
                    technique='JWT Structure Analysis',
                    request_sent=f'GET {self.url}',
                    response_summary=f"Found {len(jwt_tokens)} JWT token(s), {len(vulnerabilities)} with issues",
                )

            # JWT found but no issues
            return self._build_result(
                status='not_vulnerable',
                param_name=param_name,
                location=location,
                method=method,
                payload='JWT analysis',
                evidence=f'Found {len(jwt_tokens)} JWT token(s) but no security issues detected.',
                confidence=0.0,
                technique='JWT Structure Analysis',
            )

        except Exception as exc:
            logger.warning(f"JWT verification error: {exc}")
            return self._build_result(
                status='not_tested',
                param_name=param_name,
                location=location,
                method=method,
                payload='JWT analysis',
                evidence=f'Error during JWT analysis: {exc}',
                confidence=0.0,
                technique='JWT Structure Analysis',
            )

    def collect_evidence(self, response, payload, baseline_response=None):
        """Not used — JWT uses custom verify logic."""
        return None

    def calculate_confidence(self, evidence):
        """Not used — JWT uses custom confidence logic."""
        return 0.5
