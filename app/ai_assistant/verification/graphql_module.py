"""GraphQL Introspection Verification Module.

Tests for GraphQL endpoints by sending introspection queries
and checking if the schema is exposed.
"""
import logging
import json
from app.ai_assistant.verification.base_module import BaseVerificationModule

logger = logging.getLogger(__name__)


class GraphQLModule(BaseVerificationModule):
    """GraphQL introspection verification module."""

    VULN_TYPE = "GraphQL Exposure"
    KEYWORD = "graphql"

    INTROSPECTION_QUERY = """
    {
      __schema {
        types {
          name
          fields {
            name
            type {
              name
            }
          }
        }
      }
    }
    """

    def generate_payloads(self):
        """Generate GraphQL test payloads."""
        return [self.INTROSPECTION_QUERY.strip()]

    def verify(self, param_name, location, method):
        """Run GraphQL introspection verification."""
        import requests

        # Try common GraphQL endpoints
        graphql_endpoints = [
            self.url,
            self.url.rstrip('/') + '/graphql',
            self.url.rstrip('/') + '/api/graphql',
            self.url.rstrip('/') + '/query',
        ]

        for endpoint in graphql_endpoints:
            try:
                # Send introspection query
                headers = dict(self.headers)
                headers['Content-Type'] = 'application/json'

                payload_json = json.dumps({"query": self.INTROSPECTION_QUERY.strip()})

                resp = requests.post(endpoint, data=payload_json, headers=headers,
                                     timeout=10, verify=False, allow_redirects=False)

                if not resp:
                    continue

                evidence = self.collect_evidence(resp, self.INTROSPECTION_QUERY.strip())
                if evidence:
                    return self._build_result(
                        status='verified',
                        param_name=param_name,
                        location=location,
                        method='POST (GraphQL)',
                        payload='Introspection query',
                        evidence=evidence,
                        confidence=0.9,
                        technique='GraphQL Introspection Query',
                        request_sent=f'POST {endpoint}',
                        response_summary=f"Status: {resp.status_code}, Length: {len(resp.text)}",
                    )
            except Exception as exc:
                logger.debug(f"GraphQL check failed for {endpoint}: {exc}")
                continue

        return self._build_result(
            status='not_vulnerable',
            param_name=param_name,
            location=location,
            method=method,
            payload='Introspection query',
            evidence='No GraphQL endpoint found or introspection disabled.',
            confidence=0.0,
            technique='GraphQL Introspection Query',
        )

    def collect_evidence(self, response, payload, baseline_response=None):
        """Check for GraphQL introspection response."""
        resp_text = response.text

        # Check for __schema in response (introspection succeeded)
        if '__schema' in resp_text:
            # Try to parse as JSON
            try:
                data = json.loads(resp_text)
                if 'data' in data and '__schema' in str(data.get('data', {})):
                    types_count = str(data.get('data', {}).get('__schema', {}).get('types', ''))
                    return f"GraphQL introspection confirmed: Schema exposed. Response contains __schema with types."
            except json.JSONDecodeError:
                pass

            return f"GraphQL introspection confirmed: Response contains __schema (schema is exposed)."

        # Check for GraphQL error messages (endpoint exists but introspection disabled)
        graphql_errors = ['must provide query', 'graphql', 'syntax error', 'cannot query field']
        resp_lower = resp_text.lower()
        for err in graphql_errors:
            if err in resp_lower:
                return f"GraphQL endpoint detected: Error message '{err}' found. Introspection may be disabled."

        return None

    def calculate_confidence(self, evidence):
        """Calculate confidence."""
        if 'introspection confirmed' in evidence.lower():
            return 0.9
        if 'endpoint detected' in evidence.lower():
            return 0.6
        return 0.3
