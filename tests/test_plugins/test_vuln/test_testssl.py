"""Tests for TestsslRunner."""
import os
import pytest
import tempfile
from app.plugins.vuln.testssl import TestsslRunner


class TestTestsslRunner:
    """Test suite for the TestsslRunner class."""

    def setup_method(self):
        self.runner = TestsslRunner()

    # ── build_command ──────────────────────────────────────────────

    def test_build_command_basic(self):
        """Basic command includes --quiet and target."""
        cmd = self.runner.build_command('example.com:443', {})
        assert cmd == ['testssl.sh', '--quiet', 'example.com:443']

    def test_build_command_protocols_mode(self):
        """Protocols mode uses --protocols flag."""
        cmd = self.runner.build_command('example.com:443', {'protocols': True})
        assert '--protocols' in cmd
        assert '--quiet' not in cmd

    def test_build_command_vulnerabilities_mode(self):
        """Vulnerabilities mode uses --vulnerabilities flag."""
        cmd = self.runner.build_command('example.com:443', {'vulnerabilities': True})
        assert '--vulnerabilities' in cmd

    def test_build_command_ciphers_mode(self):
        """Ciphers mode uses --ciphers flag."""
        cmd = self.runner.build_command('example.com:443', {'ciphers': True})
        assert '--ciphers' in cmd

    def test_build_command_rejects_dangerous_target(self):
        """Dangerous characters in target should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid target"):
            self.runner.build_command('example.com;whoami', {})

    # ── parse_output ──────────────────────────────────────────────

    def test_parse_output_with_vulnerabilities(self):
        """SSL vulnerabilities produce findings with correct severity."""
        stdout = (
            " Testing Heartbleed\n"
            " VULNERABLE\n"
            " CRITICAL: POODLE (SSLv3)\n"
            " HIGH: Insecure renegotiation\n"
            " MEDIUM: Weak cipher suite\n"
            " ok: Certificate valid\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.parse_output(stdout, '', tmpdir)
            assert len(result['findings']) >= 3
            # Check severity mapping
            severities = [f['severity'] for f in result['findings']]
            assert 'critical' in severities
            assert 'high' in severities
            assert 'medium' in severities
            # ok lines should be skipped
            ok_findings = [f for f in result['findings'] if 'Certificate valid' in f.get('description', '')]
            assert len(ok_findings) == 0

    def test_parse_output_empty(self):
        """Empty output should return no findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.parse_output('', '', tmpdir)
            assert result['findings'] == []

    def test_parse_output_from_file(self):
        """Parse findings from output file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, 'testssl_output.txt')
            with open(output_file, 'w') as f:
                f.write("CRITICAL: Heartbleed vulnerability found\n")

            result = self.runner.parse_output('', '', tmpdir)
            assert len(result['findings']) >= 1
            assert output_file in result['output_files']

    def test_parse_output_ssl_tls_category(self):
        """All findings should have category 'ssl_tls'."""
        stdout = "CRITICAL: POODLE vulnerability\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.parse_output(stdout, '', tmpdir)
            assert len(result['findings']) >= 1
            assert all(f['category'] == 'ssl_tls' for f in result['findings'])

    # ── validate_target ───────────────────────────────────────────

    def test_validate_target_safe(self):
        assert self.runner.validate_target('example.com:443') is True

    def test_validate_target_dangerous(self):
        assert self.runner.validate_target('example.com;rm -rf /') is False

    # ── tool_name and defaults ────────────────────────────────────

    def test_tool_name(self):
        assert self.runner.tool_name == 'testssl'

    def test_default_timeout(self):
        assert self.runner.default_timeout == 600
