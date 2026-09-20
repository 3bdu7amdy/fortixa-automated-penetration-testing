"""Tests for Wafw00fRunner."""
import os
import pytest
import tempfile
from app.plugins.vuln.wafw00f import Wafw00fRunner


class TestWafw00fRunner:
    """Test suite for the Wafw00fRunner class."""

    def setup_method(self):
        self.runner = Wafw00fRunner()

    # ── build_command ──────────────────────────────────────────────

    def test_build_command_basic(self):
        """Basic command includes target URL."""
        cmd = self.runner.build_command('https://example.com', {})
        assert cmd == ['wafw00f', 'https://example.com']

    def test_build_command_with_verbose(self):
        """Verbose option adds -v flag."""
        cmd = self.runner.build_command('https://example.com', {'verbose': True})
        assert '-v' in cmd

    def test_build_command_with_list(self):
        """List option adds -l flag."""
        cmd = self.runner.build_command('https://example.com', {'list': True})
        assert '-l' in cmd

    def test_build_command_rejects_dangerous_target(self):
        """Dangerous characters in target should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid target"):
            self.runner.build_command('https://example.com;whoami', {})

    # ── parse_output ──────────────────────────────────────────────

    def test_parse_output_with_waf(self):
        """WAF detection produces info-severity finding."""
        stdout = (
            "Checking https://example.com\n"
            "The site https://example.com is behind Cloudflare\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.parse_output(stdout, '', tmpdir)
            assert len(result['findings']) >= 1
            waf_findings = [f for f in result['findings'] if f['category'] == 'waf_detection']
            assert len(waf_findings) >= 1
            assert all(f['severity'] == 'info' for f in waf_findings)
            assert result['stats']['wafs_detected'] >= 1

    def test_parse_output_empty(self):
        """Empty output should return no findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.parse_output('', '', tmpdir)
            assert result['findings'] == []
            assert result['stats']['wafs_detected'] == 0

    def test_parse_output_from_file(self):
        """Parse findings from output file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, 'wafw00f_output.txt')
            with open(output_file, 'w') as f:
                f.write("The site https://example.com is behind Imperva Incapsula\n")

            result = self.runner.parse_output('', '', tmpdir)
            assert len(result['findings']) >= 1
            assert output_file in result['output_files']

    def test_parse_output_no_waf(self):
        """No WAF detected returns no findings."""
        stdout = "Checking https://example.com\nNo WAF detected\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.parse_output(stdout, '', tmpdir)
            assert result['findings'] == []
            assert result['stats']['wafs_detected'] == 0

    # ── validate_target ───────────────────────────────────────────

    def test_validate_target_safe(self):
        assert self.runner.validate_target('https://example.com') is True

    def test_validate_target_dangerous(self):
        assert self.runner.validate_target('https://example.com;whoami') is False

    # ── tool_name and defaults ────────────────────────────────────

    def test_tool_name(self):
        assert self.runner.tool_name == 'wafw00f'

    def test_default_timeout(self):
        assert self.runner.default_timeout == 300
