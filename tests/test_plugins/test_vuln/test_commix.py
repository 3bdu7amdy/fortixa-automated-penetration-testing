"""Tests for CommixRunner."""
import os
import pytest
import tempfile
from app.plugins.vuln.commix import CommixRunner


class TestCommixRunner:
    """Test suite for the CommixRunner class."""

    def setup_method(self):
        self.runner = CommixRunner()

    # ── build_command ──────────────────────────────────────────────

    def test_build_command_basic(self):
        """Basic command includes --url, --batch, --random-agent."""
        cmd = self.runner.build_command('https://example.com/?cmd=test', {})
        assert cmd[0] == 'commix'
        assert '--url' in cmd
        assert 'https://example.com/?cmd=test' in cmd
        assert '--batch' in cmd
        assert '--random-agent' in cmd

    def test_build_command_with_data(self):
        """POST data option adds --data flag."""
        cmd = self.runner.build_command('https://example.com', {'data': 'cmd=ls'})
        assert '--data' in cmd

    def test_build_command_with_cookie(self):
        """Cookie option adds --cookie flag."""
        cmd = self.runner.build_command('https://example.com', {'cookie': 'session=abc'})
        assert '--cookie' in cmd

    def test_build_command_with_level(self):
        """Level option adds --level flag."""
        cmd = self.runner.build_command('https://example.com', {'level': 3})
        assert '--level' in cmd

    def test_build_command_rejects_dangerous_target(self):
        """Dangerous characters in target should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid target"):
            self.runner.build_command('https://example.com;whoami', {})

    def test_build_command_no_batch(self):
        """batch=False omits --batch flag."""
        cmd = self.runner.build_command('https://example.com', {'batch': False})
        assert '--batch' not in cmd

    # ── parse_output ──────────────────────────────────────────────

    def test_parse_output_with_injection(self):
        """Command injection detection produces critical severity finding."""
        stdout = (
            "Command injection found on parameter 'cmd'\n"
            "The 'cmd' parameter is vulnerable\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.parse_output(stdout, '', tmpdir)
            assert len(result['findings']) >= 1
            cmdi_findings = [f for f in result['findings'] if f['category'] == 'command_injection']
            assert len(cmdi_findings) >= 1
            assert all(f['severity'] == 'critical' for f in cmdi_findings)
            assert result['stats']['injections_found'] >= 1

    def test_parse_output_empty(self):
        """Empty output should return no findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.parse_output('', '', tmpdir)
            assert result['findings'] == []
            assert result['stats']['injections_found'] == 0

    def test_parse_output_from_file(self):
        """Parse findings from output file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, 'commix_output.txt')
            with open(output_file, 'w') as f:
                f.write("Command injection detected on parameter 'cmd'\n")

            result = self.runner.parse_output('', '', tmpdir)
            assert len(result['findings']) >= 1
            assert output_file in result['output_files']

    # ── validate_target ───────────────────────────────────────────

    def test_validate_target_safe(self):
        assert self.runner.validate_target('https://example.com/?cmd=test') is True

    def test_validate_target_dangerous(self):
        assert self.runner.validate_target('https://example.com`id`') is False

    # ── tool_name and defaults ────────────────────────────────────

    def test_tool_name(self):
        assert self.runner.tool_name == 'commix'

    def test_default_timeout(self):
        assert self.runner.default_timeout == 600
