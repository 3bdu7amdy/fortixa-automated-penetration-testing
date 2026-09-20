"""Tests for GhauriRunner."""
import os
import pytest
import tempfile
from app.plugins.vuln.ghauri import GhauriRunner


class TestGhauriRunner:
    """Test suite for the GhauriRunner class."""

    def setup_method(self):
        self.runner = GhauriRunner()

    # ── build_command ──────────────────────────────────────────────

    def test_build_command_basic(self):
        """Basic command includes -u, --batch, --random-agent."""
        cmd = self.runner.build_command('https://example.com/?id=1', {})
        assert cmd[0] == 'ghauri'
        assert '-u' in cmd
        assert 'https://example.com/?id=1' in cmd
        assert '--batch' in cmd
        assert '--random-agent' in cmd

    def test_build_command_with_data(self):
        """POST data option adds --data flag."""
        cmd = self.runner.build_command('https://example.com', {'data': 'id=1'})
        assert '--data' in cmd
        idx = cmd.index('--data')
        assert cmd[idx + 1] == 'id=1'

    def test_build_command_with_level(self):
        """Level option adds --level flag."""
        cmd = self.runner.build_command('https://example.com', {'level': 3})
        assert '--level' in cmd
        idx = cmd.index('--level')
        assert cmd[idx + 1] == '3'

    def test_build_command_with_tamper(self):
        """Tamper option adds --tamper flag."""
        cmd = self.runner.build_command('https://example.com', {'tamper': 'between,space2comment'})
        assert '--tamper' in cmd

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
        """Vulnerable parameter produces critical severity finding."""
        stdout = (
            "Parameter: id is vulnerable\n"
            "Type: boolean-based blind\n"
            "Title: AND boolean-based blind\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.parse_output(stdout, '', tmpdir)
            assert len(result['findings']) >= 1
            sqli_findings = [f for f in result['findings'] if f['category'] == 'sqli']
            assert len(sqli_findings) >= 1
            assert result['stats']['injections_found'] >= 1

    def test_parse_output_waf_bypass(self):
        """WAF bypass detection produces a finding."""
        stdout = "WAF bypass detected for Cloudflare\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.parse_output(stdout, '', tmpdir)
            assert len(result['findings']) == 1
            assert result['findings'][0]['category'] == 'sqli'

    def test_parse_output_empty(self):
        """Empty output should return no findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.parse_output('', '', tmpdir)
            assert result['findings'] == []
            assert result['stats']['injections_found'] == 0

    def test_parse_output_from_file(self):
        """Parse findings from output file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, 'ghauri_output.txt')
            with open(output_file, 'w') as f:
                f.write("Parameter: id is vulnerable\n")

            result = self.runner.parse_output('', '', tmpdir)
            assert len(result['findings']) >= 1
            assert output_file in result['output_files']

    # ── validate_target ───────────────────────────────────────────

    def test_validate_target_safe(self):
        assert self.runner.validate_target('https://example.com/?id=1') is True

    def test_validate_target_dangerous(self):
        assert self.runner.validate_target('https://example.com`id`') is False

    # ── tool_name and defaults ────────────────────────────────────

    def test_tool_name(self):
        assert self.runner.tool_name == 'ghauri'

    def test_default_timeout(self):
        assert self.runner.default_timeout == 900
