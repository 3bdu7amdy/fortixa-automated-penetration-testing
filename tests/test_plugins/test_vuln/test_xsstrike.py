"""Tests for XSStrikeRunner."""
import os
import pytest
import tempfile
from app.plugins.vuln.xsstrike import XSStrikeRunner


class TestXSStrikeRunner:
    """Test suite for the XSStrikeRunner class."""

    def setup_method(self):
        self.runner = XSStrikeRunner()

    # ── build_command ──────────────────────────────────────────────

    def test_build_command_basic(self):
        """Basic command includes -u and --crawl."""
        cmd = self.runner.build_command('https://example.com', {})
        assert cmd == ['xsstrike', '-u', 'https://example.com', '--crawl']

    def test_build_command_with_threads(self):
        """Threads option adds --threads flag."""
        cmd = self.runner.build_command('https://example.com', {'threads': 5})
        assert '--threads' in cmd
        idx = cmd.index('--threads')
        assert cmd[idx + 1] == '5'

    def test_build_command_with_delay(self):
        """Delay option adds --delay flag."""
        cmd = self.runner.build_command('https://example.com', {'delay': 2})
        assert '--delay' in cmd
        idx = cmd.index('--delay')
        assert cmd[idx + 1] == '2'

    def test_build_command_no_crawl(self):
        """crawl=False omits --crawl flag."""
        cmd = self.runner.build_command('https://example.com', {'crawl': False})
        assert '--crawl' not in cmd

    def test_build_command_rejects_dangerous_target(self):
        """Dangerous characters in target should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid target"):
            self.runner.build_command('https://example.com;rm -rf /', {})

    # ── parse_output ──────────────────────────────────────────────

    def test_parse_output_with_xss_findings(self):
        """XSS findings produce high-severity results."""
        stdout = (
            "[+] Testing: https://example.com/?q=test\n"
            "[+] XSS Found: https://example.com/?q=<script>alert(1)</script>\n"
            "[+] Potentially vulnerable: https://example.com/?q=test\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.parse_output(stdout, '', tmpdir)
            assert len(result['findings']) >= 1
            xss_findings = [f for f in result['findings'] if f['category'] == 'xss']
            assert len(xss_findings) >= 1
            assert all(f['severity'] == 'high' for f in xss_findings)
            assert result['stats']['xss_found'] >= 1

    def test_parse_output_empty(self):
        """Empty output should return no findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.parse_output('', '', tmpdir)
            assert result['findings'] == []
            assert result['stats']['xss_found'] == 0

    def test_parse_output_from_file(self):
        """Parse findings from output file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, 'xsstrike_output.txt')
            with open(output_file, 'w') as f:
                f.write("[+] XSS Found: https://example.com/?q=<script>alert(1)</script>\n")

            result = self.runner.parse_output('', '', tmpdir)
            assert len(result['findings']) == 1
            assert result['findings'][0]['category'] == 'xss'
            assert output_file in result['output_files']

    # ── validate_target ───────────────────────────────────────────

    def test_validate_target_safe(self):
        assert self.runner.validate_target('https://example.com/?q=test') is True

    def test_validate_target_dangerous(self):
        assert self.runner.validate_target('https://example.com;whoami') is False

    # ── tool_name and defaults ────────────────────────────────────

    def test_tool_name(self):
        assert self.runner.tool_name == 'xsstrike'

    def test_default_timeout(self):
        assert self.runner.default_timeout == 600
