"""Tests for DalfoxRunner."""
import os
import pytest
import tempfile
from app.plugins.vuln.dalfox import DalfoxRunner


class TestDalfoxRunner:
    """Test suite for the DalfoxRunner class."""

    def setup_method(self):
        self.runner = DalfoxRunner()

    # ── build_command ──────────────────────────────────────────────

    def test_build_command_url_mode(self):
        """Single URL uses 'url' subcommand."""
        cmd = self.runner.build_command('https://example.com/?q=test', {
            'output_dir': '/tmp',
        })
        assert cmd[0] == 'dalfox'
        assert cmd[1] == 'url'
        assert cmd[2] == 'https://example.com/?q=test'
        assert '-o' in cmd

    def test_build_command_file_mode(self):
        """File input uses 'file' subcommand."""
        cmd = self.runner.build_command('https://example.com', {
            'output_dir': '/tmp',
            'url_file': '/absolute/path/to/urls.txt',
        })
        assert cmd[1] == 'file'
        assert cmd[2] == '/absolute/path/to/urls.txt'

    def test_build_command_blind_xss(self):
        """Blind XSS option adds --blind flag."""
        cmd = self.runner.build_command('https://example.com', {
            'output_dir': '/tmp',
            'blind': 'https://callback.example.com',
        })
        assert '--blind' in cmd
        idx = cmd.index('--blind')
        assert cmd[idx + 1] == 'https://callback.example.com'

    def test_build_command_rejects_dangerous_target(self):
        """Dangerous characters in target should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid target"):
            self.runner.build_command('https://example.com;rm -rf /', {
                'output_dir': '/tmp',
            })

    def test_build_command_rejects_relative_url_file(self):
        """Relative url_file path should raise ValueError."""
        with pytest.raises(ValueError, match="absolute path"):
            self.runner.build_command('https://example.com', {
                'output_dir': '/tmp',
                'url_file': 'relative/urls.txt',
            })

    # ── parse_output ──────────────────────────────────────────────

    def test_parse_output_with_vulnerabilities(self):
        """[V] lines produce high-severity XSS findings."""
        stdout = (
            "[I] Found testing query: q\n"
            "[V] XSS Found: https://example.com/?q=<script>alert(1)</script>\n"
            "[V] XSS Found: https://example.com/?q=\"><img src=x onerror=alert(1)>\n"
            "[I] Scanning finished\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.parse_output(stdout, '', tmpdir)
            vuln_findings = [f for f in result['findings'] if f['category'] == 'xss']
            assert len(vuln_findings) == 2
            assert vuln_findings[0]['severity'] == 'high'
            assert result['stats']['xss_found'] == 2

    def test_parse_output_with_warnings(self):
        """[W] lines produce medium-severity warnings."""
        stdout = (
            "[W] Reflected parameter found: q\n"
            "[I] Testing parameter: id\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.parse_output(stdout, '', tmpdir)
            warn_findings = [f for f in result['findings'] if f['severity'] == 'medium']
            assert len(warn_findings) == 1

    def test_parse_output_from_file(self):
        """Parse findings from output file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, 'dalfox_output.txt')
            with open(output_file, 'w') as f:
                f.write("[V] XSS Found: https://example.com/?q=<script>alert(1)</script>\n")

            result = self.runner.parse_output('', '', tmpdir)
            assert len(result['findings']) == 1
            assert result['findings'][0]['category'] == 'xss'
            assert output_file in result['output_files']

    def test_parse_output_empty(self):
        """Empty output should return no findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.parse_output('', '', tmpdir)
            assert result['findings'] == []
            assert result['stats']['xss_found'] == 0

    # ── validate_target ───────────────────────────────────────────

    def test_validate_target_safe(self):
        assert self.runner.validate_target('https://example.com/?q=test') is True

    def test_validate_target_dangerous(self):
        assert self.runner.validate_target('https://example.com;whoami') is False
        assert self.runner.validate_target('https://example.com`id`') is False

    # ── tool_name and defaults ────────────────────────────────────

    def test_tool_name(self):
        assert self.runner.tool_name == 'dalfox'

    def test_default_timeout(self):
        assert self.runner.default_timeout == 600
