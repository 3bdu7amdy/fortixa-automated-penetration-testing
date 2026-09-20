"""Tests for NosqliRunner."""
import os
import pytest
import tempfile
from app.plugins.vuln.nosqli import NosqliRunner


class TestNosqliRunner:
    """Test suite for the NosqliRunner class."""

    def setup_method(self):
        self.runner = NosqliRunner()

    # ── build_command ──────────────────────────────────────────────

    def test_build_command_basic(self):
        """Basic command includes -u flag."""
        cmd = self.runner.build_command('https://example.com/api', {})
        assert cmd == ['nosqli', '-u', 'https://example.com/api']

    def test_build_command_with_data(self):
        """POST data option adds --data flag."""
        cmd = self.runner.build_command('https://example.com', {'data': '{"user":"admin"}'})
        assert '--data' in cmd
        idx = cmd.index('--data')
        assert cmd[idx + 1] == '{"user":"admin"}'

    def test_build_command_with_method(self):
        """Method option adds --method flag."""
        cmd = self.runner.build_command('https://example.com', {'method': 'POST'})
        assert '--method' in cmd

    def test_build_command_with_verbosity(self):
        """Verbosity option adds -v flag."""
        cmd = self.runner.build_command('https://example.com', {'verbosity': 2})
        assert '-v' in cmd

    def test_build_command_rejects_dangerous_target(self):
        """Dangerous characters in target should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid target"):
            self.runner.build_command('https://example.com;rm -rf /', {})

    # ── parse_output ──────────────────────────────────────────────

    def test_parse_output_with_nosqli_finding(self):
        """NoSQL injection detection produces high-severity finding."""
        stdout = (
            "NoSQL injection detected in parameter: username\n"
            "Testing parameter: password\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.parse_output(stdout, '', tmpdir)
            assert len(result['findings']) >= 1
            nosqli_findings = [f for f in result['findings'] if f['category'] == 'nosqli']
            assert len(nosqli_findings) >= 1
            assert nosqli_findings[0]['severity'] == 'high'
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
            output_file = os.path.join(tmpdir, 'nosqli_output.txt')
            with open(output_file, 'w') as f:
                f.write("NoSQL injection detected in parameter: user\n")

            result = self.runner.parse_output('', '', tmpdir)
            assert len(result['findings']) >= 1
            assert output_file in result['output_files']

    # ── validate_target ───────────────────────────────────────────

    def test_validate_target_safe(self):
        assert self.runner.validate_target('https://example.com/api') is True

    def test_validate_target_dangerous(self):
        assert self.runner.validate_target('https://example.com;whoami') is False

    # ── tool_name and defaults ────────────────────────────────────

    def test_tool_name(self):
        assert self.runner.tool_name == 'nosqli'

    def test_default_timeout(self):
        assert self.runner.default_timeout == 600
