"""Tests for NucleiRunner."""
import os
import json
import pytest
import tempfile
from app.plugins.vuln.nuclei import NucleiRunner


class TestNucleiRunner:
    """Test suite for the NucleiRunner class."""

    def setup_method(self):
        self.runner = NucleiRunner()

    # ── build_command ──────────────────────────────────────────────

    def test_build_command_basic(self):
        """Basic command includes -u target, -o, -json."""
        cmd = self.runner.build_command('https://example.com', {'output_dir': '/tmp'})
        assert cmd[0] == 'nuclei'
        assert '-u' in cmd
        idx_u = cmd.index('-u')
        assert cmd[idx_u + 1] == 'https://example.com'
        assert '-o' in cmd
        assert '-json' in cmd

    def test_build_command_with_templates(self):
        """Templates option adds -t flag."""
        cmd = self.runner.build_command('https://example.com', {
            'output_dir': '/tmp',
            'templates': 'cves/',
        })
        assert '-t' in cmd
        idx_t = cmd.index('-t')
        assert cmd[idx_t + 1] == 'cves/'

    def test_build_command_with_severity(self):
        """Severity option adds -severity flag."""
        cmd = self.runner.build_command('https://example.com', {
            'output_dir': '/tmp',
            'severity': 'critical,high',
        })
        assert '-severity' in cmd
        idx_s = cmd.index('-severity')
        assert cmd[idx_s + 1] == 'critical,high'

    def test_build_command_with_rate_limit(self):
        """Rate limit option adds -rate-limit flag."""
        cmd = self.runner.build_command('https://example.com', {
            'output_dir': '/tmp',
            'rate_limit': 100,
        })
        assert '-rate-limit' in cmd

    def test_build_command_rejects_dangerous_target(self):
        """Dangerous characters in target should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid target"):
            self.runner.build_command('https://example.com;whoami', {
                'output_dir': '/tmp',
            })

    # ── parse_output ──────────────────────────────────────────────

    def test_parse_output_json(self):
        """Parse JSON output from nuclei."""
        json_lines = [
            json.dumps({
                'template-id': 'CVE-2021-44228-log4j',
                'info': {
                    'name': 'Apache Log4j RCE',
                    'severity': 'critical',
                },
                'type': 'http',
                'host': 'https://example.com',
                'matched-at': 'https://example.com/api',
            }),
            json.dumps({
                'template-id': 'tech-detect-nginx',
                'info': {
                    'name': 'Nginx Detected',
                    'severity': 'info',
                },
                'type': 'http',
                'host': 'https://example.com',
                'matched-at': 'https://example.com/',
            }),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            json_file = os.path.join(tmpdir, 'nuclei_output.json')
            with open(json_file, 'w') as f:
                f.write('\n'.join(json_lines) + '\n')

            result = self.runner.parse_output('', '', tmpdir)
            assert len(result['findings']) == 2
            assert result['findings'][0]['category'] == 'vulnerability'
            assert result['findings'][0]['severity'] == 'critical'
            assert result['findings'][1]['severity'] == 'info'
            assert result['stats']['total_findings'] == 2
            assert result['stats']['severity_counts']['critical'] == 1

    def test_parse_output_text_fallback(self):
        """Parse text output when no JSON file."""
        stdout = (
            "[CVE-2021-44228] [http] [critical] https://example.com\n"
            "[info-disclosure] [http] [low] https://example.com/info\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.parse_output(stdout, '', tmpdir)
            assert len(result['findings']) == 2
            assert result['findings'][0]['severity'] == 'critical'
            assert result['findings'][1]['severity'] == 'low'

    def test_parse_output_empty(self):
        """Empty output should return no findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.parse_output('', '', tmpdir)
            assert result['findings'] == []
            assert result['stats']['total_findings'] == 0

    # ── severity mapping ──────────────────────────────────────────

    def test_severity_map(self):
        """SEVERITY_MAP should cover all nuclei severity levels."""
        assert NucleiRunner.SEVERITY_MAP['critical'] == 'critical'
        assert NucleiRunner.SEVERITY_MAP['high'] == 'high'
        assert NucleiRunner.SEVERITY_MAP['medium'] == 'medium'
        assert NucleiRunner.SEVERITY_MAP['low'] == 'low'
        assert NucleiRunner.SEVERITY_MAP['info'] == 'info'
        assert NucleiRunner.SEVERITY_MAP['unknown'] == 'medium'

    # ── validate_target ───────────────────────────────────────────

    def test_validate_target_safe(self):
        assert self.runner.validate_target('https://example.com') is True

    def test_validate_target_dangerous(self):
        assert self.runner.validate_target('https://example.com;whoami') is False
        assert self.runner.validate_target('https://example.com$(cmd)') is False

    # ── tool_name and defaults ────────────────────────────────────

    def test_tool_name(self):
        assert self.runner.tool_name == 'nuclei'

    def test_default_timeout(self):
        assert self.runner.default_timeout == 900
