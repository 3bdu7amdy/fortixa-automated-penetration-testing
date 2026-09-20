"""Tests for HttpxRunner."""
import os
import json
import pytest
import tempfile
from app.plugins.recon.httpx import HttpxRunner


class TestHttpxRunner:
    """Test suite for the HttpxRunner class."""

    def setup_method(self):
        self.runner = HttpxRunner()

    # ── build_command ──────────────────────────────────────────────

    def test_build_command_single_target(self):
        """Single target uses -u flag."""
        cmd = self.runner.build_command('https://example.com', {'output_dir': '/tmp'})
        assert cmd[0] == 'httpx'
        assert '-u' in cmd
        idx_u = cmd.index('-u')
        assert cmd[idx_u + 1] == 'https://example.com'

    def test_build_command_file_input(self):
        """File input uses -l flag."""
        cmd = self.runner.build_command('example.com', {
            'output_dir': '/tmp',
            'url_file': '/absolute/path/to/urls.txt',
        })
        assert '-l' in cmd
        idx_l = cmd.index('-l')
        assert cmd[idx_l + 1] == '/absolute/path/to/urls.txt'
        # -u should NOT be present when using file input
        assert '-u' not in cmd

    def test_build_command_rejects_dangerous_target(self):
        """Dangerous characters in target should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid target"):
            self.runner.build_command('example.com;whoami', {'output_dir': '/tmp'})

    def test_build_command_default_flags(self):
        """Default flags: -sc, -title, -td, -fr, -json."""
        cmd = self.runner.build_command('https://example.com', {'output_dir': '/tmp'})
        assert '-sc' in cmd
        assert '-title' in cmd
        assert '-td' in cmd
        assert '-fr' in cmd
        assert '-json' in cmd

    def test_build_command_disable_flags(self):
        """Can disable default flags."""
        cmd = self.runner.build_command('https://example.com', {
            'output_dir': '/tmp',
            'status_code': False,
            'title': False,
            'tech_detect': False,
            'follow_redirects': False,
        })
        assert '-sc' not in cmd
        assert '-title' not in cmd
        assert '-td' not in cmd
        assert '-fr' not in cmd

    def test_build_command_with_threads(self):
        """Threads option adds -t flag."""
        cmd = self.runner.build_command('https://example.com', {
            'output_dir': '/tmp',
            'threads': 25,
        })
        assert '-t' in cmd
        idx_t = cmd.index('-t')
        assert cmd[idx_t + 1] == '25'

    def test_build_command_rejects_relative_url_file(self):
        """Relative url_file path should raise ValueError."""
        with pytest.raises(ValueError, match="absolute path"):
            self.runner.build_command('example.com', {
                'output_dir': '/tmp',
                'url_file': 'relative/path.txt',
            })

    # ── parse_output ──────────────────────────────────────────────

    def test_parse_output_json(self):
        """Parse JSON output from httpx."""
        json_lines = [
            json.dumps({
                'url': 'https://example.com',
                'status_code': 200,
                'title': 'Example',
                'tech': ['Nginx', 'React'],
                'content_length': 1234,
                'webserver': 'nginx',
            }),
            json.dumps({
                'url': 'https://api.example.com',
                'status_code': 403,
                'title': 'Forbidden',
                'tech': [],
                'content_length': 0,
                'webserver': '',
            }),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, 'httpx_output.txt')
            with open(output_file, 'w') as f:
                f.write('\n'.join(json_lines) + '\n')

            result = self.runner.parse_output('', '', tmpdir)
            assert len(result['findings']) == 2
            assert result['findings'][0]['category'] == 'live_host'
            assert result['findings'][0]['severity'] == 'info'
            assert 'https://example.com' in result['findings'][0]['title']
            assert result['stats']['total_live_hosts'] == 2

    def test_parse_output_text_fallback(self):
        """Parse text output from stdout when no file."""
        stdout = "https://example.com [200] [Example]\nhttps://test.com [404]\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.parse_output(stdout, '', tmpdir)
            assert len(result['findings']) == 2
            assert result['findings'][0]['category'] == 'live_host'

    def test_parse_output_empty(self):
        """Empty output should return no findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.parse_output('', '', tmpdir)
            assert result['findings'] == []
            assert result['stats']['total_live_hosts'] == 0

    # ── validate_target ───────────────────────────────────────────

    def test_validate_target_safe(self):
        """Safe URLs should pass validation."""
        assert self.runner.validate_target('https://example.com') is True
        assert self.runner.validate_target('http://test.example.com:8080') is True

    def test_validate_target_dangerous(self):
        """Dangerous characters should fail validation."""
        assert self.runner.validate_target('https://example.com;whoami') is False
        assert self.runner.validate_target('https://example.com$(cmd)') is False

    # ── tool_name and defaults ────────────────────────────────────

    def test_tool_name(self):
        assert self.runner.tool_name == 'httpx'

    def test_default_timeout(self):
        assert self.runner.default_timeout == 300
