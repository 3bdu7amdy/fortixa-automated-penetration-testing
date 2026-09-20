"""Tests for SubfinderRunner."""
import os
import pytest
import tempfile
from app.plugins.recon.subfinder import SubfinderRunner


class TestSubfinderRunner:
    """Test suite for the SubfinderRunner class."""

    def setup_method(self):
        self.runner = SubfinderRunner()

    # ── build_command ──────────────────────────────────────────────

    def test_build_command_basic(self):
        """Basic command includes -d target, -all, -recursive, -o."""
        cmd = self.runner.build_command('example.com', {'output_dir': '/tmp'})
        assert cmd[0] == 'subfinder'
        assert '-d' in cmd
        idx_d = cmd.index('-d')
        assert cmd[idx_d + 1] == 'example.com'
        assert '-all' in cmd
        assert '-recursive' in cmd
        assert '-o' in cmd

    def test_build_command_with_threads(self):
        """Threads option adds -t flag."""
        cmd = self.runner.build_command('example.com', {
            'output_dir': '/tmp',
            'threads': 10,
        })
        assert '-t' in cmd
        idx_t = cmd.index('-t')
        assert cmd[idx_t + 1] == '10'

    def test_build_command_disable_all(self):
        """Setting all=False should omit -all flag."""
        cmd = self.runner.build_command('example.com', {
            'output_dir': '/tmp',
            'all': False,
        })
        assert '-all' not in cmd

    def test_build_command_disable_recursive(self):
        """Setting recursive=False should omit -recursive flag."""
        cmd = self.runner.build_command('example.com', {
            'output_dir': '/tmp',
            'recursive': False,
        })
        assert '-recursive' not in cmd

    def test_build_command_rejects_dangerous_target(self):
        """Dangerous characters in target should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid target"):
            self.runner.build_command('example.com;rm -rf /', {'output_dir': '/tmp'})

    def test_build_command_rejects_pipe(self):
        """Pipe character in target should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid target"):
            self.runner.build_command('example.com|cat /etc/passwd', {'output_dir': '/tmp'})

    def test_build_command_custom_output_file(self):
        """Custom output_file should be used."""
        with tempfile.TemporaryDirectory() as tmpdir:
            custom_file = os.path.join(tmpdir, 'custom_output.txt')
            cmd = self.runner.build_command('example.com', {
                'output_dir': '/tmp',
                'output_file': custom_file,
            })
            idx_o = cmd.index('-o')
            assert cmd[idx_o + 1] == custom_file

    # ── parse_output ──────────────────────────────────────────────

    def test_parse_output_from_stdout(self):
        """Parse subdomains from stdout when no file exists."""
        stdout = "sub1.example.com\nsub2.example.com\nsub3.example.com\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.parse_output(stdout, '', tmpdir)
            assert len(result['findings']) == 3
            assert result['findings'][0]['category'] == 'subdomain'
            assert result['findings'][0]['severity'] == 'info'
            assert 'sub1.example.com' in result['findings'][0]['title']
            assert result['stats']['total_subdomains'] == 3

    def test_parse_output_from_file(self):
        """Parse subdomains from output file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, 'subfinder_output.txt')
            with open(output_file, 'w') as f:
                f.write("api.example.com\ndev.example.com\n")

            result = self.runner.parse_output('', '', tmpdir)
            assert len(result['findings']) == 2
            assert result['stats']['total_subdomains'] == 2
            assert output_file in result['output_files']

    def test_parse_output_empty(self):
        """Empty output should return no findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.parse_output('', '', tmpdir)
            assert result['findings'] == []
            assert result['stats']['total_subdomains'] == 0

    # ── validate_target ───────────────────────────────────────────

    def test_validate_target_safe(self):
        """Safe domain names should pass validation."""
        assert self.runner.validate_target('example.com') is True
        assert self.runner.validate_target('sub.example.com') is True
        assert self.runner.validate_target('test-site.example.co.uk') is True

    def test_validate_target_dangerous(self):
        """Dangerous characters should fail validation."""
        assert self.runner.validate_target('example.com;whoami') is False
        assert self.runner.validate_target('example.com$(cmd)') is False
        assert self.runner.validate_target('example.com`id`') is False
        assert self.runner.validate_target('example.com&ls') is False
        assert self.runner.validate_target('example.com\nid') is False

    # ── tool_name and defaults ────────────────────────────────────

    def test_tool_name(self):
        assert self.runner.tool_name == 'subfinder'

    def test_default_timeout(self):
        assert self.runner.default_timeout == 300
