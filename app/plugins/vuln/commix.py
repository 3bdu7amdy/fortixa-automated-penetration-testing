"""Commix runner - command injection detection."""
import os
import re
import logging
from app.plugins.base import BaseToolRunner

logger = logging.getLogger(__name__)


class CommixRunner(BaseToolRunner):
    """Runner for commix - automated command injection detection.

    Detects and exploits OS command injection vulnerabilities.
    """

    tool_name = 'commix'
    default_timeout = 600

    def build_command(self, target: str, options: dict) -> list:
        """Build commix command.

        Args:
            target: URL to test for command injection
            options: Optional flags:
                - data: str - POST data
                - cookie: str - HTTP cookie header
                - level: int - detection level (1-3)
                - technique: str - injection techniques
                - batch: bool (default True) - never ask for user input
                - randomAgent: bool (default True) - use random User-Agent
                - output_file: str - custom output path

        Returns:
            Command arguments list for subprocess.run.
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        cmd = ['commix', '--url', target]

        # Batch mode
        if options.get('batch', True):
            cmd.append('--batch')

        # Random agent
        if options.get('randomAgent', True):
            cmd.append('--random-agent')

        # POST data
        if 'data' in options:
            cmd.extend(['--data', options['data']])

        # Cookie
        if 'cookie' in options:
            cmd.extend(['--cookie', options['cookie']])

        # Level
        if 'level' in options:
            cmd.extend(['--level', str(options['level'])])

        # Technique
        if 'technique' in options:
            cmd.extend(['--technique', options['technique']])

        return cmd

    def parse_output(self, stdout: str, stderr: str, output_dir: str) -> dict:
        """Parse commix output into findings.

        Commix reports command injection findings with markers like
        "command injection" or "vulnerable" in its output.

        Returns:
            Dict with findings, output_files, and stats.
        """
        findings = []
        output_files = []
        injection_count = 0
        injection_params = []

        raw_content = ''

        # Try reading from output file first
        output_file = os.path.join(output_dir, 'commix_output.txt')
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                raw_content = f.read()
            output_files.append(output_file)

        # Fall back to stdout
        if not raw_content and stdout:
            raw_content = stdout

        for line in raw_content.splitlines():
            line = line.strip()
            if not line:
                continue

            # Check for command injection detection
            if 'command injection' in line.lower() and ('found' in line.lower() or 'detected' in line.lower() or 'vulnerable' in line.lower()):
                injection_count += 1
                # Try to extract parameter
                param = ''
                param_match = re.search(r"parameter[:\s]+['\"]?(\w+)", line, re.IGNORECASE)
                if param_match:
                    param = param_match.group(1)
                    injection_params.append(param)

                findings.append({
                    'category': 'command_injection',
                    'severity': 'critical',
                    'title': f'Command injection found{": " + param if param else ""}',
                    'description': line,
                    'raw_data': line,
                    'tool': self.tool_name,
                })
            elif 'vulnerable' in line.lower() and 'injection' in line.lower():
                injection_count += 1
                findings.append({
                    'category': 'command_injection',
                    'severity': 'critical',
                    'title': 'Command injection vulnerability',
                    'description': line,
                    'raw_data': line,
                    'tool': self.tool_name,
                })

        stats = {
            'injections_found': injection_count,
            'parameters': injection_params,
        }

        return {
            'findings': findings,
            'output_files': output_files,
            'stats': stats,
        }
