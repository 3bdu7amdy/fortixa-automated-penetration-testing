"""Nosqli runner - NoSQL injection detection."""
import os
import re
import logging
from app.plugins.base import BaseToolRunner

logger = logging.getLogger(__name__)


class NosqliRunner(BaseToolRunner):
    """Runner for nosqli - NoSQL injection detection tool.

    Detects NoSQL injection vulnerabilities in web applications.
    """

    tool_name = 'nosqli'
    default_timeout = 600

    def build_command(self, target: str, options: dict) -> list:
        """Build nosqli command.

        Args:
            target: URL to test for NoSQL injection
            options: Optional flags:
                - data: str - POST data
                - method: str - HTTP method (GET/POST)
                - verbosity: int - verbosity level
                - output_file: str - custom output path

        Returns:
            Command arguments list for subprocess.run.
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        cmd = ['nosqli', '-u', target]

        # POST data
        if 'data' in options:
            cmd.extend(['--data', options['data']])

        # Method
        if 'method' in options:
            cmd.extend(['--method', options['method']])

        # Verbosity
        if 'verbosity' in options:
            cmd.extend(['-v', str(options['verbosity'])])

        return cmd

    def parse_output(self, stdout: str, stderr: str, output_dir: str) -> dict:
        """Parse nosqli output into findings.

        Nosqli outputs detection results with markers like
        "NoSQL injection detected" or "vulnerable".

        Returns:
            Dict with findings, output_files, and stats.
        """
        findings = []
        output_files = []
        injection_count = 0

        raw_content = ''

        # Try reading from output file first
        output_file = os.path.join(output_dir, 'nosqli_output.txt')
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                raw_content = f.read()
            output_files.append(output_file)

        # Fall back to stdout
        if not raw_content and stdout:
            raw_content = stdout

        for line in raw_content.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            # Check for NoSQL injection detection
            if 'nosql injection' in line.lower() or 'vulnerable' in line.lower():
                injection_count += 1
                # Extract parameter if available
                param = ''
                param_match = re.search(r"parameter[:\s]+(\w+)", line, re.IGNORECASE)
                if param_match:
                    param = param_match.group(1)

                findings.append({
                    'category': 'nosqli',
                    'severity': 'high',
                    'title': f'NoSQL injection found{": " + param if param else ""}',
                    'description': line,
                    'raw_data': line,
                    'tool': self.tool_name,
                })
            elif 'inject' in line.lower() and ('found' in line.lower() or 'detected' in line.lower()):
                injection_count += 1
                findings.append({
                    'category': 'nosqli',
                    'severity': 'high',
                    'title': 'NoSQL injection detected',
                    'description': line,
                    'raw_data': line,
                    'tool': self.tool_name,
                })

        stats = {
            'injections_found': injection_count,
        }

        return {
            'findings': findings,
            'output_files': output_files,
            'stats': stats,
        }
