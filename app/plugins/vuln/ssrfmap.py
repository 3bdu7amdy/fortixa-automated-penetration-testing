"""SSRFMap runner - SSRF detection and exploitation."""
import os
import re
import logging
from app.plugins.base import BaseToolRunner

logger = logging.getLogger(__name__)


class SSRFMapRunner(BaseToolRunner):
    """Runner for SSRFMap - automatic SSRF detection and exploitation.

    Detects Server-Side Request Forgery vulnerabilities.
    """

    tool_name = 'ssrfmap'
    default_timeout = 600

    def build_command(self, target: str, options: dict) -> list:
        """Build SSRFMap command.

        Args:
            target: URL to test for SSRF
            options: Optional flags:
                - request_file: str - path to request file (required by SSRFMap)
                - param: str - parameter to test
                - module: str - SSRFMap module to use
                - output_file: str - custom output path

        Returns:
            Command arguments list for subprocess.run.
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        request_file = options.get('request_file', '')
        param = options.get('param', 'url')

        if request_file:
            if not os.path.isabs(request_file):
                raise ValueError("request_file must be an absolute path")
            cmd = ['python3', 'ssrfmap.py', '-r', request_file, '-p', param]
        else:
            # Simpler mode: use target URL directly with -u flag if supported,
            # otherwise create a minimal request file
            cmd = ['python3', 'ssrfmap.py', '-u', target, '-p', param]

        # Module selection
        if 'module' in options:
            cmd.extend(['-m', options['module']])

        return cmd

    def parse_output(self, stdout: str, stderr: str, output_dir: str) -> dict:
        """Parse SSRFMap output into findings.

        SSRFMap reports SSRF vulnerabilities with markers like
        "SSRF detected" or successful internal requests.

        Returns:
            Dict with findings, output_files, and stats.
        """
        findings = []
        output_files = []
        ssrf_count = 0

        raw_content = ''

        # Try reading from output file first
        output_file = os.path.join(output_dir, 'ssrfmap_output.txt')
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

            # Check for SSRF detection
            if 'ssrf' in line.lower() and ('detected' in line.lower() or 'found' in line.lower() or 'vulnerable' in line.lower()):
                ssrf_count += 1
                findings.append({
                    'category': 'ssrf',
                    'severity': 'high',
                    'title': 'SSRF vulnerability detected',
                    'description': line,
                    'raw_data': line,
                    'tool': self.tool_name,
                })
            elif 'internal' in line.lower() and 'request' in line.lower():
                ssrf_count += 1
                findings.append({
                    'category': 'ssrf',
                    'severity': 'high',
                    'title': 'Internal request via SSRF',
                    'description': line,
                    'raw_data': line,
                    'tool': self.tool_name,
                })

        stats = {
            'ssrf_found': ssrf_count,
        }

        return {
            'findings': findings,
            'output_files': output_files,
            'stats': stats,
        }
