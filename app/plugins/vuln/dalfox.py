"""Dalfox runner - XSS scanning and parameter analysis."""
import os
import re
import logging
from app.plugins.base import BaseToolRunner

logger = logging.getLogger(__name__)


class DalfoxRunner(BaseToolRunner):
    """Runner for dalfox - powerful XSS scanner and param analysis tool.

    Scans for XSS vulnerabilities in web applications.
    """

    tool_name = 'dalfox'
    default_timeout = 600

    def build_command(self, target: str, options: dict) -> list:
        """Build dalfox command.

        Args:
            target: URL to scan for XSS
            options: Optional flags:
                - url_file: str - path to file with URLs (uses --file flag)
                - blind: str - blind XSS callback URL
                - output_file: str - custom output path
                - timeout: int - request timeout

        Returns:
            Command arguments list for subprocess.run.
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        output_file = options.get(
            'output_file',
            os.path.join(options.get('output_dir', '/tmp'), 'dalfox_output.txt')
        )
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        # File input mode or single URL
        url_file = options.get('url_file')
        if url_file:
            if not os.path.isabs(url_file):
                raise ValueError("url_file must be an absolute path")
            cmd = ['dalfox', 'file', url_file]
        else:
            cmd = ['dalfox', 'url', target]

        # Blind XSS
        if 'blind' in options:
            cmd.extend(['--blind', options['blind']])

        # Output file
        cmd.extend(['-o', output_file])

        return cmd

    def parse_output(self, stdout: str, stderr: str, output_dir: str) -> dict:
        """Parse dalfox output into findings.

        Dalfox marks XSS findings with [V] prefix in its output.
        Other information lines use [I] (info) or [W] (warning).

        Returns:
            Dict with findings, output_files, and stats.
        """
        findings = []
        output_files = []
        xss_count = 0
        info_count = 0

        raw_content = ''

        # Try reading from output file first
        output_file = os.path.join(output_dir, 'dalfox_output.txt')
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

            if '[V]' in line:
                # Vulnerable finding
                xss_count += 1
                findings.append({
                    'category': 'xss',
                    'severity': 'high',
                    'title': f'XSS vulnerability found',
                    'description': line,
                    'raw_data': line,
                    'tool': self.tool_name,
                })
            elif '[W]' in line:
                # Warning - lower severity
                info_count += 1
                findings.append({
                    'category': 'xss_warning',
                    'severity': 'medium',
                    'title': 'XSS scan warning',
                    'description': line,
                    'raw_data': line,
                    'tool': self.tool_name,
                })
            elif '[I]' in line:
                # Informational
                info_count += 1

        stats = {
            'xss_found': xss_count,
            'warnings_and_info': info_count,
        }

        return {
            'findings': findings,
            'output_files': output_files,
            'stats': stats,
        }
