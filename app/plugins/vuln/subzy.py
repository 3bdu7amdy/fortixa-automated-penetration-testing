"""Subzy runner - subdomain takeover detection."""
import os
import re
import logging
from app.plugins.base import BaseToolRunner

logger = logging.getLogger(__name__)


class SubzyRunner(BaseToolRunner):
    """Runner for subzy - subdomain takeover detection tool.

    Checks if subdomains are vulnerable to takeover via
    dangling DNS records.
    """

    tool_name = 'subzy'
    default_timeout = 600

    def build_command(self, target: str, options: dict) -> list:
        """Build subzy command.

        Args:
            target: Subdomain or domain to check for takeover
            options: Optional flags:
                - target_file: str - path to file with subdomains
                - https: bool (default True) - use HTTPS
                - verify_ssl: bool - verify SSL certificates
                - timeout: int - request timeout per subdomain
                - output_file: str - custom output path

        Returns:
            Command arguments list for subprocess.run.
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        # File input mode or single target
        target_file = options.get('target_file')
        if target_file:
            if not os.path.isabs(target_file):
                raise ValueError("target_file must be an absolute path")
            cmd = ['subzy', '--target_file', target_file]
        else:
            cmd = ['subzy', '--target', target]

        # HTTPS mode
        if options.get('https', True):
            cmd.append('--https')

        # SSL verification
        if options.get('verify_ssl', False):
            cmd.append('--verify_ssl')

        # Timeout
        if 'timeout' in options:
            cmd.extend(['--timeout', str(options['timeout'])])

        return cmd

    def parse_output(self, stdout: str, stderr: str, output_dir: str) -> dict:
        """Parse subzy output into findings.

        Subzy reports takeover-vulnerable subdomains with markers
        like "VULNERABLE" or "takeover possible".

        Returns:
            Dict with findings, output_files, and stats.
        """
        findings = []
        output_files = []
        takeover_count = 0

        raw_content = ''

        # Try reading from output file first
        output_file = os.path.join(output_dir, 'subzy_output.txt')
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

            # Check for takeover vulnerability
            if 'vulnerable' in line.lower() or 'takeover' in line.lower():
                takeover_count += 1
                # Try to extract subdomain
                subdomain = ''
                subdomain_match = re.search(r'(?:https?://)?([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', line)
                if subdomain_match:
                    subdomain = subdomain_match.group(1)

                # Determine if confirmed or possible
                if 'possible' in line.lower() or 'maybe' in line.lower():
                    severity = 'high'
                    title = f'Possible subdomain takeover{": " + subdomain if subdomain else ""}'
                else:
                    severity = 'high'
                    title = f'Subdomain takeover vulnerability{": " + subdomain if subdomain else ""}'

                findings.append({
                    'category': 'subdomain_takeover',
                    'severity': severity,
                    'title': title,
                    'description': line,
                    'raw_data': line,
                    'tool': self.tool_name,
                })

        stats = {
            'takeover_found': takeover_count,
        }

        return {
            'findings': findings,
            'output_files': output_files,
            'stats': stats,
        }
