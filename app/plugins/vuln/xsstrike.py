"""XSStrike runner - advanced XSS detection suite."""
import os
import re
import logging
from app.plugins.base import BaseToolRunner

logger = logging.getLogger(__name__)


class XSStrikeRunner(BaseToolRunner):
    """Runner for XSStrike - advanced XSS detection suite.

    Detects cross-site scripting vulnerabilities with advanced
    fuzzing and crawling capabilities.
    """

    tool_name = 'xsstrike'
    default_timeout = 600

    def build_command(self, target: str, options: dict) -> list:
        """Build XSStrike command.

        Args:
            target: URL to scan for XSS
            options: Optional flags:
                - crawl: bool (default True) - crawl the target
                - threads: int - number of threads for crawling
                - delay: int - delay between requests
                - timeout: int - request timeout
                - output_file: str - custom output path

        Returns:
            Command arguments list for subprocess.run.
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        cmd = ['xsstrike', '-u', target]

        # Crawl mode (default)
        if options.get('crawl', True):
            cmd.append('--crawl')

        # Threads
        if 'threads' in options:
            cmd.extend(['--threads', str(options['threads'])])

        # Delay
        if 'delay' in options:
            cmd.extend(['--delay', str(options['delay'])])

        return cmd

    def parse_output(self, stdout: str, stderr: str, output_dir: str) -> dict:
        """Parse XSStrike output into findings.

        XSStrike marks XSS findings with lines containing
        'XSS' or 'Potentially vulnerable' in the output.

        Returns:
            Dict with findings, output_files, and stats.
        """
        findings = []
        output_files = []
        xss_count = 0
        info_count = 0

        raw_content = ''

        # Try reading from output file first
        output_file = os.path.join(output_dir, 'xsstrike_output.txt')
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

            # XSStrike reports confirmed XSS findings
            if 'XSS' in line and ('vulnerable' in line.lower() or 'found' in line.lower() or 'injected' in line.lower()):
                xss_count += 1
                # Try to extract the payload/URL
                payload = ''
                payload_match = re.search(r'(?:Payload|payload|POC|poc)[:\s]+(.+)', line)
                if payload_match:
                    payload = payload_match.group(1).strip()

                findings.append({
                    'category': 'xss',
                    'severity': 'high',
                    'title': 'XSS vulnerability found',
                    'description': line,
                    'raw_data': line,
                    'tool': self.tool_name,
                })
            elif 'potentially vulnerable' in line.lower():
                xss_count += 1
                findings.append({
                    'category': 'xss',
                    'severity': 'high',
                    'title': 'Potential XSS vulnerability',
                    'description': line,
                    'raw_data': line,
                    'tool': self.tool_name,
                })
            elif 'alert' in line.lower() and 'injection' in line.lower():
                xss_count += 1
                findings.append({
                    'category': 'xss',
                    'severity': 'high',
                    'title': 'XSS injection found',
                    'description': line,
                    'raw_data': line,
                    'tool': self.tool_name,
                })
            else:
                info_count += 1

        stats = {
            'xss_found': xss_count,
            'info_lines': info_count,
        }

        return {
            'findings': findings,
            'output_files': output_files,
            'stats': stats,
        }
