"""Httpx runner - fast multi-purpose HTTP toolkit."""
import os
import json
import logging
from app.plugins.base import BaseToolRunner

logger = logging.getLogger(__name__)


class HttpxRunner(BaseToolRunner):
    """Runner for httpx - HTTP probe and metadata extraction.

    Probes URLs for status code, title, technology detection, and more.
    """

    tool_name = 'httpx'
    default_timeout = 300

    def build_command(self, target: str, options: dict) -> list:
        """Build httpx command.

        Args:
            target: Domain, URL, or path to file with targets
            options: Optional flags:
                - url_file: str - path to file with URLs (uses -l flag)
                - status_code: bool (default True) - show status code
                - title: bool (default True) - show page title
                - tech_detect: bool (default True) - detect technologies
                - follow_redirects: bool (default True)
                - threads: int - number of threads
                - output_file: str - custom output path
                - json_output: bool (default True) - JSON output mode

        Returns:
            Command arguments list for subprocess.run.
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        output_file = options.get(
            'output_file',
            os.path.join(options.get('output_dir', '/tmp'), 'httpx_output.txt')
        )
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        cmd = ['httpx']

        # File input mode or single target
        url_file = options.get('url_file')
        if url_file:
            if not os.path.isabs(url_file):
                raise ValueError("url_file must be an absolute path")
            cmd.extend(['-l', url_file])
        else:
            cmd.extend(['-u', target])

        # Status code
        if options.get('status_code', True):
            cmd.append('-sc')

        # Title
        if options.get('title', True):
            cmd.append('-title')

        # Tech detection
        if options.get('tech_detect', True):
            cmd.append('-td')

        # Follow redirects
        if options.get('follow_redirects', True):
            cmd.append('-fr')

        # Threads
        if 'threads' in options:
            cmd.extend(['-t', str(options['threads'])])

        # JSON output for richer parsing
        if options.get('json_output', True):
            cmd.extend(['-json', '-o', output_file])
        else:
            cmd.extend(['-o', output_file])

        return cmd

    def parse_output(self, stdout: str, stderr: str, output_dir: str) -> dict:
        """Parse httpx output into findings.

        Httpx can output in text format (one URL per line with metadata)
        or JSON format (one JSON object per line).

        Returns:
            Dict with findings, output_files, and stats.
        """
        findings = []
        output_files = []
        live_hosts = []

        output_file = os.path.join(output_dir, 'httpx_output.txt')
        raw_content = ''

        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                raw_content = f.read()
            output_files.append(output_file)

        # Fallback to stdout
        if not raw_content and stdout:
            raw_content = stdout

        # Try JSON parsing first
        for line in raw_content.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host_info = {
                    'url': data.get('url', ''),
                    'status_code': data.get('status_code', ''),
                    'title': data.get('title', ''),
                    'tech': data.get('tech', []),
                    'content_length': data.get('content_length', ''),
                    'webserver': data.get('webserver', ''),
                }
                live_hosts.append(host_info)
                findings.append({
                    'category': 'live_host',
                    'severity': 'info',
                    'title': f"Live host: {host_info['url']} [{host_info['status_code']}]",
                    'description': (
                        f"URL: {host_info['url']}\n"
                        f"Status: {host_info['status_code']}\n"
                        f"Title: {host_info['title']}\n"
                        f"Tech: {', '.join(host_info['tech']) if host_info['tech'] else 'N/A'}"
                    ),
                    'raw_data': data,
                    'tool': self.tool_name,
                })
            except json.JSONDecodeError:
                # Text format: "https://example.com [200] [title]"
                host_info = self._parse_text_line(line)
                if host_info:
                    live_hosts.append(host_info)
                    findings.append({
                        'category': 'live_host',
                        'severity': 'info',
                        'title': f"Live host: {host_info['url']}",
                        'description': line,
                        'raw_data': line,
                        'tool': self.tool_name,
                    })

        stats = {
            'total_live_hosts': len(live_hosts),
        }

        return {
            'findings': findings,
            'output_files': output_files,
            'stats': stats,
        }

    @staticmethod
    def _parse_text_line(line: str) -> dict:
        """Parse a text-format httpx output line."""
        # httpx text format: URL [STATUS] [TITLE] [TECH1,TECH2]
        parts = line.split()
        if not parts:
            return {}
        return {
            'url': parts[0],
            'status_code': '',
            'title': '',
            'tech': [],
        }
