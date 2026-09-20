"""Gau runner - Get All URLs from multiple sources."""
import os
import logging
from app.plugins.base import BaseToolRunner

logger = logging.getLogger(__name__)


class GauRunner(BaseToolRunner):
    """Runner for gau - fetch known URLs from multiple sources.

    Collects URLs from Wayback Machine, Common Crawl, and VirusTotal.
    """

    tool_name = 'gau'
    default_timeout = 300

    def build_command(self, target: str, options: dict) -> list:
        """Build gau command.

        Args:
            target: Domain to fetch URLs for
            options: Optional flags:
                - providers: list - sources to use (wayback, commoncrawl, virustotal)
                - threads: int - number of threads
                - verbose: bool - show source information
                - output_file: str - custom output path

        Returns:
            Command arguments list for subprocess.run.
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        output_file = options.get(
            'output_file',
            os.path.join(options.get('output_dir', '/tmp'), 'gau_output.txt')
        )
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        cmd = ['gau', target]

        # Providers
        if 'providers' in options:
            cmd.extend(['--providers', ','.join(options['providers'])])

        # Threads
        if 'threads' in options:
            cmd.extend(['--threads', str(options['threads'])])

        # Verbose
        if options.get('verbose', False):
            cmd.append('--verbose')

        # Output file
        cmd.extend(['-o', output_file])

        return cmd

    def parse_output(self, stdout: str, stderr: str, output_dir: str) -> dict:
        """Parse gau output into findings.

        Gau outputs one URL per line.

        Returns:
            Dict with findings, output_files, and stats.
        """
        findings = []
        output_files = []
        urls = []

        # Try reading from output file first
        output_file = os.path.join(output_dir, 'gau_output.txt')
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            output_files.append(output_file)

        # Fall back to stdout
        if not urls and stdout:
            urls = [line.strip() for line in stdout.strip().splitlines() if line.strip()]

        for url in urls:
            findings.append({
                'category': 'url_discovery',
                'severity': 'info',
                'title': f'URL discovered: {url}',
                'description': f'GAU discovered URL: {url}',
                'raw_data': url,
                'tool': self.tool_name,
            })

        stats = {
            'total_urls': len(urls),
        }

        return {
            'findings': findings,
            'output_files': output_files,
            'stats': stats,
        }
