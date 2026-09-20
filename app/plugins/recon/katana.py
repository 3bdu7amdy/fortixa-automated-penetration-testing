"""Katana runner - next-generation crawling and spidering framework."""
import os
import logging
from app.plugins.base import BaseToolRunner

logger = logging.getLogger(__name__)


class KatanaRunner(BaseToolRunner):
    """Runner for katana - web crawler and URL discovery.

    Crawls web applications to discover URLs, endpoints, and forms.
    """

    tool_name = 'katana'
    default_timeout = 600

    def build_command(self, target: str, options: dict) -> list:
        """Build katana command.

        Args:
            target: URL to crawl
            options: Optional flags:
                - depth: int (default 5) - crawl depth
                - javascript_crawl: bool (default True) - enable JS crawling
                - threads: int - number of threads
                - output_file: str - custom output path

        Returns:
            Command arguments list for subprocess.run.
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        output_file = options.get(
            'output_file',
            os.path.join(options.get('output_dir', '/tmp'), 'katana_output.txt')
        )
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        cmd = ['katana', '-u', target]

        # JavaScript crawling
        if options.get('javascript_crawl', True):
            cmd.append('-jc')

        # Depth
        cmd.extend(['-d', str(options.get('depth', 5))])

        # Threads
        if 'threads' in options:
            cmd.extend(['-t', str(options['threads'])])

        # Output file
        cmd.extend(['-o', output_file])

        return cmd

    def parse_output(self, stdout: str, stderr: str, output_dir: str) -> dict:
        """Parse katana output into findings.

        Katana outputs one URL per line.

        Returns:
            Dict with findings, output_files, and stats.
        """
        findings = []
        output_files = []
        urls = []

        # Try reading from output file
        output_file = os.path.join(output_dir, 'katana_output.txt')
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
                'description': f'Katana crawled URL: {url}',
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
