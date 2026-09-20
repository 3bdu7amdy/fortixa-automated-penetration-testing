"""Waybackurls runner - URL discovery from Wayback Machine."""
import os
import logging
from app.plugins.base import BaseToolRunner

logger = logging.getLogger(__name__)


class WaybackurlsRunner(BaseToolRunner):
    """Runner for waybackurls - fetch known URLs from Wayback Machine.

    Takes a domain as a positional argument and returns all known URLs
    from the Wayback Machine archive.
    """

    tool_name = 'waybackurls'
    default_timeout = 300

    def build_command(self, target: str, options: dict) -> list:
        """Build waybackurls command.

        waybackurls takes the domain as a positional argument:
            waybackurls example.com

        Args:
            target: Domain to fetch URLs for
            options: Optional flags

        Returns:
            Command arguments list for subprocess.run.
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        # Strip protocol if present (waybackurls expects bare domain)
        clean_target = target
        if clean_target.startswith('https://'):
            clean_target = clean_target[8:]
        elif clean_target.startswith('http://'):
            clean_target = clean_target[7:]
        clean_target = clean_target.rstrip('/')

        cmd = ['waybackurls', clean_target]
        return cmd

    def parse_output(self, stdout: str, stderr: str, output_dir: str) -> dict:
        """Parse waybackurls output into findings.

        Waybackurls outputs one URL per line to stdout.

        Returns:
            Dict with findings, output_files, and stats.
        """
        findings = []
        output_files = []
        urls = []

        if stdout:
            urls = [line.strip() for line in stdout.strip().splitlines() if line.strip()]

        # Save URLs to output file
        output_file = os.path.join(output_dir, 'waybackurls_output.txt')
        if urls:
            with open(output_file, 'w') as f:
                f.write('\n'.join(urls) + '\n')
            output_files.append(output_file)

        for url in urls:
            findings.append({
                'category': 'url',
                'severity': 'info',
                'title': f'URL: {url}',
                'description': f'Wayback Machine URL: {url}',
                'url': url,
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
