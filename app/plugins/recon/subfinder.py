"""Subfinder runner - subdomain discovery tool."""
import os
import logging
from app.plugins.base import BaseToolRunner

logger = logging.getLogger(__name__)


class SubfinderRunner(BaseToolRunner):
    """Runner for subfinder - subdomain discovery tool.

    Discovers subdomains using passive data sources.
    """

    tool_name = 'subfinder'
    default_timeout = 300

    def build_command(self, target: str, options: dict) -> list:
        """Build subfinder command.

        Args:
            target: Domain to scan (e.g. 'example.com')
            options: Optional flags:
                - recursive: bool (default True)
                - all: bool (default True) - use all sources
                - timeout: int - per-source timeout
                - threads: int - number of threads
                - output_file: str - custom output path

        Returns:
            Command arguments list for subprocess.run.
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        output_file = options.get(
            'output_file',
            os.path.join(options.get('output_dir', '/tmp'), 'subfinder_output.txt')
        )
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        cmd = ['subfinder', '-d', target]

        # All sources
        if options.get('all', True):
            cmd.append('-all')

        # Recursive resolution
        if options.get('recursive', True):
            cmd.append('-recursive')

        # Threads
        if 'threads' in options:
            cmd.extend(['-t', str(options['threads'])])

        # Per-source timeout
        if 'timeout' in options:
            cmd.extend(['-timeout', str(options['timeout'])])

        # Output file
        cmd.extend(['-o', output_file])

        return cmd

    def parse_output(self, stdout: str, stderr: str, output_dir: str) -> dict:
        """Parse subfinder output into findings.

        Subfinder outputs one subdomain per line, either to stdout
        or to the specified output file.

        Returns:
            Dict with findings, output_files, and stats.
        """
        findings = []
        output_files = []
        subdomains = []

        # Try reading from output file first
        output_file = os.path.join(output_dir, 'subfinder_output.txt')
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            output_files.append(output_file)

        # Fall back to stdout if no file
        if not subdomains and stdout:
            subdomains = [line.strip() for line in stdout.strip().splitlines() if line.strip()]

        for subdomain in subdomains:
            findings.append({
                'category': 'subdomain',
                'severity': 'info',
                'title': f'Subdomain discovered: {subdomain}',
                'description': f'Subfinder discovered subdomain: {subdomain}',
                'raw_data': subdomain,
                'tool': self.tool_name,
            })

        stats = {
            'total_subdomains': len(subdomains),
        }

        return {
            'findings': findings,
            'output_files': output_files,
            'stats': stats,
        }
