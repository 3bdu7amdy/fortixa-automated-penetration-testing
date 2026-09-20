"""Assetfinder runner - subdomain discovery using various data sources."""
import os
import logging
from app.plugins.base import BaseToolRunner

logger = logging.getLogger(__name__)


class AssetfinderRunner(BaseToolRunner):
    """Runner for assetfinder - subdomain discovery tool.

    Discovers subdomains using various passive data sources.
    """

    tool_name = 'assetfinder'
    default_timeout = 300

    def build_command(self, target: str, options: dict) -> list:
        """Build assetfinder command.

        Args:
            target: Domain to scan (e.g. 'example.com')
            options: Optional flags:
                - subs_only: bool (default True) - only subdomains
                - output_file: str - custom output path

        Returns:
            Command arguments list for subprocess.run.
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        output_file = options.get(
            'output_file',
            os.path.join(options.get('output_dir', '/tmp'), 'assetfinder_output.txt')
        )
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        cmd = ['assetfinder']

        # Subdomains only (exclude parent domain itself)
        if options.get('subs_only', True):
            cmd.append('--subs-only')

        cmd.append(target)

        return cmd

    def parse_output(self, stdout: str, stderr: str, output_dir: str) -> dict:
        """Parse assetfinder output into findings.

        Assetfinder outputs one subdomain per line to stdout.

        Returns:
            Dict with findings, output_files, and stats.
        """
        findings = []
        output_files = []
        subdomains = []

        # Assetfinder writes to stdout; capture it
        if stdout:
            subdomains = [line.strip() for line in stdout.strip().splitlines() if line.strip()]

        # Also check for output file (if redirected)
        output_file = os.path.join(output_dir, 'assetfinder_output.txt')
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                file_subdomains = [line.strip() for line in f if line.strip()]
            if file_subdomains and not subdomains:
                subdomains = file_subdomains
            output_files.append(output_file)

        for subdomain in subdomains:
            findings.append({
                'category': 'subdomain',
                'severity': 'info',
                'title': f'Subdomain discovered: {subdomain}',
                'description': f'Assetfinder discovered subdomain: {subdomain}',
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
