"""Amass runner - subdomain enumeration and attack surface mapping."""
import os
import logging
from app.plugins.base import BaseToolRunner

logger = logging.getLogger(__name__)


class AmassRunner(BaseToolRunner):
    """Runner for amass - in-depth attack surface mapping and asset discovery.

    Performs subdomain enumeration through passive and active techniques.
    """

    tool_name = 'amass'
    default_timeout = 600

    def build_command(self, target: str, options: dict) -> list:
        """Build amass command.

        Args:
            target: Domain to scan (e.g. 'example.com')
            options: Optional flags:
                - passive: bool - passive mode only (no DNS resolution)
                - brute: bool - enable brute force
                - threads: int - number of threads
                - output_file: str - custom output path

        Returns:
            Command arguments list for subprocess.run.
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        output_file = options.get(
            'output_file',
            os.path.join(options.get('output_dir', '/tmp'), 'amass_output.txt')
        )
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        cmd = ['amass', 'enum', '-d', target]

        # Passive mode
        if options.get('passive', False):
            cmd.append('-passive')

        # Brute force
        if options.get('brute', False):
            cmd.append('-brute')

        # Threads
        if 'threads' in options:
            cmd.extend(['-t', str(options['threads'])])

        # Output file
        cmd.extend(['-o', output_file])

        return cmd

    def parse_output(self, stdout: str, stderr: str, output_dir: str) -> dict:
        """Parse amass output into findings.

        Amass outputs results in various formats. The default text output
        contains subdomains, one per line or with additional metadata.

        Returns:
            Dict with findings, output_files, and stats.
        """
        findings = []
        output_files = []
        subdomains = []

        # Try reading from output file
        output_file = os.path.join(output_dir, 'amass_output.txt')
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    # Amass text output may have extra metadata;
                    # subdomain is typically the first field
                    subdomain = line.split()[0] if line.split() else line
                    subdomains.append(subdomain)
            output_files.append(output_file)

        # Fall back to stdout
        if not subdomains and stdout:
            for line in stdout.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                subdomain = line.split()[0] if line.split() else line
                subdomains.append(subdomain)

        for subdomain in subdomains:
            findings.append({
                'category': 'subdomain',
                'severity': 'info',
                'title': f'Subdomain discovered: {subdomain}',
                'description': f'Amass discovered subdomain: {subdomain}',
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
