"""Wafw00f runner - Web Application Firewall detection."""
import os
import re
import logging
from app.plugins.base import BaseToolRunner

logger = logging.getLogger(__name__)


class Wafw00fRunner(BaseToolRunner):
    """Runner for wafw00f - Web Application Firewall detection tool.

    Identifies and fingerprints WAF products protecting web applications.
    """

    tool_name = 'wafw00f'
    default_timeout = 300

    def build_command(self, target: str, options: dict) -> list:
        """Build wafw00f command.

        Args:
            target: URL to check for WAF
            options: Optional flags:
                - list: bool - list all known WAFs
                - verbose: bool - verbose output
                - output_file: str - custom output path

        Returns:
            Command arguments list for subprocess.run.
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        cmd = ['wafw00f', target]

        # Verbose mode
        if options.get('verbose'):
            cmd.append('-v')

        # List WAFs
        if options.get('list'):
            cmd.append('-l')

        return cmd

    def parse_output(self, stdout: str, stderr: str, output_dir: str) -> dict:
        """Parse wafw00f output into findings.

        Wafw00f outputs WAF detection results with lines like
        "is behind" a specific WAF product.

        Returns:
            Dict with findings, output_files, and stats.
        """
        findings = []
        output_files = []
        wafs_found = []

        raw_content = ''

        # Try reading from output file first
        output_file = os.path.join(output_dir, 'wafw00f_output.txt')
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                raw_content = f.read()
            output_files.append(output_file)

        # Fall back to stdout
        if not raw_content and stdout:
            raw_content = stdout

        for line in raw_content.splitlines():
            line = line.strip()
            if not line:
                continue

            # Check for WAF detection - "is behind" pattern
            if 'is behind' in line.lower():
                # Extract WAF name
                waf_match = re.search(r"is behind\s+(.+?)(?:\s*$|\s*\()", line, re.IGNORECASE)
                waf_name = waf_match.group(1).strip() if waf_match else 'Unknown WAF'
                if waf_name not in wafs_found:
                    wafs_found.append(waf_name)

                findings.append({
                    'category': 'waf_detection',
                    'severity': 'info',
                    'title': f'WAF detected: {waf_name}',
                    'description': line,
                    'raw_data': line,
                    'tool': self.tool_name,
                })
            elif 'waf' in line.lower() and ('detected' in line.lower() or 'found' in line.lower()) and 'no waf' not in line.lower():
                waf_match = re.search(r"(?:detected|found)[:\s]+(.+?)(?:\s*$|\s*\()", line, re.IGNORECASE)
                waf_name = waf_match.group(1).strip() if waf_match else 'Unknown WAF'
                if waf_name not in wafs_found:
                    wafs_found.append(waf_name)

                findings.append({
                    'category': 'waf_detection',
                    'severity': 'info',
                    'title': f'WAF detected: {waf_name}',
                    'description': line,
                    'raw_data': line,
                    'tool': self.tool_name,
                })

        stats = {
            'wafs_detected': len(wafs_found),
            'waf_names': wafs_found,
        }

        return {
            'findings': findings,
            'output_files': output_files,
            'stats': stats,
        }
