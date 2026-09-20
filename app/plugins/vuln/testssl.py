"""Testssl runner - SSL/TLS security testing."""
import os
import re
import logging
from app.plugins.base import BaseToolRunner

logger = logging.getLogger(__name__)


class TestsslRunner(BaseToolRunner):
    """Runner for testssl.sh - SSL/TLS security testing.

    Tests SSL/TLS configurations and identifies vulnerabilities.
    """

    tool_name = 'testssl'
    default_timeout = 600

    # Severity mapping for various SSL/TLS issues
    SEVERITY_MAP = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'info': 'info',
        'warn': 'high',
        'ok': 'info',
    }

    def build_command(self, target: str, options: dict) -> list:
        """Build testssl.sh command.

        Args:
            target: Host:port to test SSL/TLS
            options: Optional flags:
                - quiet: bool (default True) - quiet mode
                - protocols: bool - test protocols only
                - vulnerabilities: bool - test vulnerabilities only
                - ciphers: bool - test ciphers only
                - output_file: str - custom output path

        Returns:
            Command arguments list for subprocess.run.
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        cmd = ['testssl.sh', '--quiet', target]

        # Specific test modes
        if options.get('protocols'):
            cmd = ['testssl.sh', '--protocols', target]
        elif options.get('vulnerabilities'):
            cmd = ['testssl.sh', '--vulnerabilities', target]
        elif options.get('ciphers'):
            cmd = ['testssl.sh', '--ciphers', target]

        return cmd

    def parse_output(self, stdout: str, stderr: str, output_dir: str) -> dict:
        """Parse testssl.sh output into findings.

        Testssl.sh outputs color-coded results with severity levels.
        Key markers include severity identifiers (CRITICAL, HIGH, MEDIUM, LOW)
        and vulnerability names (Heartbleed, POODLE, etc.).

        Returns:
            Dict with findings, output_files, and stats.
        """
        findings = []
        output_files = []
        severity_counts = {}

        raw_content = ''

        # Try reading from output file first
        output_file = os.path.join(output_dir, 'testssl_output.txt')
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

            # Determine severity from the line
            severity = None
            if 'CRITICAL' in line.upper():
                severity = 'critical'
            elif 'HIGH' in line.upper() and not re.search(r'HIGH\s+CIPHER', line, re.IGNORECASE):
                severity = 'high'
            elif 'MEDIUM' in line.upper():
                severity = 'medium'
            elif 'LOW' in line.upper():
                severity = 'low'
            elif 'WARN' in line.upper():
                severity = 'high'
            elif 'NOT ok' in line or 'VULNERABLE' in line.upper():
                severity = 'high'
            elif 'ok' in line.lower() and 'NOT' not in line:
                continue  # Skip OK findings

            if severity:
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

                # Extract test name
                title = 'SSL/TLS finding'
                # Common vulnerability names
                vuln_match = re.search(
                    r"(Heartbleed|POODLE|FREAK|Logjam|DROWN|BEAST|CRIME|BREACH|Sweet32|RC4|ROBOT|Sloth|Lucky13|Padding\s+Oracle|Downgrade|Forward\s+Secrecy|HSTS|OCSP\s+stapling)",
                    line, re.IGNORECASE
                )
                if vuln_match:
                    title = f'SSL/TLS: {vuln_match.group(1)}'

                # Protocol issues
                proto_match = re.search(
                    r"(SSLv2|SSLv3|TLS\s*1\.0|TLS\s*1\.1|TLS\s*1\.2|TLS\s*1\.3)",
                    line, re.IGNORECASE
                )
                if proto_match and not vuln_match:
                    title = f'SSL/TLS protocol: {proto_match.group(1)}'

                findings.append({
                    'category': 'ssl_tls',
                    'severity': severity,
                    'title': title,
                    'description': line,
                    'raw_data': line,
                    'tool': self.tool_name,
                })

        stats = {
            'total_findings': len(findings),
            'severity_counts': severity_counts,
        }

        return {
            'findings': findings,
            'output_files': output_files,
            'stats': stats,
        }
