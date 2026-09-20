"""Ghauri runner - advanced SQL injection with WAF bypass."""
import os
import re
import logging
from app.plugins.base import BaseToolRunner

logger = logging.getLogger(__name__)


class GhauriRunner(BaseToolRunner):
    """Runner for Ghauri - advanced SQL injection detection tool.

    Detects and exploits SQL injection vulnerabilities with
    advanced WAF bypass capabilities.
    """

    tool_name = 'ghauri'
    default_timeout = 900

    def build_command(self, target: str, options: dict) -> list:
        """Build ghauri command.

        Args:
            target: URL to test for SQL injection
            options: Optional flags:
                - data: str - POST data
                - level: int - detection level (1-5)
                - risk: int - risk level (1-3)
                - technique: str - SQL injection techniques
                - batch: bool (default True) - never ask for user input
                - random_agent: bool (default True) - use random User-Agent
                - tamper: str - tamper scripts for WAF bypass

        Returns:
            Command arguments list for subprocess.run.
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        cmd = ['ghauri', '-u', target]

        # Batch mode
        if options.get('batch', True):
            cmd.append('--batch')

        # Random agent
        if options.get('randomAgent', True):
            cmd.append('--random-agent')

        # POST data
        if 'data' in options:
            cmd.extend(['--data', options['data']])

        # Level
        if 'level' in options:
            cmd.extend(['--level', str(options['level'])])

        # Risk
        if 'risk' in options:
            cmd.extend(['--risk', str(options['risk'])])

        # Technique
        if 'technique' in options:
            cmd.extend(['--technique', options['technique']])

        # Tamper scripts
        if 'tamper' in options:
            cmd.extend(['--tamper', options['tamper']])

        return cmd

    def parse_output(self, stdout: str, stderr: str, output_dir: str) -> dict:
        """Parse ghauri output into findings.

        Ghauri outputs injection information similar to sqlmap.
        Key markers include "is vulnerable" and injection type details.

        Returns:
            Dict with findings, output_files, and stats.
        """
        findings = []
        output_files = []
        injection_params = []

        raw_content = ''

        # Try reading from output file first
        output_file = os.path.join(output_dir, 'ghauri_output.txt')
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                raw_content = f.read()
            output_files.append(output_file)

        # Fall back to stdout
        if not raw_content and stdout:
            raw_content = stdout

        current_param = None
        for line in raw_content.splitlines():
            line = line.strip()
            if not line:
                continue

            # Check for vulnerable parameter
            if 'is vulnerable' in line.lower():
                param_match = re.search(r"Parameter:\s*(\w+)", line)
                if param_match:
                    current_param = param_match.group(1)

                severity = 'critical'
                if 'blind' in line.lower() or 'time-based' in line.lower():
                    severity = 'high'

                findings.append({
                    'category': 'sqli',
                    'severity': severity,
                    'title': f'SQL injection found: {current_param or "unknown parameter"}',
                    'description': line,
                    'raw_data': line,
                    'tool': self.tool_name,
                })
                injection_params.append(current_param or 'unknown')

            # Check for injection type details
            elif current_param and ('Type:' in line or 'Title:' in line):
                if findings:
                    findings[-1]['description'] += '\n' + line

            # Ghauri-specific: WAF bypass detection
            elif 'waf' in line.lower() and 'bypass' in line.lower():
                findings.append({
                    'category': 'sqli',
                    'severity': 'critical',
                    'title': 'SQL injection with WAF bypass',
                    'description': line,
                    'raw_data': line,
                    'tool': self.tool_name,
                })

        stats = {
            'injections_found': len(injection_params),
            'parameters': injection_params,
        }

        return {
            'findings': findings,
            'output_files': output_files,
            'stats': stats,
        }
