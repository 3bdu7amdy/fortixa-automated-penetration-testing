"""Sqlmap runner - automatic SQL injection detection."""
import os
import re
import logging
from app.plugins.base import BaseToolRunner

logger = logging.getLogger(__name__)


class SqlmapRunner(BaseToolRunner):
    """Runner for sqlmap - automatic SQL injection and database takeover tool.

    Detects and exploits SQL injection vulnerabilities.
    """

    tool_name = 'sqlmap'
    default_timeout = 900

    def build_command(self, target: str, options: dict) -> list:
        """Build sqlmap command.

        Args:
            target: URL to test for SQL injection
            options: Optional flags:
                - url_file: str - path to file with URLs (uses -m flag)
                - data: str - POST data
                - level: int - detection level (1-5, default 1)
                - risk: int - risk level (1-3, default 1)
                - technique: str - SQL injection techniques (BEUSTQ)
                - output_dir: str - custom sqlmap output directory
                - batch: bool (default True) - never ask for user input
                - random_agent: bool (default True) - use random User-Agent

        Returns:
            Command arguments list for subprocess.run.
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        output_dir = options.get(
            'sqlmap_output_dir',
            os.path.join(options.get('output_dir', '/tmp'), 'sqlmap_output')
        )
        os.makedirs(output_dir, exist_ok=True)

        # File input mode or single URL
        url_file = options.get('url_file')
        if url_file:
            if not os.path.isabs(url_file):
                raise ValueError("url_file must be an absolute path")
            cmd = ['sqlmap', '-m', url_file]
        else:
            cmd = ['sqlmap', '-u', target]

        # Batch mode (never ask for user input)
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

        # Output directory
        cmd.extend(['-o', output_dir])

        return cmd

    def parse_output(self, stdout: str, stderr: str, output_dir: str) -> dict:
        """Parse sqlmap output into findings.

        Sqlmap outputs results to both stdout and a dedicated output
        directory. Key markers include "is vulnerable" and injection
        parameter information.

        Returns:
            Dict with findings, output_files, and stats.
        """
        findings = []
        output_files = []
        injection_params = []

        raw_content = ''

        # Try reading from sqlmap log file
        sqlmap_out_dir = os.path.join(output_dir, 'sqlmap_output')
        log_file = os.path.join(sqlmap_out_dir, 'target', 'log')
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                raw_content = f.read()
            output_files.append(log_file)

        # Fall back to stdout
        if not raw_content and stdout:
            raw_content = stdout

        # Parse for injection findings
        current_param = None
        for line in raw_content.splitlines():
            line = line.strip()

            # Check for vulnerable parameter
            if 'is vulnerable' in line.lower():
                # Extract parameter name
                param_match = re.search(r"Parameter:\s*(\w+)", line)
                if param_match:
                    current_param = param_match.group(1)

                # Determine severity based on injection type
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
                # Additional detail for previous finding
                if findings:
                    findings[-1]['description'] += '\n' + line

        # Also collect any output files from sqlmap directory
        if os.path.isdir(sqlmap_out_dir):
            for root, dirs, files in os.walk(sqlmap_out_dir):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    if fpath not in output_files:
                        output_files.append(fpath)

        stats = {
            'injections_found': len(injection_params),
            'parameters': injection_params,
        }

        return {
            'findings': findings,
            'output_files': output_files,
            'stats': stats,
        }
