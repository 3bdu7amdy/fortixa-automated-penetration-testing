"""Nuclei runner - template-based vulnerability scanner."""
import os
import json
import logging
from app.plugins.base import BaseToolRunner

logger = logging.getLogger(__name__)


class NucleiRunner(BaseToolRunner):
    """Runner for nuclei - fast and customisable vulnerability scanner.

    Scans for vulnerabilities using community and custom templates.
    """

    tool_name = 'nuclei'
    default_timeout = 900

    # Map nuclei severity to our severity levels
    SEVERITY_MAP = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'info': 'info',
        'unknown': 'medium',
    }

    def build_command(self, target: str, options: dict) -> list:
        """Build nuclei command.

        Args:
            target: URL or domain to scan
            options: Optional flags:
                - templates: str - path or tag for templates
                - severity: str - filter by severity (e.g. 'critical,high')
                - exclude_severity: str - exclude severities
                - rate_limit: int - requests per second
                - threads: int - number of threads
                - output_file: str - custom output path (JSON format)
                - json_output: str - (deprecated, kept for compatibility)

        Returns:
            Command arguments list for subprocess.run.
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        output_file = options.get(
            'output_file',
            os.path.join(options.get('output_dir', '/tmp'), 'nuclei_output.json')
        )
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        # Build nuclei command with JSON output
        # Use -j (short flag) for compatibility across nuclei versions
        cmd = ['nuclei', '-u', target, '-silent', '-j', '-o', output_file]

        # Templates (can be a tag name or path)
        if 'templates' in options:
            cmd.extend(['-t', options['templates']])

        # Severity filter
        if 'severity' in options:
            cmd.extend(['-severity', options['severity']])

        # Exclude severity
        if 'exclude_severity' in options:
            cmd.extend(['-exclude-severity', options['exclude_severity']])

        # Rate limit
        if 'rate_limit' in options:
            cmd.extend(['-rate-limit', str(options['rate_limit'])])

        # Threads
        if 'threads' in options:
            cmd.extend(['-c', str(options['threads'])])

        return cmd

    def parse_output(self, stdout: str, stderr: str, output_dir: str) -> dict:
        """Parse nuclei output into findings.

        Nuclei outputs JSON to the output file (one JSON object per line).
        If no findings are found, the output file may be empty or missing.

        Returns:
            Dict with findings, output_files, and stats.
        """
        findings = []
        output_files = []
        severity_counts = {}

        # Try JSON output file first, then fall back to stdout
        json_file = os.path.join(output_dir, 'nuclei_output.json')
        text_file = os.path.join(output_dir, 'nuclei_output.txt')

        # Collect nuclei output lines from file and/or stdout
        nuclei_lines = []
        if os.path.exists(json_file):
            output_files.append(json_file)
            with open(json_file, 'r') as f:
                nuclei_lines = f.readlines()
        # If file is empty, try stdout (some nuclei versions print to stdout)
        if not nuclei_lines and stdout:
            nuclei_lines = stdout.splitlines()

        for raw_line in nuclei_lines:
            line = raw_line.strip() if isinstance(raw_line, str) else str(raw_line).strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                severity = data.get('info', {}).get('severity', 'unknown').lower()
                mapped_severity = self.SEVERITY_MAP.get(severity, 'medium')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

                template_name = data.get('info', {}).get('name', 'Unknown')
                template_id = data.get('template-id', '')
                matched_at = data.get('matched-at', data.get('host', ''))

                findings.append({
                    'category': 'vulnerability',
                    'severity': mapped_severity,
                    'title': template_name,
                    'description': (
                        f"Template: {template_id}\n"
                        f"Severity: {severity}\n"
                        f"Matched at: {matched_at}\n"
                        f"Type: {data.get('type', '')}"
                    ),
                    'url': matched_at,
                    'raw_data': data,
                    'tool': self.tool_name,
                })
            except json.JSONDecodeError:
                continue

        # If no JSON file, also check stdout for JSON lines
        # (nuclei sometimes outputs to stdout instead of the -o file)
        if not findings and stdout:
            for line in stdout.strip().splitlines():
                line = line.strip()
                if not line or not line.startswith('{'):
                    continue
                try:
                    data = json.loads(line)
                    severity = data.get('info', {}).get('severity', 'unknown').lower()
                    mapped_severity = self.SEVERITY_MAP.get(severity, 'medium')
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1

                    template_name = data.get('info', {}).get('name', 'Unknown')
                    template_id = data.get('template-id', '')
                    matched_at = data.get('matched-at', data.get('host', ''))

                    findings.append({
                        'category': 'vulnerability',
                        'severity': mapped_severity,
                        'title': template_name,
                        'description': (
                            f"Template: {template_id}\n"
                            f"Severity: {severity}\n"
                            f"Matched at: {matched_at}\n"
                            f"Type: {data.get('type', '')}"
                        ),
                        'url': matched_at,
                        'raw_data': data,
                        'tool': self.tool_name,
                    })
                except json.JSONDecodeError:
                    continue

        # Fall back to text output
        elif os.path.exists(text_file):
            output_files.append(text_file)
            with open(text_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    finding = self._parse_text_line(line)
                    if finding:
                        sev = finding.get('severity', 'medium')
                        severity_counts[sev] = severity_counts.get(sev, 0) + 1
                        findings.append(finding)

        # If neither file exists, try stdout
        elif stdout:
            for line in stdout.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                finding = self._parse_text_line(line)
                if finding:
                    sev = finding.get('severity', 'medium')
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                    findings.append(finding)

        stats = {
            'total_findings': len(findings),
            'severity_counts': severity_counts,
        }

        return {
            'findings': findings,
            'output_files': output_files,
            'stats': stats,
        }

    @staticmethod
    def _parse_text_line(line: str) -> dict:
        """Parse a text-format nuclei output line.

        Format: [template-id] [type] [severity] URL
        Example: [CVE-2021-44228] [http] [critical] https://example.com
        """
        # Nuclei text format includes severity in brackets
        severity = 'medium'  # default
        if '[critical]' in line:
            severity = 'critical'
        elif '[high]' in line:
            severity = 'high'
        elif '[medium]' in line:
            severity = 'medium'
        elif '[low]' in line:
            severity = 'low'
        elif '[info]' in line:
            severity = 'info'

        return {
            'category': 'vulnerability',
            'severity': severity,
            'title': 'Nuclei finding',
            'description': line,
            'raw_data': line,
            'tool': 'nuclei',
        }
