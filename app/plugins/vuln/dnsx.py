"""Dnsx runner - DNS toolkit for analysis."""
import os
import json
import logging
from app.plugins.base import BaseToolRunner

logger = logging.getLogger(__name__)


class DnsxRunner(BaseToolRunner):
    """Runner for dnsx - fast DNS toolkit for analysis.

    Performs DNS queries including A, CNAME, and other record lookups.
    """

    tool_name = 'dnsx'
    default_timeout = 300

    def build_command(self, target: str, options: dict) -> list:
        """Build dnsx command.

        Args:
            target: Domain to perform DNS analysis on
            options: Optional flags:
                - domain_list: str - path to file with domains
                - a: bool (default True) - resolve A records
                - cname: bool (default True) - resolve CNAME records
                - txt: bool - resolve TXT records
                - mx: bool - resolve MX records
                - ns: bool - resolve NS records
                - json: bool (default True) - JSON output
                - output_file: str - custom output path
                - resolver: str - custom DNS resolver

        Returns:
            Command arguments list for subprocess.run.
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        # File input mode or single domain
        domain_list = options.get('domain_list')
        if domain_list:
            if not os.path.isabs(domain_list):
                raise ValueError("domain_list must be an absolute path")
            cmd = ['dnsx', '-l', domain_list]
        else:
            cmd = ['dnsx', '-d', target]

        # Record types
        if options.get('a', True):
            cmd.append('-a')
        if options.get('cname', True):
            cmd.append('-cname')
        if options.get('txt'):
            cmd.append('-txt')
        if options.get('mx'):
            cmd.append('-mx')
        if options.get('ns'):
            cmd.append('-ns')

        # JSON output
        if options.get('json', True):
            cmd.append('-json')

        # Custom resolver
        if 'resolver' in options:
            cmd.extend(['-r', options['resolver']])

        return cmd

    def parse_output(self, stdout: str, stderr: str, output_dir: str) -> dict:
        """Parse dnsx output into findings.

        Dnsx outputs DNS records either in JSON format (one per line)
        or plain text format.

        Returns:
            Dict with findings, output_files, and stats.
        """
        findings = []
        output_files = []
        domains_resolved = []
        record_types_found = set()

        raw_content = ''

        # Try reading from output file first
        output_file = os.path.join(output_dir, 'dnsx_output.txt')
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                raw_content = f.read()
            output_files.append(output_file)

        # Fall back to stdout
        if not raw_content and stdout:
            raw_content = stdout

        # Try JSON parsing first
        json_parsed = False
        for line in raw_content.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                json_parsed = True
                host = data.get('host', '')
                a_records = data.get('a', [])
                cname_records = data.get('cname', [])
                txt_records = data.get('txt', [])
                mx_records = data.get('mx', [])
                ns_records = data.get('ns', [])

                if host:
                    domains_resolved.append(host)

                description_parts = []
                if a_records:
                    record_types_found.add('A')
                    description_parts.append(f"A: {', '.join(a_records)}")
                if cname_records:
                    record_types_found.add('CNAME')
                    description_parts.append(f"CNAME: {', '.join(cname_records)}")
                if txt_records:
                    record_types_found.add('TXT')
                    description_parts.append(f"TXT: {', '.join(txt_records)}")
                if mx_records:
                    record_types_found.add('MX')
                    description_parts.append(f"MX: {', '.join(mx_records)}")
                if ns_records:
                    record_types_found.add('NS')
                    description_parts.append(f"NS: {', '.join(ns_records)}")

                if description_parts:
                    findings.append({
                        'category': 'dns',
                        'severity': 'info',
                        'title': f'DNS records for {host}',
                        'description': '; '.join(description_parts),
                        'raw_data': data,
                        'tool': self.tool_name,
                    })
            except json.JSONDecodeError:
                continue

        # Fall back to text parsing
        if not json_parsed:
            for line in raw_content.strip().splitlines():
                line = line.strip()
                if not line:
                    continue

                # dnsx text format: host [record_type] value
                findings.append({
                    'category': 'dns',
                    'severity': 'info',
                    'title': 'DNS record found',
                    'description': line,
                    'raw_data': line,
                    'tool': self.tool_name,
                })

                # Try to extract domain
                domain_match = line.split()[0] if line.split() else ''
                if domain_match and domain_match not in domains_resolved:
                    domains_resolved.append(domain_match)

        stats = {
            'domains_resolved': len(domains_resolved),
            'record_types': list(record_types_found) if record_types_found else ['unknown'],
        }

        return {
            'findings': findings,
            'output_files': output_files,
            'stats': stats,
        }
