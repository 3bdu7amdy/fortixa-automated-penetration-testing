"""Tplmap runner - Server-Side Template Injection detection."""
import os
import re
import logging
from app.plugins.base import BaseToolRunner

logger = logging.getLogger(__name__)


class TplmapRunner(BaseToolRunner):
    """Runner for tplmap - Server-Side Template Injection (SSTI) detection.

    Detects and exploits SSTI vulnerabilities in web applications.
    """

    tool_name = 'tplmap'
    default_timeout = 600

    def build_command(self, target: str, options: dict) -> list:
        """Build tplmap command.

        Args:
            target: URL to test for SSTI
            options: Optional flags:
                - data: str - POST data
                - cookie: str - HTTP cookie header
                - header: str - HTTP header
                - engine: str - force a specific template engine
                - output_file: str - custom output path

        Returns:
            Command arguments list for subprocess.run.
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        cmd = ['tplmap', '-u', target]

        # POST data
        if 'data' in options:
            cmd.extend(['--data', options['data']])

        # Cookie
        if 'cookie' in options:
            cmd.extend(['--cookie', options['cookie']])

        # Custom header
        if 'header' in options:
            cmd.extend(['--header', options['header']])

        # Engine selection
        if 'engine' in options:
            cmd.extend(['--engine', options['engine']])

        return cmd

    def parse_output(self, stdout: str, stderr: str, output_dir: str) -> dict:
        """Parse tplmap output into findings.

        Tplmap reports SSTI vulnerabilities with markers like
        "template injection" or engine identification details.

        Returns:
            Dict with findings, output_files, and stats.
        """
        findings = []
        output_files = []
        ssti_count = 0
        engines_found = []

        raw_content = ''

        # Try reading from output file first
        output_file = os.path.join(output_dir, 'tplmap_output.txt')
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                raw_content = f.read()
            output_files.append(output_file)

        # Fall back to stdout
        if not raw_content and stdout:
            raw_content = stdout

        for line in raw_content.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            # Check for SSTI detection
            if 'template injection' in line.lower() or 'ssti' in line.lower():
                # Try to identify the engine
                engine = ''
                engine_match = re.search(
                    r"(Jinja2|Mako|Tornado|Twig|Freemarker|Velocity|Smarty|Erb|Erubis|Slim|Pug|Jade|Dot|Handlebars|Underscore|EJS|Blade|Thymeleaf|Pebble|Jinjava)",
                    line, re.IGNORECASE
                )
                if engine_match:
                    engine = engine_match.group(1)
                    if engine.lower() not in [e.lower() for e in engines_found]:
                        engines_found.append(engine)

                ssti_count += 1
                findings.append({
                    'category': 'ssti',
                    'severity': 'critical',
                    'title': f'SSTI vulnerability found{": " + engine if engine else ""}',
                    'description': line,
                    'raw_data': line,
                    'tool': self.tool_name,
                })
            elif 'engine' in line.lower() and ('found' in line.lower() or 'detected' in line.lower()):
                engine_match = re.search(
                    r"(Jinja2|Mako|Tornado|Twig|Freemarker|Velocity|Smarty|Erb|Erubis|Slim|Pug|Jade|Dot|Handlebars|Underscore|EJS|Blade|Thymeleaf|Pebble|Jinjava)",
                    line, re.IGNORECASE
                )
                if engine_match:
                    engine = engine_match.group(1)
                    if engine.lower() not in [e.lower() for e in engines_found]:
                        engines_found.append(engine)
                    ssti_count += 1
                    findings.append({
                        'category': 'ssti',
                        'severity': 'critical',
                        'title': f'Template engine detected: {engine}',
                        'description': line,
                        'raw_data': line,
                        'tool': self.tool_name,
                    })

        stats = {
            'ssti_found': ssti_count,
            'engines_detected': engines_found,
        }

        return {
            'findings': findings,
            'output_files': output_files,
            'stats': stats,
        }
