"""Report service - handles report generation business logic."""
import json
import logging
import os
from datetime import datetime, timezone

from flask import current_app, render_template
from app.extensions import db
from app.models.report import Report
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.target import Target
from app.models.project import Project
from app.models.user import User

logger = logging.getLogger(__name__)


class ReportService:
    """Handles all report-related business logic."""

    def generate_report(self, scan_id, user_id, format='html', **kwargs):
        """Generate a report for a scan.

        Args:
            scan_id: ID of the scan to report on.
            user_id: ID of the user requesting the report.
            format: Report format - 'html', 'pdf', or 'json'.
            **kwargs: Additional options (title, includes_executive_summary, includes_remediation).

        Returns:
            dict with 'success' flag and 'report' or 'errors'.
        """
        # Validate format
        format = format.lower().strip()
        if format not in ('html', 'pdf', 'json'):
            return {'success': False, 'errors': [f'Unsupported report format: {format}']}

        # Fetch scan
        scan = db.session.get(Scan, scan_id)
        if not scan:
            return {'success': False, 'errors': ['Scan not found']}

        # Fetch related data
        target = db.session.get(Target, scan.target_id)
        project = db.session.get(Project, target.project_id) if target else None
        all_findings = Finding.query.filter_by(scan_id=scan_id).order_by(
            Finding.severity, Finding.created_at
        ).all()

        # Filter: separate actual vulnerabilities from recon data
        from app.utils.vuln_categories import is_vulnerability_category
        vulnerabilities = []
        recon_findings = []
        for f in all_findings:
            cat = f.vuln_category or f.category
            if is_vulnerability_category(cat):
                vulnerabilities.append(f)
            else:
                recon_findings.append(f)

        # Use vulnerabilities for the "Detailed Vulnerabilities" section
        findings = vulnerabilities

        # Get options
        title = kwargs.get('title') or f"Pentest Report - {scan.name}"
        includes_executive_summary = kwargs.get('includes_executive_summary', True)
        includes_remediation = kwargs.get('includes_remediation', True)

        # Count severities
        severity_counts = self._count_severities(findings)

        # Generate report based on format
        try:
            if format == 'html':
                file_path = self._generate_html_report(
                    scan, findings, target, project,
                    title=title,
                    includes_executive_summary=includes_executive_summary,
                    includes_remediation=includes_remediation,
                    severity_counts=severity_counts,
                )
            elif format == 'json':
                file_path = self._generate_json_report(
                    scan, findings, target, project,
                    title=title,
                    includes_executive_summary=includes_executive_summary,
                    includes_remediation=includes_remediation,
                    severity_counts=severity_counts,
                )
            elif format == 'pdf':
                file_path = self._generate_pdf_report(
                    scan, findings, target, project,
                    title=title,
                    includes_executive_summary=includes_executive_summary,
                    includes_remediation=includes_remediation,
                    severity_counts=severity_counts,
                )
            else:
                return {'success': False, 'errors': [f'Unsupported format: {format}']}
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return {'success': False, 'errors': [f'Report generation failed: {str(e)}']}

        # Get file size
        file_size = None
        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path)

        # Create Report record
        report = Report(
            scan_id=scan_id,
            generated_by=user_id,
            title=title,
            format=format,
            file_path=file_path,
            file_size=file_size,
            includes_executive_summary=includes_executive_summary,
            includes_remediation=includes_remediation,
            finding_count=len(findings),
            critical_count=severity_counts.get('critical', 0),
            high_count=severity_counts.get('high', 0),
            medium_count=severity_counts.get('medium', 0),
            low_count=severity_counts.get('low', 0),
            info_count=severity_counts.get('info', 0),
        )
        report.save()

        logger.info(f"Report generated: {report.title} [{report.format}] (ID: {report.id})")
        return {'success': True, 'report': report}

    def _generate_html_report(self, scan, findings, target, project, **kwargs):
        """Generate an HTML report using Jinja2 template.

        Returns:
            str: Path to the generated HTML file.
        """
        title = kwargs.get('title', 'Pentest Report')
        severity_counts = kwargs.get('severity_counts', {})
        includes_executive_summary = kwargs.get('includes_executive_summary', True)
        includes_remediation = kwargs.get('includes_remediation', True)

        executive_summary = ''
        if includes_executive_summary:
            executive_summary = self._generate_executive_summary(scan, findings, severity_counts)

        remediation_recommendations = []
        if includes_remediation:
            remediation_recommendations = self._generate_remediation(findings)

        # Render template
        html_content = render_template(
            'reports/report_html.html',
            title=title,
            scan=scan,
            findings=findings,
            target=target,
            project=project,
            severity_counts=severity_counts,
            executive_summary=executive_summary,
            remediation_recommendations=remediation_recommendations,
            includes_executive_summary=includes_executive_summary,
            includes_remediation=includes_remediation,
            generated_at=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
        )

        # Save to file
        output_dir = self._get_output_dir()
        filename = f"report_scan_{scan.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        file_path = os.path.join(output_dir, filename)

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return file_path

    def _generate_json_report(self, scan, findings, target, project, **kwargs):
        """Generate a JSON report.

        Returns:
            str: Path to the generated JSON file.
        """
        title = kwargs.get('title', 'Pentest Report')
        severity_counts = kwargs.get('severity_counts', {})
        includes_executive_summary = kwargs.get('includes_executive_summary', True)
        includes_remediation = kwargs.get('includes_remediation', True)

        # Build report structure
        report_data = {
            'metadata': {
                'title': title,
                'scan_id': scan.id,
                'scan_name': scan.name,
                'scan_type': scan.scan_type,
                'scan_status': scan.status,
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'project': {
                    'id': project.id,
                    'name': project.name,
                    'description': project.description,
                } if project else None,
                'target': {
                    'id': target.id,
                    'value': target.value,
                    'type': target.type,
                } if target else None,
            },
            'scope': {
                'target': target.value if target else 'Unknown',
                'target_type': target.type if target else 'Unknown',
                'scan_type': scan.scan_type,
                'started_at': scan.started_at.isoformat() if scan.started_at else None,
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            },
            'findings': [
                {
                    'id': f.id,
                    'title': f.title,
                    'description': f.description,
                    'severity': f.severity,
                    'category': f.category,
                    'tool_name': f.tool_name,
                    'url': f.url,
                    'parameter': f.parameter,
                    'payload': f.payload,
                    'evidence': f.evidence,
                    'remediation': f.remediation,
                    'confidence': f.confidence,
                    'cvss_score': f.cvss_score,
                    'cve_id': f.cve_id,
                    'is_false_positive': f.is_false_positive,
                    'is_duplicate': f.is_duplicate,
                }
                for f in findings
            ],
            'summary': {
                'total_findings': len(findings),
                'severity_counts': severity_counts,
                'critical': severity_counts.get('critical', 0),
                'high': severity_counts.get('high', 0),
                'medium': severity_counts.get('medium', 0),
                'low': severity_counts.get('low', 0),
                'info': severity_counts.get('info', 0),
            },
        }

        if includes_executive_summary:
            report_data['executive_summary'] = self._generate_executive_summary(
                scan, findings, severity_counts
            )

        if includes_remediation:
            report_data['recommendations'] = self._generate_remediation(findings)

        # Save to file
        output_dir = self._get_output_dir()
        filename = f"report_scan_{scan.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        file_path = os.path.join(output_dir, filename)

        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)

        return file_path

    def _generate_pdf_report(self, scan, findings, target, project, **kwargs):
        """Generate a PDF report.

        Tries weasyprint first; falls back to saving an HTML file
        with a .pdf-ready note if weasyprint is unavailable.

        Returns:
            str: Path to the generated PDF (or HTML fallback) file.
        """
        title = kwargs.get('title', 'Pentest Report')
        severity_counts = kwargs.get('severity_counts', {})
        includes_executive_summary = kwargs.get('includes_executive_summary', True)
        includes_remediation = kwargs.get('includes_remediation', True)

        executive_summary = ''
        if includes_executive_summary:
            executive_summary = self._generate_executive_summary(scan, findings, severity_counts)

        remediation_recommendations = []
        if includes_remediation:
            remediation_recommendations = self._generate_remediation(findings)

        html_content = render_template(
            'reports/report_html.html',
            title=title,
            scan=scan,
            findings=findings,
            target=target,
            project=project,
            severity_counts=severity_counts,
            executive_summary=executive_summary,
            remediation_recommendations=remediation_recommendations,
            includes_executive_summary=includes_executive_summary,
            includes_remediation=includes_remediation,
            generated_at=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
        )

        output_dir = self._get_output_dir()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Try weasyprint
        try:
            from weasyprint import HTML as WeasyHTML
            filename = f"report_scan_{scan.id}_{timestamp}.pdf"
            file_path = os.path.join(output_dir, filename)
            WeasyHTML(string=html_content).write_pdf(file_path)
            return file_path
        except ImportError:
            logger.warning("weasyprint not available; generating HTML instead of PDF")
        except Exception as e:
            logger.warning(f"weasyprint failed ({e}); generating HTML instead of PDF")

        # Fallback: save HTML with .html extension
        filename = f"report_scan_{scan.id}_{timestamp}_pdf_fallback.html"
        file_path = os.path.join(output_dir, filename)

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return file_path

    def list_reports(self, scan_id=None, user_id=None):
        """List generated reports.

        Args:
            scan_id: Optional filter by scan.
            user_id: Optional filter by generating user.

        Returns:
            list of Report objects.
        """
        query = Report.query
        if scan_id:
            query = query.filter_by(scan_id=scan_id)
        if user_id:
            query = query.filter_by(generated_by=user_id)
        return query.order_by(Report.created_at.desc()).all()

    def get_report(self, report_id, user_id):
        """Get a report by ID with ownership check.

        Args:
            report_id: ID of the report.
            user_id: ID of the requesting user.

        Returns:
            dict with 'success' flag and 'report' or 'errors'.
        """
        report = db.session.get(Report, report_id)
        if not report:
            return {'success': False, 'errors': ['Report not found']}
        if report.generated_by != user_id:
            return {'success': False, 'errors': ['Access denied']}
        return {'success': True, 'report': report}

    def download_report(self, report_id, user_id):
        """Get the file path for downloading a report.

        Args:
            report_id: ID of the report.
            user_id: ID of the requesting user.

        Returns:
            dict with 'success' flag and 'file_path' or 'errors'.
        """
        result = self.get_report(report_id, user_id)
        if not result['success']:
            return result

        report = result['report']
        if not report.file_path or not os.path.exists(report.file_path):
            return {'success': False, 'errors': ['Report file not found on disk']}

        return {'success': True, 'file_path': report.file_path, 'report': report}

    def delete_report(self, report_id, user_id):
        """Delete a report and its file.

        Args:
            report_id: ID of the report.
            user_id: ID of the requesting user.

        Returns:
            dict with 'success' flag.
        """
        result = self.get_report(report_id, user_id)
        if not result['success']:
            return result

        report = result['report']

        # Delete file from disk
        if report.file_path and os.path.exists(report.file_path):
            try:
                os.remove(report.file_path)
            except OSError as e:
                logger.warning(f"Failed to delete report file {report.file_path}: {e}")

        # Delete DB record
        report.delete()
        logger.info(f"Report deleted: {report.title} (ID: {report_id})")
        return {'success': True}

    def _count_severities(self, findings):
        """Count findings by severity level.

        Args:
            findings: List of Finding objects.

        Returns:
            dict mapping severity names to counts.
        """
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = f.severity.lower() if f.severity else 'info'
            if sev in counts:
                counts[sev] += 1
            else:
                counts['info'] += 1
        return counts

    def _generate_executive_summary(self, scan, findings, severity_counts):
        """Generate executive summary text.

        Args:
            scan: Scan object.
            findings: List of Finding objects.
            severity_counts: Dict of severity counts.

        Returns:
            str: Executive summary text.
        """
        total = len(findings)
        critical = severity_counts.get('critical', 0)
        high = severity_counts.get('high', 0)
        medium = severity_counts.get('medium', 0)
        low = severity_counts.get('low', 0)
        info = severity_counts.get('info', 0)

        # Determine overall risk level
        if critical > 0:
            risk_level = "CRITICAL"
            risk_desc = "Immediate action is required. Critical vulnerabilities were identified that could lead to complete system compromise."
        elif high > 0:
            risk_level = "HIGH"
            risk_desc = "Urgent attention is needed. Significant vulnerabilities were found that could be exploited by attackers."
        elif medium > 0:
            risk_level = "MODERATE"
            risk_desc = "Moderate risk vulnerabilities were identified. These should be addressed in a timely manner."
        elif low > 0:
            risk_level = "LOW"
            risk_desc = "Low-risk issues were identified. These represent minor security concerns."
        else:
            risk_level = "MINIMAL"
            risk_desc = "No significant vulnerabilities were identified during this assessment."

        # Get unique categories
        categories = list(set(f.category for f in findings)) if findings else []

        target_value = scan.target.value if scan.target else 'the target'

        summary = (
            f"This report presents the findings from a {scan.scan_type} security assessment "
            f"conducted against {target_value}. "
            f"The assessment identified a total of {total} finding(s): "
            f"{critical} Critical, {high} High, {medium} Medium, {low} Low, and {info} Informational.\n\n"
            f"Overall Risk Assessment: {risk_level}\n"
            f"{risk_desc}"
        )

        if categories:
            summary += f"\n\nAffected categories include: {', '.join(sorted(categories))}."

        return summary

    def _generate_remediation(self, findings):
        """Generate remediation recommendations.

        Args:
            findings: List of Finding objects.

        Returns:
            list of dicts with severity, title, and recommendation.
        """
        # Sort by severity order
        severity_order = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4, 'info': 5}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.severity.lower(), 99)
        )

        recommendations = []
        for f in sorted_findings:
            remediation = f.remediation or self._default_remediation(f)
            recommendations.append({
                'severity': f.severity,
                'title': f.title,
                'category': f.category,
                'recommendation': remediation,
                'url': f.url,
            })

        return recommendations

    def _default_remediation(self, finding):
        """Generate default remediation text based on finding category/severity.

        Args:
            finding: Finding object.

        Returns:
            str: Default remediation text.
        """
        category = finding.category.lower() if finding.category else ''
        severity = finding.severity.lower() if finding.severity else 'info'

        defaults = {
            'xss': 'Implement proper output encoding and use Content Security Policy (CSP) headers. Validate and sanitize all user input.',
            'sqli': 'Use parameterized queries or prepared statements. Implement input validation and use least-privilege database accounts.',
            'ssrf': 'Validate and whitelist allowed URLs/IPs. Implement network segmentation and use allow-lists for outbound requests.',
            'rce': 'Avoid passing user input to system commands. Use allow-lists and implement strict input validation.',
            'lfi': 'Validate and sanitize file paths. Use chroot jails and restrict file system access.',
            'rfi': 'Disable remote file inclusion in PHP configuration. Validate and sanitize all file paths.',
            'xxe': 'Disable external entity processing in XML parsers. Use JSON instead of XML where possible.',
            'subdomain': 'Review DNS configuration and ensure subdomains are properly secured or decommissioned if unused.',
            'live_host': 'Review exposed services and close unnecessary ports. Implement proper access controls.',
            'url': 'Review exposed endpoints and implement proper authentication and authorization controls.',
            'info': 'Review the identified information and assess whether it poses a security risk.',
        }

        for key, text in defaults.items():
            if key in category:
                return text

        if severity in ('critical', 'high'):
            return 'Address this finding with high priority. Conduct a thorough review and apply appropriate security controls.'
        elif severity == 'medium':
            return 'Address this finding in a timely manner. Implement recommended security controls and verify the fix.'
        else:
            return 'Review this finding and apply appropriate controls as part of regular maintenance.'

    def _get_output_dir(self):
        """Get or create the output directory for reports.

        Returns:
            str: Absolute path to the output directory.
        """
        output_dir = current_app.config.get('OUTPUT_DIR', 'output')
        # Make absolute if needed
        if not os.path.isabs(output_dir):
            output_dir = os.path.join(current_app.root_path, '..', output_dir)
        output_dir = os.path.abspath(output_dir)

        os.makedirs(output_dir, exist_ok=True)
        return output_dir

    # ── Sectioned reports (per-section download) ────────────────

    SECTION_NAMES = {
        'subdomains': 'Subdomains',
        'urls': 'URLs',
        'urls_with_params': 'URLs with Parameters',
        'vulnerabilities': 'Vulnerabilities',
        'all_findings': 'All Findings',
    }

    def generate_section_file(self, scan_id, section, fmt='txt'):
        """Generate a single section as TXT or HTML and return its path.

        Args:
            scan_id: The scan ID.
            section: One of: subdomains, urls, urls_with_params,
                     vulnerabilities, all_findings.
            fmt: 'txt' or 'html'.

        Returns:
            dict with 'success', 'file_path', 'filename', 'mimetype'.
        """
        scan = db.session.get(Scan, scan_id)
        if not scan:
            return {'success': False, 'errors': ['Scan not found']}

        fmt = (fmt or 'txt').lower()
        if fmt not in ('txt', 'html'):
            fmt = 'txt'

        content = self._build_section_content(scan, section, fmt)
        output_dir = self._get_output_dir()
        ext = 'html' if fmt == 'html' else 'txt'
        filename = f"scan_{scan.id}_{section}.{ext}"
        file_path = os.path.join(output_dir, filename)

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

        mimetype = 'text/html' if fmt == 'html' else 'text/plain'
        return {
            'success': True,
            'file_path': file_path,
            'filename': filename,
            'mimetype': mimetype,
        }

    def _build_section_content(self, scan, section, fmt):
        """Build the textual or HTML content for one section."""
        is_html = (fmt == 'html')

        if section == 'subdomains':
            subs = scan.get_subdomains()
            lines = [s['subdomain'] for s in subs]
            if is_html:
                return self._html_wrap(f"Subdomains — {scan.name}", lines, 'subdomains')
            return '\n'.join(lines)

        elif section == 'urls':
            urls = scan.get_urls()
            lines = [u['url'] for u in urls]
            if is_html:
                return self._html_wrap(f"URLs — {scan.name}", lines, 'urls')
            return '\n'.join(lines)

        elif section == 'urls_with_params':
            urls = scan.get_urls()
            lines = [u['url'] for u in urls if u['has_parameters']]
            if is_html:
                return self._html_wrap(f"URLs with Parameters — {scan.name}",
                                       lines, 'urls_with_params')
            return '\n'.join(lines)

        elif section == 'vulnerabilities':
            grouped = scan.get_vulnerabilities_grouped()
            if is_html:
                return self._html_vuln_wrap(scan, grouped)
            # Plain text: one section per category
            out = []
            for cat, items in grouped.items():
                out.append(f"\n{'='*60}\n{cat} ({len(items)} findings)\n{'='*60}\n")
                for i, it in enumerate(items, 1):
                    out.append(f"{i}. [{it['severity'].upper()}] {it['title']}\n")
                    out.append(f"   Tool: {it['tool_name']}\n")
                    if it['url']:
                        out.append(f"   URL: {it['url']}\n")
                    if it['cvss_score']:
                        out.append(f"   CVSS: {it['cvss_score']}\n")
                    if it['cve_id']:
                        out.append(f"   CVE: {it['cve_id']}\n")
                    if it['description']:
                        out.append(f"   Description: {it['description'][:200]}\n")
                    if it['evidence']:
                        out.append(f"   Evidence: {it['evidence'][:200]}\n")
                    if it['remediation']:
                        out.append(f"   Remediation: {it['remediation'][:200]}\n")
                    out.append("")
            return '\n'.join(out) if out else 'No vulnerabilities found.'

        elif section == 'all_findings':
            findings = Finding.query.filter_by(scan_id=scan.id, is_duplicate=False).all()
            if is_html:
                lines = [f"[{f.severity}] {f.title} — {f.tool_name} — {f.url or ''}"
                         for f in findings]
                return self._html_wrap(f"All Findings — {scan.name}", lines, 'findings')
            return '\n'.join(
                f"[{f.severity.upper()}] {f.title} | tool={f.tool_name} | url={f.url or ''}"
                for f in findings
            )

        return 'Unknown section.'

    def _html_wrap(self, title, lines, css_class):
        """Wrap a list of lines in a minimal HTML document."""
        items = ''.join(f'<li>{line}</li>' for line in lines)
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; color: #222; }}
h1 {{ color: #1a73e8; border-bottom: 2px solid #1a73e8; padding-bottom: 10px; }}
ul {{ list-style: none; padding: 0; }}
li {{ padding: 8px 12px; border-bottom: 1px solid #eee; word-break: break-all; }}
li:hover {{ background: #f7f9fc; }}
.count {{ color: #666; font-size: 14px; }}
</style>
</head>
<body>
<h1>{title}</h1>
<p class="count">{len(lines)} item(s)</p>
<ul class="{css_class}">{items}</ul>
</body>
</html>"""

    def _html_vuln_wrap(self, scan, grouped):
        """Build an HTML document with vulnerabilities grouped by category."""
        sections = []
        for cat, items in grouped.items():
            rows = ''.join(f"""
                <tr>
                    <td>{i.get('title','')}</td>
                    <td><span class="sev sev-{i.get('severity','info')}">{i.get('severity','')}</span></td>
                    <td>{i.get('tool_name','')}</td>
                    <td>{i.get('url') or ''}</td>
                    <td>{i.get('cvss_score') or ''}</td>
                </tr>""" for i in items)
            sections.append(f"""
                <div class="vuln-cat">
                    <h2>{cat} <span class="cat-count">({len(items)})</span></h2>
                    <table>
                        <thead><tr>
                            <th>Title</th><th>Severity</th><th>Tool</th>
                            <th>URL</th><th>CVSS</th>
                        </tr></thead>
                        <tbody>{rows}</tbody>
                    </table>
                </div>""")
        sections_html = '\n'.join(sections) if sections else '<p>No vulnerabilities found.</p>'
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Vulnerabilities — {scan.name}</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; color: #222; }}
h1 {{ color: #d32f2f; border-bottom: 2px solid #d32f2f; padding-bottom: 10px; }}
h2 {{ color: #1a73e8; margin-top: 30px; }}
.cat-count {{ color: #666; font-size: 14px; font-weight: normal; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #ddd; }}
th {{ background: #f5f5f5; }}
tr:hover {{ background: #fafafa; }}
.sev {{ padding: 2px 8px; border-radius: 3px; font-size: 11px; text-transform: uppercase; }}
.sev-critical {{ background: #d32f2f; color: white; }}
.sev-high {{ background: #f57c00; color: white; }}
.sev-medium {{ background: #fbc02d; color: black; }}
.sev-low {{ background: #388e3c; color: white; }}
.sev-info {{ background: #90a4ae; color: white; }}
</style>
</head>
<body>
<h1>Vulnerabilities — {scan.name}</h1>
{sections_html}
</body>
</html>"""

    def generate_custom_report(self, scan_id, user_id, sections, fmt='txt'):
        """Generate a custom report with only the selected sections.

        Args:
            scan_id: Scan ID.
            user_id: Requesting user ID (for ownership check).
            sections: List of section names to include.
            fmt: 'txt' (returns a ZIP of separate files) or 'html' (single file).

        Returns:
            dict with 'success', 'file_path', 'filename', 'mimetype'.
        """
        scan = db.session.get(Scan, scan_id)
        if not scan:
            return {'success': False, 'errors': ['Scan not found']}

        valid_sections = [s for s in sections if s in self.SECTION_NAMES]
        if not valid_sections:
            return {'success': False, 'errors': ['No valid sections selected']}

        output_dir = self._get_output_dir()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        if fmt == 'txt':
            # Build a ZIP of separate .txt files
            import zipfile
            zip_path = os.path.join(output_dir,
                f"report_scan_{scan.id}_{timestamp}.zip")
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                for section in valid_sections:
                    content = self._build_section_content(scan, section, 'txt')
                    zf.writestr(f"{section}.txt", content)
            return {
                'success': True,
                'file_path': zip_path,
                'filename': f"report_scan_{scan.id}_{timestamp}.zip",
                'mimetype': 'application/zip',
            }

        elif fmt == 'html':
            # Build a single HTML file with all selected sections
            parts = [f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Report — {scan.name}</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; color: #222; }}
h1 {{ color: #1a73e8; border-bottom: 3px solid #1a73e8; padding-bottom: 10px; }}
h2 {{ color: #333; margin-top: 40px; border-bottom: 1px solid #ddd; padding-bottom: 5px; }}
.meta {{ color: #666; margin-bottom: 30px; }}
ul {{ list-style: none; padding: 0; }}
li {{ padding: 8px 12px; border-bottom: 1px solid #eee; word-break: break-all; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #ddd; }}
th {{ background: #f5f5f5; }}
.sev {{ padding: 2px 8px; border-radius: 3px; font-size: 11px; text-transform: uppercase; }}
.sev-critical {{ background: #d32f2f; color: white; }}
.sev-high {{ background: #f57c00; color: white; }}
.sev-medium {{ background: #fbc02d; color: black; }}
.sev-low {{ background: #388e3c; color: white; }}
.sev-info {{ background: #90a4ae; color: white; }}
.section-divider {{ height: 40px; }}
.download-link {{ display: inline-block; margin-top: 10px; padding: 6px 14px;
                  background: #1a73e8; color: white; text-decoration: none;
                  border-radius: 4px; font-size: 13px; }}
</style>
</head>
<body>
<h1>Pentest Report — {scan.name}</h1>
<div class="meta">
    <strong>Target:</strong> {scan.target_value}<br>
    <strong>Status:</strong> {scan.status}<br>
    <strong>Generated:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
</div>
"""]

            for section in valid_sections:
                label = self.SECTION_NAMES[section]
                parts.append(f'<h2>{label}</h2>')
                parts.append(
                    f'<a class="download-link" href="/reports/section/{scan.id}/{section}?fmt=txt">⬇ Download this section as .txt</a>'
                )
                parts.append('<div class="section-divider"></div>')
                # Embed the section content (without the full HTML wrapper)
                if section == 'vulnerabilities':
                    grouped = scan.get_vulnerabilities_grouped()
                    for cat, items in grouped.items():
                        parts.append(f'<h3>{cat} ({len(items)})</h3>')
                        rows = ''.join(f"""
                            <tr>
                                <td>{i.get('title','')}</td>
                                <td><span class="sev sev-{i.get('severity','info')}">{i.get('severity','')}</span></td>
                                <td>{i.get('tool_name','')}</td>
                                <td>{i.get('url') or ''}</td>
                            </tr>""" for i in items)
                        parts.append(f'<table><thead><tr><th>Title</th><th>Severity</th><th>Tool</th><th>URL</th></tr></thead><tbody>{rows}</tbody></table>')
                elif section == 'subdomains':
                    subs = scan.get_subdomains()
                    items = ''.join(f'<li>{s["subdomain"]}</li>' for s in subs)
                    parts.append(f'<p>{len(subs)} subdomain(s)</p><ul>{items}</ul>')
                elif section in ('urls', 'urls_with_params'):
                    urls = scan.get_urls()
                    if section == 'urls_with_params':
                        urls = [u for u in urls if u['has_parameters']]
                    items = ''.join(f'<li>{u["url"]}</li>' for u in urls)
                    parts.append(f'<p>{len(urls)} URL(s)</p><ul>{items}</ul>')
                elif section == 'all_findings':
                    findings = Finding.query.filter_by(scan_id=scan.id, is_duplicate=False).all()
                    items = ''.join(
                        f'<li>[{f.severity.upper()}] {f.title} — {f.tool_name} — {f.url or ""}</li>'
                        for f in findings
                    )
                    parts.append(f'<p>{len(findings)} finding(s)</p><ul>{items}</ul>')

            parts.append('</body></html>')
            content = '\n'.join(parts)

            file_path = os.path.join(output_dir,
                f"report_scan_{scan.id}_{timestamp}.html")
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)

            return {
                'success': True,
                'file_path': file_path,
                'filename': f"report_scan_{scan.id}_{timestamp}.html",
                'mimetype': 'text/html',
            }

        return {'success': False, 'errors': [f'Unsupported format: {fmt}']}
