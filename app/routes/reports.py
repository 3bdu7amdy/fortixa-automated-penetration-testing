"""Report routes - report generation and management."""
import os

from flask import (
    Blueprint, render_template, redirect, url_for,
    request, flash, session, send_file, jsonify
)
from app.services.report_service import ReportService
from app.models.scan import Scan
from app.models.report import Report
from app.utils.decorators import login_required

reports_bp = Blueprint('reports', __name__, url_prefix='/reports')
report_service = ReportService()


@reports_bp.route('/')
@login_required
def list_reports():
    """List all reports for the current user."""
    user_id = session['user_id']
    scan_id = request.args.get('scan_id', type=int)

    reports = report_service.list_reports(scan_id=scan_id, user_id=user_id)

    return render_template('reports/list.html', reports=reports, scan_id=scan_id)


@reports_bp.route('/<int:report_id>')
@login_required
def view_report(report_id):
    """View report metadata."""
    user_id = session['user_id']
    result = report_service.get_report(report_id, user_id)

    if not result['success']:
        for error in result['errors']:
            flash(error, 'error')
        return redirect(url_for('reports.list_reports'))

    report = result['report']

    # For HTML reports, try to read content for preview
    preview_content = None
    if report.format == 'html' and report.file_path and os.path.exists(report.file_path):
        try:
            with open(report.file_path, 'r', encoding='utf-8') as f:
                preview_content = f.read()
        except OSError:
            preview_content = None

    return render_template('reports/view.html', report=report, preview_content=preview_content)


@reports_bp.route('/generate', methods=['GET', 'POST'])
@login_required
def generate_report():
    """Generate a new report.

    Supports two modes:
        - 'full' (legacy): generates HTML / PDF / JSON via the original service.
        - 'custom': lets the user pick sections + format (TXT-ZIP or HTML).
    """
    if request.method == 'POST':
        scan_id = request.form.get('scan_id', type=int)
        mode = request.form.get('mode', 'full')

        if not scan_id:
            flash('Please select a scan.', 'error')
            return redirect(url_for('reports.generate_report'))

        if mode == 'custom':
            # Sectioned custom report
            sections = request.form.getlist('sections')
            fmt = request.form.get('format', 'txt')

            if not sections:
                flash('Please select at least one section.', 'error')
                return redirect(url_for('reports.generate_report', scan_id=scan_id))

            result = report_service.generate_custom_report(
                scan_id=scan_id,
                user_id=session['user_id'],
                sections=sections,
                fmt=fmt,
            )

            if result['success']:
                flash(f'Custom {fmt.upper()} report generated.', 'success')
                return send_file(
                    result['file_path'],
                    mimetype=result['mimetype'],
                    as_attachment=True,
                    download_name=result['filename'],
                )
            for error in result.get('errors', []):
                flash(error, 'error')
            return redirect(url_for('reports.generate_report', scan_id=scan_id))

        else:
            # Full report (legacy HTML/PDF/JSON)
            report_format = request.form.get('format', 'html')
            title = request.form.get('title', '').strip()
            includes_executive_summary = request.form.get('includes_executive_summary') == 'on'
            includes_remediation = request.form.get('includes_remediation') == 'on'

            kwargs = {
                'includes_executive_summary': includes_executive_summary,
                'includes_remediation': includes_remediation,
            }
            if title:
                kwargs['title'] = title

            result = report_service.generate_report(
                scan_id=scan_id,
                user_id=session['user_id'],
                format=report_format,
                **kwargs
            )

            if result['success']:
                flash(f'Report generated successfully in {report_format.upper()} format.', 'success')
                return redirect(url_for('reports.view_report', report_id=result['report'].id))
            for error in result['errors']:
                flash(error, 'error')

    # GET: Show generation form
    user_id = session['user_id']
    scans = Scan.query.filter_by(initiated_by=user_id).order_by(Scan.created_at.desc()).all()

    # Pre-select scan if scan_id provided
    preselected_scan_id = request.args.get('scan_id', type=int)

    return render_template(
        'reports/generate.html',
        scans=scans,
        preselected_scan_id=preselected_scan_id,
    )


@reports_bp.route('/section/<int:scan_id>/<section>')
@login_required
def download_section(scan_id, section):
    """Download a single section as TXT or HTML.

    Query params:
        ?fmt=txt  (default)
        ?fmt=html
    """
    fmt = request.args.get('fmt', 'txt')
    result = report_service.generate_section_file(scan_id, section, fmt=fmt)

    if not result['success']:
        for error in result['errors']:
            flash(error, 'error')
        return redirect(url_for('reports.list_reports'))

    return send_file(
        result['file_path'],
        mimetype=result['mimetype'],
        as_attachment=True,
        download_name=result['filename'],
    )


@reports_bp.route('/<int:report_id>/download')
@login_required
def download_report(report_id):
    """Download a report file."""
    user_id = session['user_id']
    result = report_service.download_report(report_id, user_id)

    if not result['success']:
        for error in result['errors']:
            flash(error, 'error')
        return redirect(url_for('reports.list_reports'))

    file_path = result['file_path']
    report = result['report']

    # Determine mimetype and download name
    if report.format == 'json':
        mimetype = 'application/json'
        download_name = os.path.basename(file_path)
    elif report.format == 'pdf':
        mimetype = 'application/pdf'
        download_name = os.path.basename(file_path)
    else:
        mimetype = 'text/html'
        download_name = os.path.basename(file_path)

    return send_file(
        file_path,
        mimetype=mimetype,
        as_attachment=True,
        download_name=download_name,
    )


@reports_bp.route('/<int:report_id>/delete', methods=['POST'])
@login_required
def delete_report(report_id):
    """Delete a report."""
    user_id = session['user_id']
    result = report_service.delete_report(report_id, user_id)

    if result['success']:
        flash('Report deleted successfully.', 'success')
    else:
        for error in result['errors']:
            flash(error, 'error')

    return redirect(url_for('reports.list_reports'))
