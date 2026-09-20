"""AI analysis routes - run AI analysis and review results."""
import json
import logging

from flask import Blueprint, render_template, redirect, url_for, flash, session, request, jsonify

from app.services.ai_service import AIService
from app.models.scan import Scan
from app.models.ai_analysis_result import AIAnalysisResult
from app.models.finding import Finding
from app.utils.decorators import login_required

logger = logging.getLogger(__name__)

ai_bp = Blueprint('ai', __name__, url_prefix='/ai')
ai_service = AIService()


@ai_bp.route('/analyze/<int:scan_id>', methods=['POST'])
@login_required
def analyze_scan(scan_id):
    """Run AI analysis on a scan."""
    scan = Scan.query.get_or_404(scan_id)

    if scan.status not in ('completed', 'failed'):
        flash('AI analysis can only be run on completed scans.', 'warning')
        return redirect(url_for('scans.view_scan', scan_id=scan_id))

    result = ai_service.analyze_scan(scan_id)

    if result['success']:
        flash(
            f"AI analysis complete: "
            f"{result['duplicates_found']} duplicates, "
            f"{result['severity_suggestions']} severity suggestions, "
            f"{result['potential_false_positives']} potential false positives, "
            f"{result['recommendations_generated']} recommendations.",
            'success',
        )
    else:
        for error in result.get('errors', ['Unknown error']):
            flash(error, 'error')

    return redirect(url_for('ai.results', scan_id=scan_id))


@ai_bp.route('/results/<int:scan_id>')
@login_required
def results(scan_id):
    """Show AI analysis results for a scan."""
    scan = Scan.query.get_or_404(scan_id)

    all_results = ai_service.get_analysis_results(scan_id)

    # Group by analysis type
    grouped = {
        'deduplication': [],
        'severity_suggestion': [],
        'false_positive': [],
        'recommendation': [],
    }
    for r in all_results:
        group = grouped.setdefault(r.analysis_type, [])
        group.append(r)

    return render_template(
        'ai/results.html',
        scan=scan,
        grouped=grouped,
        total_results=len(all_results),
    )


@ai_bp.route('/findings/<int:finding_id>/review', methods=['POST'])
@login_required
def review_finding(finding_id):
    """Accept or reject an AI suggestion."""
    finding = Finding.query.get_or_404(finding_id)
    analysis_type = request.form.get('analysis_type')
    action = request.form.get('action')  # 'accept' or 'reject'

    if not analysis_type or action not in ('accept', 'reject'):
        flash('Invalid review parameters.', 'error')
        return redirect(request.referrer or url_for('scans.list_scans'))

    accept = action == 'accept'
    result = ai_service.review_finding(finding_id, analysis_type, accept)

    if result['success']:
        flash(
            f"Suggestion {'accepted' if accept else 'rejected'} successfully.",
            'success',
        )
    else:
        for error in result.get('errors', ['Unknown error']):
            flash(error, 'error')

    # Redirect back to the AI results page for the scan
    return redirect(url_for('ai.results', scan_id=finding.scan_id))
