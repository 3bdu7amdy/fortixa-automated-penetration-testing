"""API routes - JSON endpoints for AJAX interactions."""
from flask import Blueprint, jsonify, request, session
from app.models.scan import Scan
from app.models.scan_job import ScanJob
from app.models.finding import Finding
from app.models.project import Project
from app.models.notification import Notification
from app.utils.decorators import login_required

api_bp = Blueprint('api', __name__, url_prefix='/api')


@api_bp.route('/stats')
@login_required
def dashboard_stats():
    """Get dashboard statistics as JSON."""
    user_id = session['user_id']
    projects = Project.query.filter_by(owner_id=user_id).all()
    project_ids = [p.id for p in projects]

    total_scans = Scan.query.filter(Scan.initiated_by == user_id).count()
    running_scans = Scan.query.filter(Scan.initiated_by == user_id, Scan.status == 'running').count()
    total_findings = Finding.query.filter(Finding.project_id.in_(project_ids)).count() if project_ids else 0

    severity_counts = {}
    if project_ids:
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            severity_counts[sev] = Finding.query.filter(
                Finding.project_id.in_(project_ids),
                Finding.severity == sev,
                Finding.is_duplicate == False,
                Finding.is_false_positive == False
            ).count()

    return jsonify({
        'total_scans': total_scans,
        'running_scans': running_scans,
        'total_findings': total_findings,
        'severity_counts': severity_counts,
        'total_projects': len(projects)
    })


@api_bp.route('/dashboard/charts')
@login_required
def dashboard_charts():
    """Get chart data for dashboard visualizations."""
    user_id = session['user_id']
    projects = Project.query.filter_by(owner_id=user_id).all()
    project_ids = [p.id for p in projects]

    # Severity distribution for bar chart
    severity_data = []
    severity_colors = {
        'critical': '#f85149',
        'high': '#f0883e',
        'medium': '#d29922',
        'low': '#3fb950',
        'info': '#58a6ff'
    }
    total_findings = 0
    if project_ids:
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            count = Finding.query.filter(
                Finding.project_id.in_(project_ids),
                Finding.severity == sev,
                Finding.is_duplicate == False,
                Finding.is_false_positive == False
            ).count()
            total_findings += count
            severity_data.append({
                'severity': sev,
                'count': count,
                'color': severity_colors.get(sev, '#8b949e')
            })
    else:
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            severity_data.append({
                'severity': sev,
                'count': 0,
                'color': severity_colors.get(sev, '#8b949e')
            })

    # Active scans with progress
    active_scans = Scan.query.filter(
        Scan.initiated_by == user_id,
        Scan.status.in_(['running', 'pending'])
    ).order_by(Scan.created_at.desc()).all()

    active_scans_data = []
    for scan in active_scans:
        target_value = scan.target.value if scan.target else 'Unknown'
        active_scans_data.append({
            'id': scan.id,
            'name': scan.name,
            'target': target_value,
            'status': scan.status,
            'progress': scan.progress_percentage,
            'total_jobs': scan.total_jobs,
            'completed_jobs': scan.completed_jobs,
            'failed_jobs': scan.failed_jobs,
            'scan_type': scan.scan_type,
            'created_at': scan.created_at.isoformat() if scan.created_at else None
        })

    return jsonify({
        'severity_distribution': severity_data,
        'total_findings': total_findings,
        'active_scans': active_scans_data
    })


@api_bp.route('/scans/<int:scan_id>/status')
@login_required
def scan_status(scan_id):
    """Get scan status as JSON for AJAX polling."""
    scan = Scan.query.get_or_404(scan_id)
    jobs = ScanJob.query.filter_by(scan_id=scan_id).all()
    return jsonify({
        'scan_id': scan.id,
        'status': scan.status,
        'progress': scan.progress_percentage,
        'total_jobs': scan.total_jobs,
        'completed_jobs': scan.completed_jobs,
        'failed_jobs': scan.failed_jobs,
        'jobs': [{
            'id': j.id,
            'tool_name': j.tool_name,
            'status': j.status,
            'started_at': j.started_at.isoformat() if j.started_at else None,
            'completed_at': j.completed_at.isoformat() if j.completed_at else None,
        } for j in jobs]
    })


@api_bp.route('/notifications')
@login_required
def get_notifications():
    """Get unread notifications for the current user."""
    user_id = session['user_id']
    notifications = Notification.query.filter_by(
        user_id=user_id, is_read=False
    ).order_by(Notification.created_at.desc()).limit(10).all()

    return jsonify([{
        'id': n.id,
        'title': n.title,
        'message': n.message,
        'type': n.type,
        'created_at': n.created_at.isoformat()
    } for n in notifications])


@api_bp.route('/notifications/<int:notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    """Mark a notification as read."""
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id == session['user_id']:
        notification.is_read = True
        notification.save()
    return jsonify({'success': True})


@api_bp.route('/notifications/read-all', methods=['POST'])
@login_required
def mark_all_notifications_read():
    """Mark all notifications as read for the current user."""
    user_id = session['user_id']
    unread = Notification.query.filter_by(user_id=user_id, is_read=False).all()
    for notification in unread:
        notification.is_read = True
    from app.extensions import db
    db.session.commit()
    return jsonify({'success': True, 'marked_count': len(unread)})


@api_bp.route('/notifications/count')
@login_required
def notification_count():
    """Get unread notification count for the current user."""
    user_id = session['user_id']
    count = Notification.query.filter_by(user_id=user_id, is_read=False).count()
    return jsonify({'unread_count': count})


@api_bp.route('/findings/<int:finding_id>/false-positive', methods=['POST'])
@login_required
def toggle_false_positive(finding_id):
    """Mark or unmark a finding as false positive."""
    from app.services.finding_service import FindingService
    service = FindingService()
    is_fp = request.json.get('is_false_positive', True) if request.is_json else True
    result = service.mark_false_positive(finding_id, is_fp)
    return jsonify(result)
