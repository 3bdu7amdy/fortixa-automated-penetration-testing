"""Dashboard routes - main dashboard page."""
from flask import Blueprint, render_template, session
from app.extensions import db
from app.models.user import User
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.notification import Notification
from app.utils.decorators import login_required

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
@dashboard_bp.route('/dashboard')
@login_required
def index():
    """Render the main dashboard with statistics."""
    user_id = session['user_id']
    user = db.session.get(User, user_id)

    # Get statistics
    projects = Project.query.filter_by(owner_id=user_id).all()
    project_ids = [p.id for p in projects]

    # Scan statistics
    total_scans = Scan.query.filter(Scan.initiated_by == user_id).count()
    running_scans = Scan.query.filter(Scan.initiated_by == user_id, Scan.status == 'running').count()
    completed_scans = Scan.query.filter(Scan.initiated_by == user_id, Scan.status == 'completed').count()

    # Finding statistics
    total_findings = Finding.query.filter(Finding.project_id.in_(project_ids)).count() if project_ids else 0
    findings_summary = {}
    if project_ids:
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            findings_summary[severity] = Finding.query.filter(
                Finding.project_id.in_(project_ids),
                Finding.severity == severity,
                Finding.is_duplicate == False,
                Finding.is_false_positive == False
            ).count()

    # Recent scans
    recent_scans = Scan.query.filter(Scan.initiated_by == user_id)\
        .order_by(Scan.created_at.desc()).limit(5).all()

    # Unread notifications
    unread_notifications = Notification.query.filter_by(
        user_id=user_id, is_read=False
    ).order_by(Notification.created_at.desc()).limit(5).all()

    return render_template('dashboard/index.html',
                           user=user,
                           projects=projects,
                           total_scans=total_scans,
                           running_scans=running_scans,
                           completed_scans=completed_scans,
                           total_findings=total_findings,
                           findings_summary=findings_summary,
                           recent_scans=recent_scans,
                           unread_notifications=unread_notifications)
