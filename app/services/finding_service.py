"""Finding service - handles finding query and management business logic."""
import logging
from app.extensions import db
from app.models.finding import Finding

logger = logging.getLogger(__name__)


class FindingService:
    """Handles all finding-related business logic."""

    def get_findings(self, scan_id=None, project_id=None, severity=None,
                     category=None, tool_name=None, is_false_positive=None,
                     is_duplicate=None, page=1, per_page=50):
        """Query findings with filters and pagination."""
        query = Finding.query

        if scan_id:
            query = query.filter_by(scan_id=scan_id)
        if project_id:
            query = query.filter_by(project_id=project_id)
        if severity:
            query = query.filter_by(severity=severity)
        if category:
            query = query.filter_by(category=category)
        if tool_name:
            query = query.filter_by(tool_name=tool_name)
        if is_false_positive is not None:
            query = query.filter_by(is_false_positive=is_false_positive)
        if is_duplicate is not None:
            query = query.filter_by(is_duplicate=is_duplicate)

        return query.order_by(Finding.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )

    def get_finding(self, finding_id):
        """Get a single finding by ID."""
        return db.session.get(Finding, finding_id)

    def mark_false_positive(self, finding_id, is_fp=True):
        """Mark or unmark a finding as false positive."""
        finding = db.session.get(Finding, finding_id)
        if not finding:
            return {'success': False, 'errors': ['Finding not found']}
        finding.is_false_positive = is_fp
        finding.save()
        logger.info(f"Finding {finding_id} marked as {'false positive' if is_fp else 'real'}")
        return {'success': True}

    def get_severity_summary(self, scan_id=None, project_id=None):
        """Get a severity breakdown summary."""
        query = Finding.query.filter_by(is_duplicate=False, is_false_positive=False)
        if scan_id:
            query = query.filter_by(scan_id=scan_id)
        if project_id:
            query = query.filter_by(project_id=project_id)

        findings = query.all()
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            if f.severity in summary:
                summary[f.severity] += 1
        return summary

    def get_category_summary(self, scan_id=None, project_id=None):
        """Get a category breakdown summary."""
        query = Finding.query.filter_by(is_duplicate=False, is_false_positive=False)
        if scan_id:
            query = query.filter_by(scan_id=scan_id)
        if project_id:
            query = query.filter_by(project_id=project_id)

        findings = query.all()
        categories = {}
        for f in findings:
            categories[f.category] = categories.get(f.category, 0) + 1
        return categories
