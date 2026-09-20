"""Finding model - a vulnerability or piece of information discovered during a scan."""
from app.extensions import db
from app.models.base import BaseModel


class Finding(BaseModel):
    """Finding model.

    A finding is a single vulnerability, subdomain, URL, or other
    piece of information discovered during a scan.
    """
    __tablename__ = 'findings'

    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False, index=True)
    scan_job_id = db.Column(db.Integer, db.ForeignKey('scan_jobs.id'), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey('targets.id'), nullable=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=True, index=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), nullable=False, default='info', index=True)
    category = db.Column(db.String(50), nullable=False, index=True)
    tool_name = db.Column(db.String(50), nullable=False, index=True)
    # Unified vulnerability category - groups multiple tools testing the same vuln
    # (e.g. dalfox + xsstrike both → 'XSS'). Populated by the worker at save time.
    vuln_category = db.Column(db.String(80), nullable=True, index=True)
    url = db.Column(db.Text, nullable=True, index=True)
    parameter = db.Column(db.String(255), nullable=True)
    payload = db.Column(db.Text, nullable=True)
    evidence = db.Column(db.Text, nullable=True)
    remediation = db.Column(db.Text, nullable=True)
    confidence = db.Column(db.String(20), nullable=False, default='tentative')
    is_false_positive = db.Column(db.Boolean, default=None, index=True)
    is_duplicate = db.Column(db.Boolean, default=False, index=True)
    duplicate_of_id = db.Column(db.Integer, db.ForeignKey('findings.id'), nullable=True)
    raw_output = db.Column(db.Text, nullable=True)
    cvss_score = db.Column(db.Float, nullable=True)
    cve_id = db.Column(db.String(20), nullable=True)

    # Relationships
    ai_analyses = db.relationship('AIAnalysisResult', backref='finding', lazy='dynamic')
    target = db.relationship('Target', backref='findings')
    project = db.relationship('Project', backref='findings')

    # Severity order for sorting
    SEVERITY_ORDER = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4, 'info': 5}

    def __repr__(self):
        return f'<Finding {self.title[:50]} [{self.severity}]>'
