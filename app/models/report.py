"""Report model - generated reports and their metadata."""
from app.extensions import db
from app.models.base import BaseModel


class Report(BaseModel):
    """Report model.

    Stores generated reports and their metadata including
    severity counts for quick display without re-querying findings.
    """
    __tablename__ = 'reports'

    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False, index=True)
    generated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    format = db.Column(db.String(10), nullable=False, index=True)  # html, pdf, json
    file_path = db.Column(db.String(512), nullable=False)
    file_size = db.Column(db.Integer, nullable=True)
    includes_executive_summary = db.Column(db.Boolean, nullable=False, default=False)
    includes_remediation = db.Column(db.Boolean, nullable=False, default=True)
    finding_count = db.Column(db.Integer, nullable=False, default=0)
    critical_count = db.Column(db.Integer, nullable=False, default=0)
    high_count = db.Column(db.Integer, nullable=False, default=0)
    medium_count = db.Column(db.Integer, nullable=False, default=0)
    low_count = db.Column(db.Integer, nullable=False, default=0)
    info_count = db.Column(db.Integer, nullable=False, default=0)

    generator = db.relationship('User', backref='reports')

    def __repr__(self):
        return f'<Report {self.title} [{self.format}]>'
