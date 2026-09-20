"""Project model - represents a security engagement."""
from app.extensions import db
from app.models.base import BaseModel


class Project(BaseModel):
    """Project model.

    A project represents a security engagement. It groups targets,
    scans, and findings together.
    """
    __tablename__ = 'projects'

    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    status = db.Column(db.String(20), nullable=False, default='active', index=True)

    # Relationships
    targets = db.relationship('Target', backref='project', lazy='dynamic')
    configurations = db.relationship('Configuration', backref='project', lazy='dynamic')

    def __repr__(self):
        return f'<Project {self.name}>'

    def get_findings_count(self):
        """Get total findings count for this project."""
        from app.models.finding import Finding
        return Finding.query.filter_by(project_id=self.id).count()

    def get_findings_by_severity(self):
        """Get findings grouped by severity for this project."""
        from app.models.finding import Finding
        from sqlalchemy import or_
        counts = {}
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            counts[severity] = Finding.query.filter_by(
                project_id=self.id, severity=severity, is_duplicate=False
            ).filter(
                or_(Finding.is_false_positive == False, Finding.is_false_positive.is_(None))  # noqa: E712
            ).count()
        return counts
