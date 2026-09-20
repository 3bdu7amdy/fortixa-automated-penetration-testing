"""Target model - a domain, IP, or URL to be scanned."""
from app.extensions import db
from app.models.base import BaseModel


class Target(BaseModel):
    """Target model.

    A target is a domain, IP address, or URL range that will be
    scanned within a project. Requires admin approval before scanning.
    """
    __tablename__ = 'targets'

    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False, index=True)
    value = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(20), nullable=False, index=True)  # domain, ip, url, cidr
    description = db.Column(db.Text, nullable=True)
    is_approved = db.Column(db.Boolean, nullable=False, default=False)

    # Relationships
    scans = db.relationship('Scan', backref='target', lazy='dynamic')

    __table_args__ = (
        db.UniqueConstraint('value', 'project_id', name='idx_targets_value_project'),
    )

    def __repr__(self):
        return f'<Target {self.value}>'

    def get_scan_count(self):
        """Get number of scans for this target."""
        return self.scans.count()

    def get_latest_scan(self):
        """Get the most recent scan for this target."""
        return self.scans.order_by(self.scans.columns.created_at.desc()).first()
