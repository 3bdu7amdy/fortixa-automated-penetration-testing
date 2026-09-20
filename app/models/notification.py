"""Notification model - in-app notifications for users."""
from app.extensions import db
from app.models.base import BaseModel


class Notification(BaseModel):
    """Notification model.

    Stores in-app notifications for users such as scan completion,
    findings discovered, and system messages.
    """
    __tablename__ = 'notifications'

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), nullable=False)  # scan_complete, finding, system, warning
    is_read = db.Column(db.Boolean, nullable=False, default=False, index=True)
    related_scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=True)
    related_finding_id = db.Column(db.Integer, db.ForeignKey('findings.id'), nullable=True)

    def __repr__(self):
        return f'<Notification {self.title[:50]}>'
