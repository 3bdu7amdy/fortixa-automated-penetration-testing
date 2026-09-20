"""Session model - server-side session storage."""
import secrets
from datetime import datetime, timezone, timedelta
from app.extensions import db
from app.models.base import BaseModel


class Session(BaseModel):
    """Server-side session model.

    Allows invalidating sessions server-side (not just by deleting the cookie).
    Tracks which devices are logged in and when sessions expire.
    """
    __tablename__ = 'sessions'

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    session_token = db.Column(db.String(128), unique=True, nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(256), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    is_revoked = db.Column(db.Boolean, nullable=False, default=False)

    @staticmethod
    def create_session(user_id, ip_address, user_agent, duration_hours=1):
        """Create a new session for a user."""
        token = secrets.token_urlsafe(64)
        session = Session(
            user_id=user_id,
            session_token=token,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=duration_hours)
        )
        session.save()
        return session

    @property
    def is_valid(self):
        """Check if session is still valid (not expired and not revoked)."""
        if self.is_revoked:
            return False
        return datetime.now(timezone.utc).replace(tzinfo=None) < self.expires_at

    def revoke(self):
        """Revoke this session."""
        self.is_revoked = True
        self.save()

    @staticmethod
    def revoke_all_user_sessions(user_id):
        """Revoke all sessions for a user (log out all devices)."""
        sessions = Session.query.filter_by(user_id=user_id, is_revoked=False).all()
        for session in sessions:
            session.is_revoked = True
        db.session.commit()

    def __repr__(self):
        return f'<Session user={self.user_id} token={self.session_token[:8]}...>'
