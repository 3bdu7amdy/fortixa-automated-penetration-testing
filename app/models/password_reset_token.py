"""Password reset token model."""
import secrets
from datetime import datetime, timezone, timedelta
from app.extensions import db
from app.models.base import BaseModel


class PasswordResetToken(BaseModel):
    """Token for the 'Forgot Password' flow.

    Tokens are cryptographically random, single-use, and short-lived (1 hour).
    """
    __tablename__ = 'password_reset_tokens'

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    token = db.Column(db.String(128), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, nullable=False, default=False)

    @staticmethod
    def create_token(user_id):
        """Create a new password reset token, invalidating any previous ones."""
        # Invalidate existing tokens for this user
        existing = PasswordResetToken.query.filter_by(
            user_id=user_id, is_used=False
        ).all()
        for t in existing:
            t.is_used = True
        db.session.commit()

        token_str = secrets.token_urlsafe(64)
        token = PasswordResetToken(
            user_id=user_id,
            token=token_str,
            expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)
        )
        token.save()
        return token

    @property
    def is_valid(self):
        """Check if token is still valid."""
        if self.is_used:
            return False
        return datetime.now(timezone.utc).replace(tzinfo=None) < self.expires_at

    def mark_used(self):
        """Mark this token as used after password reset."""
        self.is_used = True
        self.save()

    def __repr__(self):
        return f'<PasswordResetToken user={self.user_id}>'
