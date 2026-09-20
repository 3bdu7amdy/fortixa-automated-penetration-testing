"""Base model with common fields for all models."""
from datetime import datetime, timezone
from app.extensions import db


def _utcnow():
    """Return current UTC time as a naive datetime (SQLite-compatible)."""
    return datetime.now(timezone.utc).replace(tzinfo=None).replace(tzinfo=None)


class BaseModel(db.Model):
    """Abstract base model with common fields.

    Every model inherits from this to get id, created_at, and updated_at
    automatically. This follows the DRY principle.
    """
    __abstract__ = True

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=_utcnow, onupdate=_utcnow)

    def save(self):
        """Save the current instance to the database."""
        db.session.add(self)
        db.session.commit()

    def delete(self):
        """Delete the current instance from the database."""
        db.session.delete(self)
        db.session.commit()

    def to_dict(self):
        """Convert model instance to dictionary (basic fields only)."""
        result = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            if isinstance(value, datetime):
                value = value.isoformat()
            result[column.name] = value
        return result
