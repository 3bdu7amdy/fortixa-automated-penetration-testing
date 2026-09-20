"""User model - stores user accounts."""
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db
from app.models.base import BaseModel


class User(BaseModel):
    """User model for authentication and authorization.

    Stores user credentials, role, and account status.
    Passwords are hashed using Werkzeug's built-in bcrypt/scrypt.
    """
    __tablename__ = 'users'

    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    last_login_at = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    # Relationships
    projects = db.relationship('Project', backref='owner', lazy='dynamic')
    sessions = db.relationship('Session', backref='user', lazy='dynamic')
    notifications = db.relationship('Notification', backref='user', lazy='dynamic')

    @property
    def password(self):
        """Password is write-only - cannot be read back."""
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        """Hash and store the password."""
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        """Verify a password against the stored hash."""
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        """Check if user has admin role."""
        return self.role == 'admin'

    @property
    def is_locked(self):
        """Check if account is currently locked."""
        if self.locked_until is None:
            return False
        return datetime.now(timezone.utc).replace(tzinfo=None) < self.locked_until

    def increment_failed_login(self):
        """Increment failed login counter and lock if threshold reached."""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            from datetime import timedelta
            self.locked_until = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=15)
        self.save()

    def reset_failed_login(self):
        """Reset failed login counter after successful login."""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login_at = datetime.now(timezone.utc).replace(tzinfo=None)
        self.save()

    @property
    def is_authenticated(self):
        """Flask-Login required property."""
        return True

    @property
    def is_anonymous(self):
        """Flask-Login required property."""
        return False

    def get_id(self):
        """Flask-Login required method - return user ID as string."""
        return str(self.id)

    def __repr__(self):
        return f'<User {self.username}>'
