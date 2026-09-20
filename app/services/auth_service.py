"""Authentication service - handles all auth business logic."""
import logging
from datetime import datetime, timedelta
from flask import session as flask_session, request
from app.extensions import db
from app.models.user import User
from app.models.session import Session
from app.models.password_reset_token import PasswordResetToken

logger = logging.getLogger(__name__)


class AuthService:
    """Handles all authentication business logic."""

    def register(self, username, email, password):
        """Register a new user.

        Args:
            username: Unique username (3-80 chars)
            email: Unique email address
            password: Plain text password (will be hashed)

        Returns:
            dict with 'success' and 'user' or 'errors'
        """
        errors = []

        # Validate input
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters')
        if not email or '@' not in email:
            errors.append('Valid email address is required')
        if not password or len(password) < 8:
            errors.append('Password must be at least 8 characters')

        # Check uniqueness
        if User.query.filter_by(username=username).first():
            errors.append('Username already exists')
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered')

        if errors:
            return {'success': False, 'errors': errors}

        # Create user
        user = User(username=username, email=email)
        user.password = password
        user.save()

        logger.info(f"New user registered: {username}")
        return {'success': True, 'user': user}

    def login(self, username, password, remember=False):
        """Authenticate a user and create a session.

        Args:
            username: Username to authenticate
            password: Password to verify
            remember: Whether to extend session lifetime

        Returns:
            dict with 'success' and 'user' or 'errors'
        """
        user = User.query.filter_by(username=username).first()

        if not user:
            return {'success': False, 'errors': ['Invalid username or password']}

        # Check if account is locked
        if user.is_locked:
            return {'success': False, 'errors': ['Account is temporarily locked. Try again later.']}

        # Check if account is active
        if not user.is_active:
            return {'success': False, 'errors': ['Account is disabled. Contact admin.']}

        # Verify password
        if not user.verify_password(password):
            user.increment_failed_login()
            logger.warning(f"Failed login attempt for {username} from {request.remote_addr}")
            return {'success': False, 'errors': ['Invalid username or password']}

        # Success - create session
        user.reset_failed_login()
        flask_session['user_id'] = user.id
        flask_session['user_role'] = user.role
        flask_session.permanent = remember

        # Create server-side session record
        server_session = Session.create_session(
            user_id=user.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            duration_hours=24 if remember else 1
        )
        flask_session['session_token'] = server_session.session_token

        logger.info(f"User {username} logged in from {request.remote_addr}")
        return {'success': True, 'user': user}

    def logout(self, user_id):
        """Destroy the user's session."""
        session_token = flask_session.get('session_token')
        if session_token:
            server_session = Session.query.filter_by(session_token=session_token).first()
            if server_session:
                server_session.revoke()

        flask_session.clear()
        logger.info(f"User {user_id} logged out")
        return {'success': True}

    def request_password_reset(self, email):
        """Generate a password reset token."""
        user = User.query.filter_by(email=email).first()
        if not user:
            # Don't reveal whether the email exists
            return {'success': True, 'message': 'If the email exists, a reset link will be sent'}

        token = PasswordResetToken.create_token(user.id)
        # In production, send email with reset link
        logger.info(f"Password reset requested for {email}")
        return {'success': True, 'token': token.token}

    def reset_password(self, token_str, new_password):
        """Reset a user's password using a valid token."""
        token = PasswordResetToken.query.filter_by(token=token_str, is_used=False).first()
        if not token or not token.is_valid:
            return {'success': False, 'errors': ['Invalid or expired reset token']}

        if not new_password or len(new_password) < 8:
            return {'success': False, 'errors': ['Password must be at least 8 characters']}

        user = db.session.get(User, token.user_id)
        user.password = new_password
        user.save()

        token.mark_used()
        logger.info(f"Password reset for user {user.username}")
        return {'success': True}
