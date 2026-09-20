"""User model tests."""
import pytest
from app.models.user import User
from app.extensions import db


def test_user_creation(app, db):
    """Test creating a user."""
    with app.app_context():
        user = User(username='testuser', email='test@example.com')
        user.password = 'TestPass123!'
        user.save()
        assert user.id is not None
        assert user.username == 'testuser'
        assert user.email == 'test@example.com'
        assert user.role == 'user'
        assert user.is_active is True


def test_password_hashing(app, db):
    """Test password hashing and verification."""
    with app.app_context():
        user = User(username='hashtest', email='hash@example.com')
        user.password = 'MySecretPass123'
        user.save()

        assert user.verify_password('MySecretPass123') is True
        assert user.verify_password('WrongPassword') is False
        assert user.password_hash != 'MySecretPass123'


def test_password_not_readable(app, db):
    """Test that password property raises AttributeError."""
    with app.app_context():
        user = User(username='readtest', email='read@example.com')
        user.password = 'TestPass123!'
        with pytest.raises(AttributeError):
            _ = user.password


def test_user_is_admin(app, db):
    """Test admin role check."""
    with app.app_context():
        user = User(username='admintest', email='admin@example.com', role='admin')
        user.password = 'AdminPass123!'
        user.save()
        assert user.is_admin is True

        regular = User(username='regulartest', email='regular@example.com')
        regular.password = 'RegularPass123!'
        regular.save()
        assert regular.is_admin is False


def test_account_lockout(app, db):
    """Test account lockout after failed logins."""
    with app.app_context():
        user = User(username='locktest', email='lock@example.com')
        user.password = 'TestPass123!'
        user.save()

        for _ in range(5):
            user.increment_failed_login()

        assert user.is_locked is True
        assert user.failed_login_attempts == 5


def test_user_get_id(app, db):
    """Test Flask-Login get_id method."""
    with app.app_context():
        user = User(username='idtest', email='id@example.com')
        user.password = 'TestPass123!'
        user.save()
        assert user.get_id() == str(user.id)
