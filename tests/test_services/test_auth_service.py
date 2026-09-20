"""Auth service tests."""
import pytest
from app.services.auth_service import AuthService
from app.models.user import User


def test_register_valid_user(app, db):
    """Test registering a valid user."""
    with app.app_context():
        service = AuthService()
        result = service.register('newuser', 'new@example.com', 'SecurePass123!')
        assert result['success'] is True
        assert result['user'].username == 'newuser'


def test_register_duplicate_username(app, db):
    """Test registering with duplicate username."""
    with app.app_context():
        service = AuthService()
        service.register('dupuser', 'dup1@example.com', 'Pass123!')
        result = service.register('dupuser', 'dup2@example.com', 'Pass123!')
        assert result['success'] is False
        assert 'Username already exists' in result['errors']


def test_register_short_password(app, db):
    """Test registering with short password."""
    with app.app_context():
        service = AuthService()
        result = service.register('shortpw', 'short@example.com', '123')
        assert result['success'] is False


def test_register_invalid_email(app, db):
    """Test registering with invalid email."""
    with app.app_context():
        service = AuthService()
        result = service.register('bademail', 'notanemail', 'Pass123!')
        assert result['success'] is False
