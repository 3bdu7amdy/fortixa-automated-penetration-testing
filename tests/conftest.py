"""Test configuration and fixtures."""
import pytest
from app import create_app
from app.extensions import db as _db


@pytest.fixture(scope='session')
def app():
    """Create application for testing."""
    app = create_app('testing')
    yield app


@pytest.fixture(scope='function')
def db(app):
    """Create a fresh database for each test."""
    with app.app_context():
        _db.create_all()
        # Create default configurations after each fresh DB creation
        from app.models.configuration import Configuration
        Configuration.create_default_configs()
        yield _db
        _db.session.remove()
        _db.drop_all()


@pytest.fixture(scope='function')
def client(app, db):
    """Create a test client."""
    return app.test_client()


@pytest.fixture(scope='function')
def authenticated_client(client, db):
    """Create an authenticated test client."""
    # Register a user
    client.post('/auth/register', data={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'TestPass123!',
        'confirm_password': 'TestPass123!'
    })
    # Login
    client.post('/auth/login', data={
        'username': 'testuser',
        'password': 'TestPass123!'
    })
    return client


@pytest.fixture(scope='function')
def admin_client(client, db):
    """Create an admin test client."""
    from app.models.user import User
    # Register a user
    client.post('/auth/register', data={
        'username': 'admin',
        'email': 'admin@example.com',
        'password': 'AdminPass123!',
        'confirm_password': 'AdminPass123!'
    })
    # Make them admin
    with client.application.app_context():
        user = User.query.filter_by(username='admin').first()
        user.role = 'admin'
        user.save()
    # Login
    client.post('/auth/login', data={
        'username': 'admin',
        'password': 'AdminPass123!'
    })
    return client
