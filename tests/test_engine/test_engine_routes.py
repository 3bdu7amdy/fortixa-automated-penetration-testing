"""Tests for Engine routes."""
import pytest
from app import create_app
from app.extensions import db as _db
from app.models.user import User


@pytest.fixture(scope='module')
def app():
    """Create application for testing."""
    app = create_app('testing')
    yield app


@pytest.fixture(scope='function')
def db(app):
    """Create a fresh database for each test."""
    with app.app_context():
        _db.create_all()
        yield _db
        _db.session.remove()
        _db.drop_all()


@pytest.fixture(scope='function')
def client(app, db):
    """Create a test client."""
    return app.test_client()


@pytest.fixture(scope='function')
def admin_client(client, db):
    """Create an admin test client."""
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


@pytest.fixture(scope='function')
def normal_client(client, db):
    """Create a normal (non-admin) test client."""
    client.post('/auth/register', data={
        'username': 'normaluser',
        'email': 'normal@example.com',
        'password': 'NormalPass123!',
        'confirm_password': 'NormalPass123!'
    })
    client.post('/auth/login', data={
        'username': 'normaluser',
        'password': 'NormalPass123!'
    })
    return client


class TestEngineRoutes:
    """Test suite for engine blueprint routes."""

    def test_status_requires_login(self, client, db):
        """GET /engine/status should redirect to login if not authenticated."""
        response = client.get('/engine/status', follow_redirects=False)
        assert response.status_code == 302
        assert '/auth/login' in response.headers['Location']

    def test_status_returns_json(self, admin_client, db):
        """GET /engine/status should return JSON with worker status."""
        response = admin_client.get('/engine/status')
        assert response.status_code == 200
        data = response.get_json()
        assert 'is_running' in data
        assert 'running_jobs' in data
        assert 'running_count' in data
        assert 'queued_count' in data

    def test_start_requires_admin(self, normal_client, db):
        """POST /engine/start should be forbidden for non-admin users."""
        response = normal_client.post('/engine/start', follow_redirects=False)
        assert response.status_code == 302
        # Should redirect to dashboard (admin_required)
        assert '/dashboard' in response.headers['Location']

    def test_start_worker(self, admin_client, db):
        """POST /engine/start should start the worker."""
        response = admin_client.post('/engine/start', follow_redirects=True)
        assert response.status_code == 200

        # Check status
        response = admin_client.get('/engine/status')
        data = response.get_json()
        assert data['is_running'] is True

        # Clean up: stop the worker
        from app.engine import stop_worker
        stop_worker()

    def test_stop_worker(self, admin_client, db):
        """POST /engine/stop should stop the worker."""
        # Start first
        from app.engine import start_worker
        start_worker(admin_client.application)

        response = admin_client.post('/engine/stop', follow_redirects=True)
        assert response.status_code == 200

        # Verify worker stopped
        response = admin_client.get('/engine/status')
        data = response.get_json()
        assert data['is_running'] is False

    def test_health_requires_admin(self, normal_client, db):
        """GET /engine/health should be forbidden for non-admin users."""
        response = normal_client.get('/engine/health', follow_redirects=False)
        assert response.status_code == 302
        assert '/dashboard' in response.headers['Location']

    def test_health_page(self, admin_client, db):
        """GET /engine/health should render the health template."""
        response = admin_client.get('/engine/health')
        assert response.status_code == 200
        # Should contain health-related content
        assert b'Worker Status' in response.data
        assert b'Database' in response.data
        assert b'Tool Installation' in response.data
