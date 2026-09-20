"""Auth route tests."""
import pytest


def test_login_page_loads(client, app, db):
    """Test login page loads correctly."""
    with app.app_context():
        response = client.get('/auth/login')
        assert response.status_code == 200
        assert b'Sign In' in response.data or b'login' in response.data.lower()


def test_register_page_loads(client, app, db):
    """Test register page loads correctly."""
    with app.app_context():
        response = client.get('/auth/register')
        assert response.status_code == 200
        assert b'Create Account' in response.data or b'register' in response.data.lower()


def test_register_and_login(client, app, db):
    """Test full registration and login flow."""
    with app.app_context():
        # Register
        response = client.post('/auth/register', data={
            'username': 'flowuser',
            'email': 'flow@example.com',
            'password': 'FlowPass123!',
            'confirm_password': 'FlowPass123!'
        }, follow_redirects=True)
        assert response.status_code == 200

        # Login
        response = client.post('/auth/login', data={
            'username': 'flowuser',
            'password': 'FlowPass123!'
        }, follow_redirects=True)
        assert response.status_code == 200


def test_dashboard_requires_login(client, app, db):
    """Test dashboard redirects unauthenticated users."""
    with app.app_context():
        response = client.get('/')
        assert response.status_code == 302  # Redirect to login


def test_authenticated_dashboard(authenticated_client, app, db):
    """Test authenticated user can access dashboard."""
    with app.app_context():
        response = authenticated_client.get('/')
        assert response.status_code == 200


def test_404_page(client, app, db):
    """Test custom 404 page."""
    with app.app_context():
        response = client.get('/nonexistent-page')
        assert response.status_code == 404
