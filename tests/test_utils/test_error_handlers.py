"""Tests for custom error handlers and exceptions."""
import json
import pytest
from app import create_app
from app.utils.error_handlers import (
    PentestPlatformError,
    ValidationError,
    AuthenticationError,
    AuthorizationError,
    ScanError,
    ToolExecutionError,
    ResourceNotFoundError,
    RateLimitExceededError,
)


# ============================================================================
# Exception class tests
# ============================================================================

class TestPentestPlatformError:
    """Tests for base PentestPlatformError."""

    def test_default_status_code(self):
        err = PentestPlatformError('test error')
        assert err.status_code == 500

    def test_custom_status_code(self):
        err = PentestPlatformError('test', status_code=418)
        assert err.status_code == 418

    def test_message(self):
        err = PentestPlatformError('something went wrong')
        assert str(err) == 'something went wrong'

    def test_to_dict(self):
        err = PentestPlatformError('test error')
        result = err.to_dict()
        assert result['error'] == 'platform_error'
        assert result['message'] == 'test error'

    def test_to_dict_with_payload(self):
        err = PentestPlatformError('test', payload={'field': 'value'})
        result = err.to_dict()
        assert result['details'] == {'field': 'value'}


class TestValidationError:
    """Tests for ValidationError."""

    def test_status_code(self):
        err = ValidationError('bad input')
        assert err.status_code == 400

    def test_error_type(self):
        err = ValidationError('bad input')
        assert err.error_type == 'validation_error'

    def test_to_dict(self):
        err = ValidationError('invalid email')
        result = err.to_dict()
        assert result['error'] == 'validation_error'
        assert result['message'] == 'invalid email'


class TestAuthenticationError:
    """Tests for AuthenticationError."""

    def test_status_code(self):
        err = AuthenticationError('bad credentials')
        assert err.status_code == 401

    def test_error_type(self):
        assert AuthenticationError.error_type == 'authentication_error'


class TestAuthorizationError:
    """Tests for AuthorizationError."""

    def test_status_code(self):
        err = AuthorizationError('no access')
        assert err.status_code == 403

    def test_error_type(self):
        assert AuthorizationError.error_type == 'authorization_error'


class TestScanError:
    """Tests for ScanError."""

    def test_status_code(self):
        err = ScanError('scan failed')
        assert err.status_code == 500

    def test_error_type(self):
        assert ScanError.error_type == 'scan_error'


class TestToolExecutionError:
    """Tests for ToolExecutionError."""

    def test_status_code(self):
        err = ToolExecutionError('tool crashed')
        assert err.status_code == 500

    def test_error_type(self):
        assert ToolExecutionError.error_type == 'tool_execution_error'


class TestResourceNotFoundError:
    """Tests for ResourceNotFoundError."""

    def test_status_code(self):
        err = ResourceNotFoundError('not found')
        assert err.status_code == 404

    def test_error_type(self):
        assert ResourceNotFoundError.error_type == 'not_found'


class TestRateLimitExceededError:
    """Tests for RateLimitExceededError."""

    def test_status_code(self):
        err = RateLimitExceededError('too many requests')
        assert err.status_code == 429

    def test_error_type(self):
        assert RateLimitExceededError.error_type == 'rate_limit_exceeded'

    def test_with_retry_after(self):
        err = RateLimitExceededError('slow down', payload={'retry_after': 30})
        result = err.to_dict()
        assert result['details']['retry_after'] == 30


# ============================================================================
# Exception hierarchy tests
# ============================================================================

class TestExceptionHierarchy:
    """Tests for exception class hierarchy."""

    def test_all_exceptions_inherit_from_base(self):
        exceptions = [
            ValidationError, AuthenticationError, AuthorizationError,
            ScanError, ToolExecutionError, ResourceNotFoundError,
            RateLimitExceededError,
        ]
        for exc_class in exceptions:
            assert issubclass(exc_class, PentestPlatformError)
            assert issubclass(exc_class, Exception)

    def test_catch_with_base_class(self):
        """All custom exceptions should be catchable with PentestPlatformError."""
        with pytest.raises(PentestPlatformError):
            raise ValidationError('test')

        with pytest.raises(PentestPlatformError):
            raise AuthorizationError('test')


# ============================================================================
# Error handler integration tests
# ============================================================================

class TestErrorHandlerIntegration:
    """Test that custom error handlers are registered and work with Flask."""

    @pytest.fixture(scope='class')
    def app(self):
        """Create application for testing with test routes registered."""
        app = create_app('testing')

        # Register test routes BEFORE any request is made
        @app.route('/test/validation_error')
        def test_validation_error():
            raise ValidationError('Invalid input data')

        @app.route('/test/authorization_error')
        def test_authz_error():
            raise AuthorizationError('Access denied')

        @app.route('/test/not_found_error')
        def test_not_found_error():
            raise ResourceNotFoundError('Item not found')

        @app.route('/test/scan_error')
        def test_scan_error():
            raise ScanError('Scan failed')

        @app.route('/test/tool_error')
        def test_tool_error():
            raise ToolExecutionError('Tool crashed')

        @app.route('/api/test/error')
        def test_api_error():
            raise ValidationError('Bad API input')

        @app.route('/test/rate_limit_error')
        def test_rate_limit_error():
            raise RateLimitExceededError('Slow down', payload={'retry_after': 30})

        return app

    @pytest.fixture(scope='class')
    def client(self, app):
        """Create a test client."""
        return app.test_client()

    def test_validation_error_returns_400(self, client):
        """ValidationError should result in a 400 response."""
        response = client.get('/test/validation_error')
        assert response.status_code == 400

    def test_authorization_error_returns_403(self, client):
        """AuthorizationError should result in a 403 response."""
        response = client.get('/test/authorization_error')
        assert response.status_code == 403

    def test_not_found_error_returns_404(self, client):
        """ResourceNotFoundError should result in a 404 response."""
        response = client.get('/test/not_found_error')
        assert response.status_code == 404

    def test_scan_error_returns_500(self, client):
        """ScanError should result in a 500 response."""
        response = client.get('/test/scan_error')
        assert response.status_code == 500

    def test_tool_execution_error_returns_500(self, client):
        """ToolExecutionError should result in a 500 response."""
        response = client.get('/test/tool_error')
        assert response.status_code == 500

    def test_api_error_returns_json(self, client):
        """API route errors should return JSON responses."""
        response = client.get('/api/test/error')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['error'] == 'validation_error'
        assert data['message'] == 'Bad API input'

    def test_rate_limit_error_returns_429(self, client):
        """RateLimitExceededError should result in a 429 response."""
        response = client.get('/test/rate_limit_error')
        assert response.status_code == 429
