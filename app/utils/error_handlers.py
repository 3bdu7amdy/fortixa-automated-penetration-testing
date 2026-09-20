"""Custom exception classes and error handlers for the Pentest AI Platform."""
import logging

logger = logging.getLogger(__name__)


# ============================================================================
# Custom Exception Classes
# ============================================================================

class PentestPlatformError(Exception):
    """Base exception for the Pentest AI Platform.

    All custom application exceptions should inherit from this class.
    """
    status_code = 500
    error_type = 'platform_error'

    def __init__(self, message=None, status_code=None, payload=None):
        super().__init__(message or self.__class__.__name__)
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload or {}

    def to_dict(self):
        """Convert exception to a dictionary for API responses."""
        result = {
            'error': self.error_type,
            'message': str(self),
        }
        if self.payload:
            result['details'] = self.payload
        return result


class ValidationError(PentestPlatformError):
    """Input validation failed."""
    status_code = 400
    error_type = 'validation_error'


class AuthenticationError(PentestPlatformError):
    """Authentication failed."""
    status_code = 401
    error_type = 'authentication_error'


class AuthorizationError(PentestPlatformError):
    """User lacks permission for the requested action."""
    status_code = 403
    error_type = 'authorization_error'


class ScanError(PentestPlatformError):
    """Scan operation failed."""
    status_code = 500
    error_type = 'scan_error'


class ToolExecutionError(PentestPlatformError):
    """Tool execution failed."""
    status_code = 500
    error_type = 'tool_execution_error'


class ResourceNotFoundError(PentestPlatformError):
    """Requested resource was not found."""
    status_code = 404
    error_type = 'not_found'


class RateLimitExceededError(PentestPlatformError):
    """Rate limit has been exceeded."""
    status_code = 429
    error_type = 'rate_limit_exceeded'


# ============================================================================
# Error Handler Registration
# ============================================================================

def register_custom_error_handlers(app):
    """Register error handlers for custom exceptions.

    Args:
        app: The Flask application instance.
    """
    @app.errorhandler(ValidationError)
    def handle_validation_error(e):
        logger.warning('Validation error: %s', str(e))
        if _wants_json_response(app):
            return e.to_dict(), e.status_code
        from flask import render_template
        return render_template('errors/400.html'), 400

    @app.errorhandler(AuthenticationError)
    def handle_authentication_error(e):
        logger.warning('Authentication error: %s', str(e))
        if _wants_json_response(app):
            return e.to_dict(), e.status_code
        from flask import render_template, redirect, url_for
        return redirect(url_for('auth.login'))

    @app.errorhandler(AuthorizationError)
    def handle_authorization_error(e):
        logger.warning('Authorization error: %s', str(e))
        if _wants_json_response(app):
            return e.to_dict(), e.status_code
        from flask import render_template
        return render_template('errors/403.html'), 403

    @app.errorhandler(ScanError)
    def handle_scan_error(e):
        logger.error('Scan error: %s', str(e))
        if _wants_json_response(app):
            return e.to_dict(), e.status_code
        from flask import render_template
        return render_template('errors/500.html'), 500

    @app.errorhandler(ToolExecutionError)
    def handle_tool_execution_error(e):
        logger.error('Tool execution error: %s', str(e))
        if _wants_json_response(app):
            return e.to_dict(), e.status_code
        from flask import render_template
        return render_template('errors/500.html'), 500

    @app.errorhandler(ResourceNotFoundError)
    def handle_not_found_error(e):
        logger.info('Resource not found: %s', str(e))
        if _wants_json_response(app):
            return e.to_dict(), e.status_code
        from flask import render_template
        return render_template('errors/404.html'), 404

    @app.errorhandler(RateLimitExceededError)
    def handle_rate_limit_error(e):
        logger.warning('Rate limit exceeded: %s', str(e))
        response = e.to_dict()
        response['retry_after'] = e.payload.get('retry_after', 60)
        if _wants_json_response(app):
            return response, e.status_code
        from flask import render_template
        return render_template('errors/429.html'), 429

    @app.errorhandler(PentestPlatformError)
    def handle_platform_error(e):
        """Catch-all handler for any unhandled PentestPlatformError subclasses."""
        logger.error('Platform error: %s', str(e), exc_info=True)
        if _wants_json_response(app):
            return e.to_dict(), e.status_code
        from flask import render_template
        return render_template('errors/500.html'), 500


def _wants_json_response(app):
    """Check if the current request expects a JSON response.

    Returns True if the request Accept header prefers JSON or
    the request path starts with /api/.
    """
    try:
        from flask import request
        if request.path.startswith('/api/'):
            return True
        accept = request.headers.get('Accept', '')
        if 'application/json' in accept:
            return True
    except RuntimeError:
        pass
    return False
