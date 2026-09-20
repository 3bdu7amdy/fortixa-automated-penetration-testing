"""Security headers middleware for the Pentest AI Platform."""
from flask import request


def add_security_headers(response):
    """Add security headers to all responses.

    Applies standard security headers to mitigate common web vulnerabilities:
    - MIME type sniffing prevention
    - Clickjacking protection
    - XSS protection (legacy browsers)
    - Content Security Policy
    - Referrer policy
    - Permissions policy
    - HSTS (production only)
    """
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # Prevent clickjacking - deny framing entirely
    response.headers['X-Frame-Options'] = 'DENY'

    # Enable XSS filter in legacy browsers
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )

    # Referrer policy - only send origin on cross-origin requests
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Permissions policy - deny access to sensitive APIs
    response.headers['Permissions-Policy'] = (
        'camera=(), microphone=(), geolocation=()'
    )

    # Strict Transport Security - production only
    # Only add HSTS if the request was made over HTTPS
    if request and request.is_secure:
        response.headers['Strict-Transport-Security'] = (
            'max-age=31536000; includeSubDomains'
        )

    # Remove server identification
    response.headers.pop('Server', None)

    # Cache control for sensitive pages
    if request and request.endpoint:
        sensitive_endpoints = [
            'auth.login', 'auth.register', 'auth.reset_password',
            'auth.change_password',
        ]
        if request.endpoint in sensitive_endpoints:
            response.headers['Cache-Control'] = (
                'no-store, no-cache, must-revalidate, max-age=0'
            )
            response.headers['Pragma'] = 'no-cache'

    return response
