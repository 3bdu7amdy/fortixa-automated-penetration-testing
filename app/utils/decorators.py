"""Custom decorators for authentication, authorization, and rate limiting."""
from functools import wraps
from flask import session, flash, redirect, url_for, request, jsonify, current_app
from app.extensions import db
from app.models.user import User


def login_required(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin role for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in.', 'info')
            return redirect(url_for('auth.login'))
        user = db.session.get(User, session['user_id'])
        if not user or user.role != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    return decorated_function


def rate_limit(max_requests=60, window_seconds=60, key_func=None):
    """Decorator to rate limit a route.

    Uses the in-memory RateLimiter to enforce request limits per key.

    Args:
        max_requests: Maximum requests per window (default: 60).
        window_seconds: Time window in seconds (default: 60).
        key_func: Function to get the rate limit key.
                  Receives the request object. Default: remote_addr.

    Returns:
        Decorator function.

    Example:
        @rate_limit(max_requests=10, window_seconds=60)
        def my_route():
            return 'OK'
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Skip rate limiting if disabled in config
            if not current_app.config.get('RATE_LIMIT_ENABLED', True):
                return f(*args, **kwargs)

            from app.utils.rate_limiter import get_rate_limiter
            limiter = get_rate_limiter()

            # Determine the rate limit key
            if key_func:
                key = key_func(request)
            else:
                key = f"rl:{request.remote_addr}"

            # Include the endpoint in the key for per-route limiting
            endpoint_key = f"{key}:{request.endpoint or f.__name__}"

            allowed, retry_after = limiter.is_allowed(
                endpoint_key, max_requests, window_seconds
            )

            if not allowed:
                # Set rate limit headers on the response would be ideal,
                # but since we're returning early, use jsonify
                response = jsonify({
                    'error': 'Rate limit exceeded',
                    'message': f'Too many requests. Try again in {retry_after} seconds.',
                    'retry_after': retry_after,
                })
                response.status_code = 429
                response.headers['Retry-After'] = str(retry_after)
                return response

            # Execute the original function
            response = f(*args, **kwargs)

            # Add rate limit info headers to successful responses
            remaining = limiter.get_remaining(
                endpoint_key, max_requests, window_seconds
            )
            if hasattr(response, 'headers'):
                response.headers['X-RateLimit-Limit'] = str(max_requests)
                response.headers['X-RateLimit-Remaining'] = str(remaining)
                response.headers['X-RateLimit-Window'] = str(window_seconds)

            return response

        return decorated_function
    return decorator
