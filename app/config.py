"""Application configuration classes."""
import os


class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    _db_url = os.environ.get('DATABASE_URL', '')
    SQLALCHEMY_DATABASE_URI = _db_url if _db_url and _db_url.startswith(('sqlite', 'postgresql', 'mysql')) else 'sqlite:///pentest.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_TYPE = 'filesystem'
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour
    OUTPUT_DIR = os.environ.get('OUTPUT_DIR', 'output')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload

    # Rate limiting
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_DEFAULT = '60/minute'

    # Security headers
    SECURITY_HEADERS_ENABLED = True

    # Session cookie security
    SESSION_COOKIE_SECURE = False  # Set True in production (HTTPS only)
    SESSION_COOKIE_HTTPONLY = True  # No JS access to session cookie
    SESSION_COOKIE_SAMESITE = 'Lax'

    # CSRF protection
    WTF_CSRF_TIME_LIMIT = 3600  # CSRF token lifetime in seconds


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    SQLALCHEMY_ECHO = False


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///test_pentest.db'
    WTF_CSRF_ENABLED = False
    SERVER_NAME = 'localhost'


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    # SECRET_KEY MUST be set via environment variable in production
    SESSION_COOKIE_SECURE = True  # HTTPS only
    SESSION_COOKIE_HTTPONLY = True  # No JS access
    SESSION_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True
    WTF_CSRF_TIME_LIMIT = 3600


config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
}
