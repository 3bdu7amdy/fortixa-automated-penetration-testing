"""Logging configuration for the application."""
import logging
import os
from logging.handlers import RotatingFileHandler


def setup_logging(app):
    """Configure application logging with file and console handlers."""
    # Ensure logs directory exists
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'logs')
    if not os.path.exists(log_dir):
        os.mkdir(log_dir)

    # File handler with rotation
    file_handler = RotatingFileHandler(
        os.path.join(log_dir, 'pentest_platform.log'),
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s %(name)s %(funcName)s:%(lineno)d - %(message)s'
    ))
    file_handler.setLevel(logging.INFO)

    # Console handler for development
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s %(name)s - %(message)s'
    ))
    console_handler.setLevel(logging.DEBUG if app.debug else logging.INFO)

    # Add handlers
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)
    app.logger.setLevel(logging.DEBUG if app.debug else logging.INFO)
    app.logger.info('Pentest AI Platform starting...')
