"""Execution Engine - task queue, worker, and job management."""
import logging

logger = logging.getLogger(__name__)

_worker = None


def start_worker(app):
    """Create and start the background worker.

    Args:
        app: Flask application instance for app context.
    """
    global _worker
    from app.engine.worker import Worker
    _worker = Worker(app)
    _worker.start()
    logger.info("Execution engine worker started.")


def stop_worker():
    """Stop the background worker gracefully."""
    global _worker
    if _worker is not None:
        _worker.stop(graceful=True)
        logger.info("Execution engine worker stopped.")
        _worker = None


def get_worker():
    """Return the current Worker instance (or None)."""
    return _worker
