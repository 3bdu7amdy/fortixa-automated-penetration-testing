"""General helper functions."""
import os
from datetime import datetime, timezone


def ensure_directory(path):
    """Ensure a directory exists, creating it if necessary."""
    os.makedirs(path, exist_ok=True)
    return path


def format_datetime(dt, format='%Y-%m-%d %H:%M:%S'):
    """Format a datetime object for display."""
    if dt is None:
        return 'N/A'
    return dt.strftime(format)


def format_file_size(size_bytes):
    """Format file size in human-readable format."""
    if size_bytes is None:
        return 'N/A'
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def severity_badge_class(severity):
    """Return CSS class for severity badge."""
    classes = {
        'critical': 'badge-critical',
        'high': 'badge-high',
        'medium': 'badge-medium',
        'low': 'badge-low',
        'info': 'badge-info'
    }
    return classes.get(severity, 'badge-info')


def status_badge_class(status):
    """Return CSS class for status badge."""
    classes = {
        'pending': 'badge-warning',
        'running': 'badge-info',
        'completed': 'badge-success',
        'failed': 'badge-danger',
        'cancelled': 'badge-secondary',
        'queued': 'badge-warning',
        'timeout': 'badge-danger',
        'skipped': 'badge-secondary'
    }
    return classes.get(status, 'badge-secondary')


def time_ago(dt):
    """Return a human-readable 'time ago' string."""
    if dt is None:
        return 'N/A'
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    diff = now - dt
    seconds = diff.total_seconds()

    if seconds < 60:
        return 'just now'
    elif seconds < 3600:
        return f"{int(seconds / 60)} minutes ago"
    elif seconds < 86400:
        return f"{int(seconds / 3600)} hours ago"
    else:
        return f"{int(seconds / 86400)} days ago"
