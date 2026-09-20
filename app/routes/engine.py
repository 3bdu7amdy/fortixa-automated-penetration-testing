"""Engine routes - worker management and health monitoring."""
import logging

from flask import Blueprint, jsonify, redirect, url_for, flash, render_template, session

from app.engine import get_worker, start_worker, stop_worker
from app.plugins.registry import tool_registry
from app.utils.decorators import login_required, admin_required

logger = logging.getLogger(__name__)

engine_bp = Blueprint('engine', __name__, url_prefix='/engine')


@engine_bp.route('/status')
@login_required
def status():
    """Return worker status as JSON."""
    worker = get_worker()
    if worker is None:
        return jsonify({
            'is_running': False,
            'running_jobs': [],
            'running_count': 0,
            'queued_count': 0,
            'max_concurrent_jobs': 0,
            'poll_interval': 0,
        })
    return jsonify(worker.get_status())


@engine_bp.route('/start', methods=['POST'])
@admin_required
def start():
    """Start the background worker (admin only)."""
    worker = get_worker()
    if worker is not None and worker._running:
        flash('Worker is already running.', 'warning')
        return redirect(url_for('engine.health'))

    # Import current_app lazily to avoid circular imports at module level
    from flask import current_app
    start_worker(current_app._get_current_object())
    flash('Worker started.', 'success')
    return redirect(url_for('engine.health'))


@engine_bp.route('/stop', methods=['POST'])
@admin_required
def stop():
    """Stop the background worker (admin only)."""
    worker = get_worker()
    if worker is None or not worker._running:
        flash('Worker is not running.', 'warning')
        return redirect(url_for('engine.health'))

    stop_worker()
    flash('Worker stopped.', 'success')
    return redirect(url_for('engine.health'))


@engine_bp.route('/health')
@admin_required
def health():
    """Full health check page: worker status, tool installation, DB connectivity."""
    # Worker status
    worker = get_worker()
    if worker is not None:
        worker_status = worker.get_status()
    else:
        worker_status = {
            'is_running': False,
            'running_jobs': [],
            'running_count': 0,
            'queued_count': 0,
            'max_concurrent_jobs': 0,
            'poll_interval': 0,
        }

    # Tool installation status
    tool_status = tool_registry.check_all_tools()

    # DB connectivity
    db_ok = True
    db_error = None
    try:
        from app.extensions import db
        db.session.execute(db.text('SELECT 1'))
    except Exception as exc:
        db_ok = False
        db_error = str(exc)

    return render_template(
        'engine/health.html',
        worker_status=worker_status,
        tool_status=tool_status,
        tools_info=tool_registry.SUPPORTED_TOOLS,
        categories=tool_registry.get_categories(),
        db_ok=db_ok,
        db_error=db_error,
    )
