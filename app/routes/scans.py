"""Scan routes - scan configuration and monitoring."""
from flask import Blueprint, render_template, redirect, url_for, request, flash, session, jsonify
from app.extensions import db
from app.services.scan_service import ScanService
from app.services.configuration_service import ConfigurationService
from app.models.scan import Scan
from app.models.scan_job import ScanJob
from app.models.finding import Finding
from app.models.target import Target
from app.models.project import Project
from app.utils.decorators import login_required
from app.plugins.registry import tool_registry

scans_bp = Blueprint('scans', __name__, url_prefix='/scans')
scan_service = ScanService()
config_service = ConfigurationService()


@scans_bp.route('/')
@login_required
def list_scans():
    """List all scans for the current user."""
    user_id = session['user_id']
    scans = Scan.query.filter_by(initiated_by=user_id)\
        .order_by(Scan.created_at.desc()).all()
    return render_template('scans/list.html', scans=scans)


@scans_bp.route('/start', methods=['GET', 'POST'])
@login_required
def start_scan():
    """Start a new scan (regular config-based).

    Auto-detects when the selected config needs pipeline mode (recon + vuln
    tools together on a domain target) and transparently routes to the
    pipeline service in that case. Also supports passing an optional
    authentication cookie for targets that require login (e.g. DVWA).
    """
    if request.method == 'POST':
        target_source = request.form.get('target_source', 'project')
        target_id = request.form.get('target_id', '').strip()
        manual_target = request.form.get('manual_target', '').strip()
        manual_target_type = request.form.get('manual_target_type', 'url')
        use_pipeline = request.form.get('use_pipeline') == 'on'
        config_id = request.form.get('config_id')
        auth_cookie = request.form.get('auth_cookie', '').strip()

        # Determine which target to use based on the source selection
        if target_source == 'manual':
            target_id = None  # Ignore project target when manual is selected
        else:
            manual_target = None  # Ignore manual target when project is selected
            manual_target_type = None

        # ── Auto-detect pipeline mode ───────────────────────────────
        # If the user checked "Use Pipeline Mode" OR the selected config
        # contains tools from multiple phases (recon + vuln), route to the
        # pipeline service instead of the regular scan service.
        from app.models.configuration import Configuration
        from app.models.target import Target as TargetModel
        from app.utils.validators import is_valid_domain, is_valid_url, is_valid_ip
        config = db.session.get(Configuration, config_id) if config_id else None

        # Determine target type for the auto-detection
        detected_target_type = manual_target_type
        detected_target_value = manual_target
        if target_id and not detected_target_value:
            t = db.session.get(TargetModel, target_id)
            if t:
                detected_target_value = t.value
                detected_target_type = t.type

        # ── Smart target-type detection ────────────────────────────
        # If the user typed a domain like "example.com" but left the dropdown
        # on "url", fix the type automatically so the pipeline can run.
        if detected_target_value:
            val = detected_target_value.strip()
            if val.startswith('http://') or val.startswith('https://'):
                detected_target_type = 'url'
            elif is_valid_domain(val):
                detected_target_type = 'domain'
            elif is_valid_ip(val):
                detected_target_type = 'ip'

        should_pipeline = use_pipeline
        if config and detected_target_value and not should_pipeline:
            should_pipeline = scan_service.should_use_pipeline(config, detected_target_type)

        # Route to pipeline mode if applicable
        if should_pipeline and detected_target_value and detected_target_type == 'domain':
            result = scan_service.start_pipeline_scan(
                user_id=session['user_id'],
                target_value=detected_target_value,
                scan_name=request.form.get('scan_name', ''),
                target_type=detected_target_type,
                config_id=config_id,
            )
            if result['success']:
                flash('Pipeline scan started! Phases will run automatically in order (1→2→3→4).',
                      'success')
                return redirect(url_for('scans.view_scan',
                                        scan_id=result['scan'].id))
            for error in result.get('errors', []):
                flash(error, 'error')
        else:
            # Regular scan with optional cookie support
            result = scan_service.start_scan(
                user_id=session['user_id'],
                target_id=target_id if target_id else None,
                config_id=config_id,
                scan_name=request.form.get('scan_name', ''),
                manual_target=manual_target if manual_target else None,
                manual_target_type=manual_target_type,
                auth_cookie=auth_cookie if auth_cookie else None,
            )
            if result['success']:
                flash(f"Scan started with {result['available_count']} tools!", 'success')
                if result.get('skipped_count', 0) > 0:
                    skipped_names = [s['binary'] for s in result.get('skipped_tools', [])]
                    unique_skipped = sorted(set(skipped_names))
                    flash(
                        f"⚠ {result['skipped_count']} tool(s) skipped (not installed): "
                        f"{', '.join(unique_skipped)}. Install them to enable full scanning.",
                        'warning'
                    )
                return redirect(url_for('scans.view_scan', scan_id=result['scan'].id))
            for error in result['errors']:
                flash(error, 'error')

    # GET: Show scan form
    user_id = session['user_id']
    projects = Project.query.filter_by(owner_id=user_id).all()
    project_ids = [p.id for p in projects]
    targets = Target.query.filter(Target.project_id.in_(project_ids)).all()
    configs = config_service.list_configs(user_id=user_id)

    # Check which tools are installed for display
    import shutil
    tool_status = {}
    for key, info in tool_registry.SUPPORTED_TOOLS.items():
        binary = info.get('tool', key)
        tool_status[key] = {
            'binary': binary,
            'installed': shutil.which(binary) is not None,
            'category': info['category'],
            'description': info['description'],
        }

    return render_template('scans/create.html', targets=targets, configs=configs,
                           projects=projects, tool_status=tool_status)


@scans_bp.route('/start-pipeline', methods=['GET', 'POST'])
@login_required
def start_pipeline_scan():
    """Start a multi-phase pipeline scan (Phase 1 → 2 → 3 → 4)."""
    if request.method == 'POST':
        target_value = request.form.get('target_value', '').strip()
        scan_name = request.form.get('scan_name', '').strip()
        target_type = request.form.get('target_type', 'domain')

        if not target_value:
            flash('Please enter a target domain.', 'error')
            return redirect(url_for('scans.start_pipeline_scan'))

        result = scan_service.start_pipeline_scan(
            user_id=session['user_id'],
            target_value=target_value,
            scan_name=scan_name,
            target_type=target_type,
        )
        if result['success']:
            flash('Pipeline scan started! Phases will run automatically.',
                  'success')
            return redirect(url_for('scans.view_scan',
                                    scan_id=result['scan'].id))
        for error in result.get('errors', []):
            flash(error, 'error')

    return render_template('scans/start_pipeline.html')


@scans_bp.route('/<int:scan_id>')
@login_required
def view_scan(scan_id):
    """View scan details with tabbed interface."""
    scan = Scan.query.get_or_404(scan_id)
    jobs = ScanJob.query.filter_by(scan_id=scan_id).order_by(ScanJob.created_at).all()

    # Compute overview stats for the first tab
    overview = scan.get_overview_stats()

    # Pipeline phase info if applicable
    pipeline_phase_label = None
    if scan.pipeline_mode:
        phase_labels = {1: 'Phase 1 — Subdomain Discovery',
                        2: 'Phase 2 — HTTP Probing',
                        3: 'Phase 3 — URL Gathering + Host Checks',
                        4: 'Phase 4 — Injection Scans'}
        pipeline_phase_label = phase_labels.get(scan.current_phase, 'Idle')

    # Fetch execution logs for each job (for debugging failed tools)
    from app.models.execution_log import ExecutionLog
    job_logs = {}
    for job in jobs:
        logs = ExecutionLog.query.filter_by(scan_job_id=job.id)\
            .order_by(ExecutionLog.created_at).all()
        if logs:
            job_logs[job.id] = logs

    return render_template('scans/view.html',
                           scan=scan, jobs=jobs,
                           overview=overview,
                           pipeline_phase_label=pipeline_phase_label,
                           job_logs=job_logs)


@scans_bp.route('/<int:scan_id>/job/<int:job_id>/logs')
@login_required
def job_logs(scan_id, job_id):
    """Return raw stdout/stderr for a job (for debugging failed tools)."""
    import os
    from flask import Response
    job = ScanJob.query.get_or_404(job_id)
    if job.scan_id != scan_id:
        return 'Job not found in this scan', 404

    output = []
    output.append(f'=== Job #{job.id}: {job.tool_name} ===')
    output.append(f'Status: {job.status}')
    output.append(f'Exit code: {job.exit_code}')
    output.append(f'Error: {job.error_message or "None"}')
    output.append(f'Command: {job.command}')
    output.append('')

    if job.stdout_path and os.path.exists(job.stdout_path):
        output.append('--- STDOUT ---')
        try:
            with open(job.stdout_path, 'r', errors='ignore') as f:
                output.append(f.read())
        except Exception as e:
            output.append(f'(error reading stdout: {e})')
        output.append('')

    if job.stderr_path and os.path.exists(job.stderr_path):
        output.append('--- STDERR ---')
        try:
            with open(job.stderr_path, 'r', errors='ignore') as f:
                output.append(f.read())
        except Exception as e:
            output.append(f'(error reading stderr: {e})')
        output.append('')

    # Also show execution logs
    from app.models.execution_log import ExecutionLog
    logs = ExecutionLog.query.filter_by(scan_job_id=job_id)\
        .order_by(ExecutionLog.created_at).all()
    if logs:
        output.append('--- EXECUTION LOGS ---')
        for log in logs:
            output.append(f'[{log.level}] {log.message}')
        output.append('')

    return Response('\n'.join(output), mimetype='text/plain')


@scans_bp.route('/<int:scan_id>/tab/overview')
@login_required
def tab_overview(scan_id):
    """Return overview stats as JSON for AJAX loading."""
    scan = Scan.query.get_or_404(scan_id)
    return jsonify(scan.get_overview_stats())


@scans_bp.route('/<int:scan_id>/tab/subdomains')
@login_required
def tab_subdomains(scan_id):
    """Return subdomains list as JSON."""
    scan = Scan.query.get_or_404(scan_id)
    subdomains = scan.get_subdomains()
    return jsonify({'subdomains': subdomains, 'count': len(subdomains)})


@scans_bp.route('/<int:scan_id>/tab/urls')
@login_required
def tab_urls(scan_id):
    """Return URLs list as JSON."""
    scan = Scan.query.get_or_404(scan_id)
    urls = scan.get_urls()
    return jsonify({'urls': urls, 'count': len(urls)})


@scans_bp.route('/<int:scan_id>/tab/vulnerabilities')
@login_required
def tab_vulnerabilities(scan_id):
    """Return vulnerabilities grouped by category as JSON."""
    scan = Scan.query.get_or_404(scan_id)
    grouped = scan.get_vulnerabilities_grouped()
    summary = {cat: len(items) for cat, items in grouped.items()}
    return jsonify({'grouped': grouped, 'summary': summary,
                    'total_categories': len(grouped)})


@scans_bp.route('/<int:scan_id>/cancel', methods=['POST'])
@login_required
def cancel_scan(scan_id):
    """Cancel a running scan."""
    result = scan_service.cancel_scan(scan_id, session['user_id'])
    if result['success']:
        flash('Scan cancelled.', 'success')
    else:
        flash(result['errors'][0], 'error')
    return redirect(url_for('scans.view_scan', scan_id=scan_id))


@scans_bp.route('/<int:scan_id>/status')
@login_required
def scan_status(scan_id):
    """Get scan status as JSON (for AJAX polling)."""
    scan = Scan.query.get_or_404(scan_id)
    jobs = ScanJob.query.filter_by(scan_id=scan_id).all()
    return jsonify({
        'scan_id': scan.id,
        'status': scan.status,
        'progress': scan.progress_percentage,
        'total_jobs': scan.total_jobs,
        'completed_jobs': scan.completed_jobs,
        'failed_jobs': scan.failed_jobs,
        'pipeline_mode': scan.pipeline_mode,
        'current_phase': scan.current_phase,
        'jobs': [{
            'id': j.id,
            'tool_name': j.tool_name,
            'status': j.status,
            'started_at': j.started_at.isoformat() if j.started_at else None,
            'completed_at': j.completed_at.isoformat() if j.completed_at else None,
        } for j in jobs]
    })
