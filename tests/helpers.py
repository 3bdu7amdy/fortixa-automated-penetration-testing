"""Test helper functions for integration tests.

Provides reusable helper functions for common operations like
user registration, login, project creation, target addition,
and scan execution with mocked tool runners.
"""
from app.extensions import db as _db
from app.models.user import User
from app.models.project import Project
from app.models.target import Target
from app.models.scan import Scan
from app.models.scan_job import ScanJob
from app.models.configuration import Configuration
from app.models.finding import Finding


def register_user(client, username, email, password):
    """Helper to register a user and return the response.

    Args:
        client: Flask test client.
        username: Desired username.
        email: User email address.
        password: Password (must be 8+ chars).

    Returns:
        Flask test client response object.
    """
    return client.post('/auth/register', data={
        'username': username,
        'email': email,
        'password': password,
        'confirm_password': password,
    })


def login_user(client, username, password):
    """Helper to login a user and return the response.

    Args:
        client: Flask test client.
        username: Username to log in.
        password: Password for the user.

    Returns:
        Flask test client response object.
    """
    return client.post('/auth/login', data={
        'username': username,
        'password': password,
    })


def create_project(client, name, description=''):
    """Helper to create a project via the web form.

    Args:
        client: Authenticated Flask test client.
        name: Project name.
        description: Optional project description.

    Returns:
        Flask test client response object.
    """
    return client.post('/projects/create', data={
        'name': name,
        'description': description,
    })


def add_target(client, project_id, value, target_type='domain'):
    """Helper to add a target to a project via the web form.

    Args:
        client: Authenticated Flask test client.
        project_id: ID of the project.
        value: Target value (domain, IP, URL, CIDR).
        target_type: Type of target (domain, ip, url, cidr).

    Returns:
        Flask test client response object.
    """
    return client.post(f'/projects/{project_id}/targets/add', data={
        'value': value,
        'type': target_type,
        'description': f'Test target {value}',
    })


def approve_target(client, project_id, target_id):
    """Helper to approve a target (requires admin user).

    Args:
        client: Authenticated admin Flask test client.
        project_id: ID of the project.
        target_id: ID of the target to approve.

    Returns:
        Flask test client response object.
    """
    return client.post(f'/projects/{project_id}/targets/{target_id}/approve')


def create_and_run_scan(client, target_id, config_id, scan_name='Test Scan'):
    """Helper to create and start a scan with mocked execution.

    Submits the scan start form, which creates a Scan record and
    associated ScanJob records. Tool execution is NOT performed
    in testing mode (no worker runs), so jobs remain in 'queued' status.

    Args:
        client: Authenticated Flask test client.
        target_id: ID of the approved target.
        config_id: ID of the scan configuration.
        scan_name: Name for the scan.

    Returns:
        Flask test client response object (redirect to scan view).
    """
    return client.post('/scans/start', data={
        'target_id': target_id,
        'config_id': config_id,
        'scan_name': scan_name,
    })


# ── Direct DB helpers (bypass routes, for setup) ────────────────────────────

def create_user_direct(username, email, password, role='user'):
    """Create a user directly in the DB (no HTTP request).

    Args:
        username: Unique username.
        email: Unique email address.
        password: Password string (will be hashed).
        role: User role ('user' or 'admin').

    Returns:
        User model instance.
    """
    user = User(username=username, email=email)
    user.password = password
    user.role = role
    user.save()
    return user


def create_project_direct(name, owner_id, description='', status='active'):
    """Create a project directly in the DB (no HTTP request).

    Args:
        name: Project name.
        owner_id: User ID of the project owner.
        description: Optional description.
        status: Project status.

    Returns:
        Project model instance.
    """
    project = Project(
        name=name,
        description=description,
        owner_id=owner_id,
        status=status,
    )
    project.save()
    return project


def add_target_direct(project_id, value, target_type='domain', is_approved=True):
    """Add a target directly in the DB (no HTTP request).

    Args:
        project_id: ID of the project.
        value: Target value (domain, IP, etc.).
        target_type: Type of target.
        is_approved: Whether the target is pre-approved.

    Returns:
        Target model instance.
    """
    target = Target(
        project_id=project_id,
        value=value,
        type=target_type,
        is_approved=is_approved,
    )
    target.save()
    return target


def create_scan_direct(target_id, user_id, config_id, scan_name='Test Scan',
                       scan_type='recon', status='pending'):
    """Create a scan directly in the DB with associated jobs.

    Args:
        target_id: ID of the target.
        user_id: ID of the initiating user.
        config_id: ID of the configuration.
        scan_name: Name for the scan.
        scan_type: Type of scan.
        status: Initial scan status.

    Returns:
        Scan model instance.
    """
    scan = Scan(
        target_id=target_id,
        initiated_by=user_id,
        name=scan_name,
        scan_type=scan_type,
        config_id=config_id,
        status=status,
    )
    scan.save()
    return scan


def create_scan_job_direct(scan_id, tool_name, command='', status='queued'):
    """Create a scan job directly in the DB.

    Args:
        scan_id: ID of the scan.
        tool_name: Name of the tool.
        command: Command string.
        status: Initial job status.

    Returns:
        ScanJob model instance.
    """
    job = ScanJob(
        scan_id=scan_id,
        tool_name=tool_name,
        command=command or f'{tool_name} example.com',
        status=status,
    )
    job.save()
    return job


def create_finding_direct(scan_id, scan_job_id, target_id, project_id,
                          title, severity='info', category='info',
                          tool_name='test_tool', url=None, evidence=None):
    """Create a finding directly in the DB.

    Args:
        scan_id: ID of the scan.
        scan_job_id: ID of the scan job.
        target_id: ID of the target.
        project_id: ID of the project.
        title: Finding title.
        severity: Severity level.
        category: Finding category.
        tool_name: Tool that discovered it.
        url: URL where finding was found.
        evidence: Evidence text.

    Returns:
        Finding model instance.
    """
    finding = Finding(
        scan_id=scan_id,
        scan_job_id=scan_job_id,
        target_id=target_id,
        project_id=project_id,
        title=title,
        severity=severity,
        category=category,
        tool_name=tool_name,
        url=url,
        evidence=evidence,
    )
    finding.save()
    return finding


def get_default_config_id(config_type='recon'):
    """Get the ID of a default configuration by type.

    Args:
        config_type: Type of configuration to find.

    Returns:
        int: Configuration ID or None if not found.
    """
    config = Configuration.query.filter_by(
        is_default=True,
        config_type=config_type,
    ).first()
    return config.id if config else None


def complete_all_scan_jobs(scan_id):
    """Mark all pending/queued/running jobs for a scan as completed.

    This simulates the worker completing all jobs without actually
    running any security tools.

    Args:
        scan_id: ID of the scan.

    Returns:
        int: Number of jobs marked as completed.
    """
    jobs = ScanJob.query.filter(
        ScanJob.scan_id == scan_id,
        ScanJob.status.in_(['queued', 'running', 'pending']),
    ).all()

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    for job in jobs:
        job.status = 'completed'
        job.exit_code = 0
        job.started_at = now
        job.completed_at = now

    _db.session.commit()

    # Update scan progress
    scan = Scan.query.get(scan_id)
    if scan:
        scan.update_progress()

    return len(jobs)
