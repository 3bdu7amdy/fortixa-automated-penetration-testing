"""Integration test - Scan lifecycle.

Tests the complete scan lifecycle:
  Create scan → Jobs created → Worker picks up → Jobs complete
  → Progress updates → Scan completion

Uses mocked tool runners — no real security tools are executed.
"""
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.extensions import db as _db
from app.models.user import User
from app.models.project import Project
from app.models.target import Target
from app.models.scan import Scan
from app.models.scan_job import ScanJob
from app.models.finding import Finding
from app.models.configuration import Configuration
from app.models.execution_log import ExecutionLog
from app.engine.task_queue import TaskQueue
from app.engine.worker import Worker
from app.services.scan_service import ScanService
from tests.helpers import (
    create_user_direct, create_project_direct, add_target_direct,
    create_scan_direct, create_scan_job_direct, get_default_config_id,
)


@pytest.fixture
def scan_setup(db):
    """Create the basic data needed for scan lifecycle tests.

    Returns a dict with user, project, target, and config.
    """
    user = create_user_direct('scan_user', 'scan@example.com', 'ScanPass123!', 'admin')
    project = create_project_direct('Scan Lifecycle Project', user.id)
    target = add_target_direct(project.id, 'lifecycle.example.com', 'domain', is_approved=True)
    config_id = get_default_config_id('recon')

    return {
        'user': user,
        'project': project,
        'target': target,
        'config_id': config_id,
    }


class TestScanCreation:
    """Test scan creation and job generation."""

    def test_scan_creates_jobs_for_enabled_tools(self, scan_setup, db):
        """When a scan is started, jobs are created for each enabled tool."""
        svc = ScanService()
        result = svc.start_scan(
            user_id=scan_setup['user'].id,
            target_id=scan_setup['target'].id,
            config_id=scan_setup['config_id'],
            scan_name='Lifecycle Scan',
        )
        assert result['success']

        scan = result['scan']
        config = Configuration.query.get(scan_setup['config_id'])
        enabled_tools = config.get_enabled_tools()

        jobs = ScanJob.query.filter_by(scan_id=scan.id).all()
        assert len(jobs) == len(enabled_tools)

        for job in jobs:
            assert job.tool_name in enabled_tools
            assert job.status == 'queued'
            assert job.scan_id == scan.id

    def test_scan_initial_status_is_pending(self, scan_setup, db):
        """A newly created scan has status='pending'."""
        svc = ScanService()
        result = svc.start_scan(
            user_id=scan_setup['user'].id,
            target_id=scan_setup['target'].id,
            config_id=scan_setup['config_id'],
            scan_name='Pending Scan',
        )
        scan = result['scan']
        assert scan.status == 'pending'
        assert scan.started_at is None

    def test_scan_total_jobs_matches_enabled_tools(self, scan_setup, db):
        """Scan total_jobs is set to the number of enabled tools."""
        svc = ScanService()
        result = svc.start_scan(
            user_id=scan_setup['user'].id,
            target_id=scan_setup['target'].id,
            config_id=scan_setup['config_id'],
            scan_name='Total Jobs Scan',
        )
        scan = result['scan']
        config = Configuration.query.get(scan_setup['config_id'])
        assert scan.total_jobs == len(config.get_enabled_tools())

    def test_scan_rejects_unapproved_target(self, db):
        """Scan cannot be started on an unapproved target."""
        user = create_user_direct('unapproved_user', 'unapproved@example.com', 'Pass1234!', 'user')
        project = create_project_direct('Unapproved Project', user.id)
        target = add_target_direct(project.id, 'unapproved.example.com', 'domain', is_approved=False)
        config_id = get_default_config_id('recon')

        svc = ScanService()
        result = svc.start_scan(
            user_id=user.id,
            target_id=target.id,
            config_id=config_id,
            scan_name='Should Fail',
        )
        assert not result['success']
        assert 'approved' in result['errors'][0].lower()

    def test_scan_rejects_nonexistent_target(self, db):
        """Scan cannot be started with a non-existent target."""
        user = create_user_direct('no_target_user', 'notarget@example.com', 'Pass1234!', 'user')
        config_id = get_default_config_id('recon')

        svc = ScanService()
        result = svc.start_scan(
            user_id=user.id,
            target_id=99999,
            config_id=config_id,
            scan_name='Should Fail',
        )
        assert not result['success']

    def test_scan_rejects_nonexistent_config(self, scan_setup, db):
        """Scan cannot be started with a non-existent config."""
        svc = ScanService()
        result = svc.start_scan(
            user_id=scan_setup['user'].id,
            target_id=scan_setup['target'].id,
            config_id=99999,
            scan_name='Should Fail',
        )
        assert not result['success']


class TestJobLifecycle:
    """Test individual job status transitions."""

    def test_job_transitions_queued_to_running(self, scan_setup, db):
        """A queued job transitions to running when picked up by the worker."""
        scan = create_scan_direct(
            scan_setup['target'].id, scan_setup['user'].id,
            scan_setup['config_id'], 'Job Test Scan',
        )
        job = create_scan_job_direct(scan.id, 'subfinder', 'subfinder -d lifecycle.example.com', 'queued')

        queue = TaskQueue()
        queue.mark_running(job.id)

        _db.session.expire_all()
        job = ScanJob.query.get(job.id)
        assert job.status == 'running'
        assert job.started_at is not None

    def test_job_transitions_running_to_completed(self, scan_setup, db):
        """A running job transitions to completed on success."""
        scan = create_scan_direct(
            scan_setup['target'].id, scan_setup['user'].id,
            scan_setup['config_id'], 'Complete Test Scan',
        )
        job = create_scan_job_direct(scan.id, 'httpx', 'httpx -u lifecycle.example.com', 'running')

        queue = TaskQueue()
        queue.mark_completed(job.id, exit_code=0)

        _db.session.expire_all()
        job = ScanJob.query.get(job.id)
        assert job.status == 'completed'
        assert job.exit_code == 0
        assert job.completed_at is not None

    def test_job_transitions_running_to_failed(self, scan_setup, db):
        """A running job transitions to failed on error."""
        scan = create_scan_direct(
            scan_setup['target'].id, scan_setup['user'].id,
            scan_setup['config_id'], 'Fail Test Scan',
        )
        job = create_scan_job_direct(scan.id, 'nuclei', 'nuclei -u lifecycle.example.com', 'running')

        queue = TaskQueue()
        queue.mark_failed(job.id, 'Tool crashed')

        _db.session.expire_all()
        job = ScanJob.query.get(job.id)
        assert job.status == 'failed'
        assert job.error_message == 'Tool crashed'

    def test_job_transitions_to_timeout(self, scan_setup, db):
        """A job can be marked as timed out."""
        scan = create_scan_direct(
            scan_setup['target'].id, scan_setup['user'].id,
            scan_setup['config_id'], 'Timeout Test Scan',
        )
        job = create_scan_job_direct(scan.id, 'amass', 'amass -d lifecycle.example.com', 'running')

        queue = TaskQueue()
        queue.mark_timeout(job.id)

        _db.session.expire_all()
        job = ScanJob.query.get(job.id)
        assert job.status == 'timeout'
        assert 'timed out' in job.error_message.lower()

    def test_job_retry_on_retryable_failure(self, scan_setup, db):
        """A failed job with retryable error gets re-queued."""
        scan = create_scan_direct(
            scan_setup['target'].id, scan_setup['user'].id,
            scan_setup['config_id'], 'Retry Test Scan',
        )
        job = create_scan_job_direct(scan.id, 'gau', 'gau -d lifecycle.example.com', 'failed')
        job.retry_count = 0
        job.max_retries = 2
        _db.session.commit()

        queue = TaskQueue()
        requeued = queue.increment_retry(job.id)
        assert requeued is True

        _db.session.expire_all()
        job = ScanJob.query.get(job.id)
        assert job.status == 'queued'
        assert job.retry_count == 1

    def test_job_max_retries_exceeded(self, scan_setup, db):
        """A job that exceeds max_retries is marked as failed permanently."""
        scan = create_scan_direct(
            scan_setup['target'].id, scan_setup['user'].id,
            scan_setup['config_id'], 'Max Retry Scan',
        )
        job = create_scan_job_direct(scan.id, 'katana', 'katana -u lifecycle.example.com', 'failed')
        job.retry_count = 1
        job.max_retries = 2
        _db.session.commit()

        queue = TaskQueue()
        requeued = queue.increment_retry(job.id)
        assert requeued is False  # max_retries hit

        _db.session.expire_all()
        job = ScanJob.query.get(job.id)
        assert job.status == 'failed'
        assert 'max retries' in job.error_message.lower()


class TestScanProgressUpdates:
    """Test that scan progress updates correctly as jobs complete."""

    def test_scan_status_updates_to_running(self, scan_setup, db):
        """Scan status changes from 'pending' to 'running' when first job starts."""
        scan = create_scan_direct(
            scan_setup['target'].id, scan_setup['user'].id,
            scan_setup['config_id'], 'Progress Scan',
        )
        job = create_scan_job_direct(scan.id, 'subfinder', 'subfinder -d test.com', 'queued')
        scan.total_jobs = 1
        _db.session.commit()

        # Mark job as running
        queue = TaskQueue()
        queue.mark_running(job.id)
        scan.update_progress()

        _db.session.expire_all()
        scan = Scan.query.get(scan.id)
        assert scan.status == 'running'
        assert scan.started_at is not None

    def test_scan_status_updates_to_completed(self, scan_setup, db):
        """Scan status changes to 'completed' when all jobs finish."""
        scan = create_scan_direct(
            scan_setup['target'].id, scan_setup['user'].id,
            scan_setup['config_id'], 'Complete Scan',
        )
        job1 = create_scan_job_direct(scan.id, 'subfinder', 'subfinder -d test.com', 'queued')
        job2 = create_scan_job_direct(scan.id, 'httpx', 'httpx -u test.com', 'queued')
        scan.total_jobs = 2
        _db.session.commit()

        queue = TaskQueue()
        # Complete both jobs
        queue.mark_running(job1.id)
        queue.mark_completed(job1.id, exit_code=0)
        queue.mark_running(job2.id)
        queue.mark_completed(job2.id, exit_code=0)

        scan.update_progress()

        _db.session.expire_all()
        scan = Scan.query.get(scan.id)
        assert scan.status == 'completed'
        assert scan.completed_at is not None
        assert scan.completed_jobs == 2

    def test_scan_progress_percentage(self, scan_setup, db):
        """Progress percentage is calculated correctly."""
        scan = create_scan_direct(
            scan_setup['target'].id, scan_setup['user'].id,
            scan_setup['config_id'], 'Percentage Scan',
        )
        job1 = create_scan_job_direct(scan.id, 'subfinder', 'subfinder -d test.com', 'queued')
        job2 = create_scan_job_direct(scan.id, 'httpx', 'httpx -u test.com', 'queued')
        scan.total_jobs = 2
        _db.session.commit()

        # Complete one job
        queue = TaskQueue()
        queue.mark_running(job1.id)
        queue.mark_completed(job1.id, exit_code=0)

        scan.update_progress()

        _db.session.expire_all()
        scan = Scan.query.get(scan.id)
        assert scan.progress_percentage == 50

    def test_scan_with_failed_jobs_still_completes(self, scan_setup, db):
        """A scan with some failed jobs still marks as completed."""
        scan = create_scan_direct(
            scan_setup['target'].id, scan_setup['user'].id,
            scan_setup['config_id'], 'Mixed Results Scan',
        )
        job1 = create_scan_job_direct(scan.id, 'subfinder', 'subfinder -d test.com', 'queued')
        job2 = create_scan_job_direct(scan.id, 'nuclei', 'nuclei -u test.com', 'queued')
        scan.total_jobs = 2
        _db.session.commit()

        queue = TaskQueue()
        queue.mark_running(job1.id)
        queue.mark_completed(job1.id, exit_code=0)
        queue.mark_running(job2.id)
        queue.mark_failed(job2.id, 'Tool error')

        scan.update_progress()

        _db.session.expire_all()
        scan = Scan.query.get(scan.id)
        # Some jobs failed but scan should still be completed
        assert scan.status == 'completed'
        assert scan.completed_jobs == 1
        assert scan.failed_jobs == 1

    def test_scan_all_failed_marks_failed(self, scan_setup, db):
        """A scan where all jobs failed marks as 'failed'."""
        scan = create_scan_direct(
            scan_setup['target'].id, scan_setup['user'].id,
            scan_setup['config_id'], 'All Failed Scan',
        )
        job = create_scan_job_direct(scan.id, 'nuclei', 'nuclei -u test.com', 'queued')
        scan.total_jobs = 1
        _db.session.commit()

        queue = TaskQueue()
        queue.mark_running(job.id)
        queue.mark_failed(job.id, 'Complete failure')

        scan.update_progress()

        _db.session.expire_all()
        scan = Scan.query.get(scan.id)
        # All jobs failed - scan is marked as 'failed'
        assert scan.status == 'failed'
        assert scan.failed_jobs == 1
        assert scan.completed_jobs == 0


class TestScanCancellation:
    """Test scan cancellation workflow."""

    def test_cancel_scan_marks_queued_jobs_skipped(self, scan_setup, db):
        """Cancelling a scan skips all queued jobs."""
        svc = ScanService()
        result = svc.start_scan(
            user_id=scan_setup['user'].id,
            target_id=scan_setup['target'].id,
            config_id=scan_setup['config_id'],
            scan_name='Cancel Scan',
        )
        scan = result['scan']

        # Cancel the scan
        cancel_result = svc.cancel_scan(scan.id, scan_setup['user'].id)
        assert cancel_result['success']

        _db.session.expire_all()
        scan = Scan.query.get(scan.id)
        assert scan.status == 'cancelled'

        # Queued jobs should be skipped
        jobs = ScanJob.query.filter_by(scan_id=scan.id).all()
        for job in jobs:
            assert job.status == 'skipped'


class TestWorkerExecution:
    """Test the worker executing scan jobs with mocked tool runners."""

    def test_worker_executes_job_with_mock_runner(self, app, scan_setup, db):
        """Worker executes a job using a mocked tool runner."""
        scan = create_scan_direct(
            scan_setup['target'].id, scan_setup['user'].id,
            scan_setup['config_id'], 'Worker Test Scan',
        )
        job = create_scan_job_direct(
            scan.id, 'mock_tool', 'mock_tool lifecycle.example.com', 'queued',
        )
        scan.total_jobs = 1
        _db.session.commit()

        # Create a mock runner
        mock_runner = MagicMock()
        mock_runner.run.return_value = {
            'exit_code': 0,
            'findings': [{
                'title': 'Test Finding',
                'severity': 'medium',
                'category': 'xss',
                'url': 'https://lifecycle.example.com/search',
                'evidence': 'XSS found',
            }],
            'output_files': [],
            'stats': {},
        }

        # Register mock runner
        with patch.dict(ScanService.TOOL_RUNNERS, {'mock_tool': lambda: mock_runner}):
            worker = Worker(app)
            worker._execute_job(job.id)

        # Verify job completed
        _db.session.expire_all()
        job = ScanJob.query.get(job.id)
        assert job.status == 'completed'
        assert job.exit_code == 0

        # Verify finding stored
        findings = Finding.query.filter_by(scan_id=scan.id).all()
        assert len(findings) == 1
        assert findings[0].title == 'Test Finding'
        assert findings[0].severity == 'medium'

        # Verify scan progress updated
        scan = Scan.query.get(scan.id)
        assert scan.status == 'completed'

    def test_worker_handles_runner_failure(self, app, scan_setup, db):
        """Worker handles a tool runner that returns an error."""
        scan = create_scan_direct(
            scan_setup['target'].id, scan_setup['user'].id,
            scan_setup['config_id'], 'Worker Fail Scan',
        )
        job = create_scan_job_direct(
            scan.id, 'failing_tool', 'failing_tool lifecycle.example.com', 'queued',
        )
        scan.total_jobs = 1
        _db.session.commit()

        # Create a mock runner that fails
        mock_runner = MagicMock()
        mock_runner.run.return_value = {
            'exit_code': 1,
            'error': 'Tool crashed',
            'findings': [],
            'output_files': [],
            'stats': {},
        }

        with patch.dict(ScanService.TOOL_RUNNERS, {'failing_tool': lambda: mock_runner}):
            worker = Worker(app)
            worker._execute_job(job.id)

        _db.session.expire_all()
        job = ScanJob.query.get(job.id)
        assert job.status in ('failed', 'queued')  # May be re-queued for retry

    def test_worker_handles_no_runner(self, app, scan_setup, db):
        """Worker handles the case where no runner is registered for a tool."""
        scan = create_scan_direct(
            scan_setup['target'].id, scan_setup['user'].id,
            scan_setup['config_id'], 'No Runner Scan',
        )
        job = create_scan_job_direct(
            scan.id, 'unknown_tool', 'unknown_tool lifecycle.example.com', 'queued',
        )
        scan.total_jobs = 1
        _db.session.commit()

        # Ensure no runner registered
        with patch.dict(ScanService.TOOL_RUNNERS, {}, clear=True):
            worker = Worker(app)
            worker._execute_job(job.id)

        _db.session.expire_all()
        job = ScanJob.query.get(job.id)
        assert job.status == 'failed'
        assert 'runner' in (job.error_message or '').lower() or 'No runner' in (job.error_message or '')

    def test_worker_creates_execution_logs(self, app, scan_setup, db):
        """Worker creates ExecutionLog entries during job execution."""
        scan = create_scan_direct(
            scan_setup['target'].id, scan_setup['user'].id,
            scan_setup['config_id'], 'Log Test Scan',
        )
        job = create_scan_job_direct(
            scan.id, 'logged_tool', 'logged_tool lifecycle.example.com', 'queued',
        )
        scan.total_jobs = 1
        _db.session.commit()

        mock_runner = MagicMock()
        mock_runner.run.return_value = {
            'exit_code': 0,
            'findings': [],
            'output_files': [],
            'stats': {},
        }

        with patch.dict(ScanService.TOOL_RUNNERS, {'logged_tool': lambda: mock_runner}):
            worker = Worker(app)
            worker._execute_job(job.id)

        # Verify execution logs created
        logs = ExecutionLog.query.filter_by(scan_job_id=job.id).all()
        assert len(logs) >= 1
        log_messages = [l.message for l in logs]
        assert any('Starting' in m for m in log_messages)

    def test_worker_handles_cancelled_scan(self, app, scan_setup, db):
        """Worker skips execution for jobs in a cancelled scan."""
        scan = create_scan_direct(
            scan_setup['target'].id, scan_setup['user'].id,
            scan_setup['config_id'], 'Cancelled Worker Scan',
            status='cancelled',
        )
        job = create_scan_job_direct(
            scan.id, 'cancel_tool', 'cancel_tool lifecycle.example.com', 'queued',
        )
        scan.total_jobs = 1
        _db.session.commit()

        mock_runner = MagicMock()

        with patch.dict(ScanService.TOOL_RUNNERS, {'cancel_tool': lambda: mock_runner}):
            worker = Worker(app)
            worker._execute_job(job.id)

        # Runner should not have been called
        mock_runner.run.assert_not_called()

        # Job should be marked as failed
        _db.session.expire_all()
        job = ScanJob.query.get(job.id)
        assert job.status == 'failed'


class TestTaskQueueOperations:
    """Test the task queue operations used during scan lifecycle."""

    def test_dequeue_returns_oldest_queued_job(self, scan_setup, db):
        """Dequeue returns the oldest queued job (FIFO)."""
        scan = create_scan_direct(
            scan_setup['target'].id, scan_setup['user'].id,
            scan_setup['config_id'], 'Queue Order Scan',
        )
        job1 = create_scan_job_direct(scan.id, 'subfinder', 'subfinder -d test.com', 'queued')
        job2 = create_scan_job_direct(scan.id, 'httpx', 'httpx -u test.com', 'queued')

        queue = TaskQueue()
        next_job = queue.dequeue()
        assert next_job is not None
        assert next_job.id == job1.id

    def test_dequeue_returns_none_when_empty(self, db):
        """Dequeue returns None when no queued jobs exist."""
        queue = TaskQueue()
        result = queue.dequeue()
        assert result is None

    def test_get_queued_count(self, scan_setup, db):
        """get_queued_count returns correct count of queued jobs."""
        scan = create_scan_direct(
            scan_setup['target'].id, scan_setup['user'].id,
            scan_setup['config_id'], 'Count Scan',
        )
        create_scan_job_direct(scan.id, 'tool1', 'tool1 test.com', 'queued')
        create_scan_job_direct(scan.id, 'tool2', 'tool2 test.com', 'queued')
        create_scan_job_direct(scan.id, 'tool3', 'tool3 test.com', 'running')

        queue = TaskQueue()
        assert queue.get_queued_count() == 2

    def test_get_running_count(self, scan_setup, db):
        """get_running_count returns correct count of running jobs."""
        scan = create_scan_direct(
            scan_setup['target'].id, scan_setup['user'].id,
            scan_setup['config_id'], 'Running Count Scan',
        )
        create_scan_job_direct(scan.id, 'tool1', 'tool1 test.com', 'running')
        create_scan_job_direct(scan.id, 'tool2', 'tool2 test.com', 'queued')

        queue = TaskQueue()
        assert queue.get_running_count() == 1

    def test_dequeue_by_scan(self, scan_setup, db):
        """dequeue_by_scan returns the next queued job for a specific scan."""
        scan = create_scan_direct(
            scan_setup['target'].id, scan_setup['user'].id,
            scan_setup['config_id'], 'Specific Scan',
        )
        job = create_scan_job_direct(scan.id, 'subfinder', 'subfinder -d test.com', 'queued')

        queue = TaskQueue()
        result = queue.dequeue_by_scan(scan.id)
        assert result is not None
        assert result.id == job.id
