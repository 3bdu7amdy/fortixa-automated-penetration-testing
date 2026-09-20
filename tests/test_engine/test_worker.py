"""Tests for the Worker."""
import time
import pytest
from unittest.mock import MagicMock, patch
from app import create_app
from app.extensions import db as _db
from app.engine.worker import Worker
from app.engine.task_queue import TaskQueue
from app.models.scan import Scan
from app.models.scan_job import ScanJob
from app.models.target import Target
from app.models.project import Project
from app.models.user import User
from app.models.finding import Finding
from app.models.execution_log import ExecutionLog
from app.services.scan_service import ScanService
from app.plugins.base import BaseToolRunner


@pytest.fixture(scope='module')
def app():
    """Create application for testing."""
    app = create_app('testing')
    yield app


@pytest.fixture(scope='function')
def db(app):
    """Create a fresh database for each test."""
    with app.app_context():
        _db.create_all()
        yield _db
        _db.session.remove()
        _db.drop_all()


_counter = 0


def _setup_scan_job(db, status='queued', tool_name='nmap', max_retries=2):
    """Helper: create a ScanJob with all dependencies."""
    global _counter
    _counter += 1
    uid = _counter
    user = User(username=f'testuser{uid}', email=f'test{uid}@example.com', role='admin')
    user.password = 'TestPass123!'
    db.session.add(user)
    db.session.commit()

    project = Project(name=f'Test Project {uid}', owner_id=user.id)
    db.session.add(project)
    db.session.commit()

    target = Target(project_id=project.id, value=f'example{uid}.com', type='domain', is_approved=True)
    db.session.add(target)
    db.session.commit()

    scan = Scan(
        target_id=target.id,
        initiated_by=user.id,
        name=f'Test Scan {uid}',
        scan_type='recon',
        status='pending',
    )
    db.session.add(scan)
    db.session.commit()

    job = ScanJob(
        scan_id=scan.id,
        tool_name=tool_name,
        status=status,
        command=f'{tool_name} example{uid}.com',
        max_retries=max_retries,
        timeout_seconds=600,
        output_dir=f'output/example{uid}.com/{tool_name}',
    )
    db.session.add(job)
    db.session.commit()

    return {
        'user': user,
        'project': project,
        'target': target,
        'scan': scan,
        'job': job,
    }


class FakeRunner(BaseToolRunner):
    """A fake tool runner for testing that returns configurable results."""

    tool_name = 'fake'

    def __init__(self, result=None, side_effect=None):
        self._result = result or {
            'exit_code': 0,
            'findings': [],
            'output_files': [],
            'stats': {},
        }
        self._side_effect = side_effect

    def build_command(self, target, options):
        return ['echo', target]

    def parse_output(self, stdout, stderr, output_dir):
        return {
            'findings': [],
            'output_files': [],
            'stats': {},
        }

    def run(self, target, options, output_dir):
        if self._side_effect:
            raise self._side_effect
        return self._result


class TestWorker:
    """Test suite for the Worker class."""

    def test_worker_start_stop(self, app, db):
        """Worker should start and stop cleanly."""
        with app.app_context():
            worker = Worker(app)
            assert not worker._running

            worker.start()
            assert worker._running
            assert worker._thread is not None
            assert worker._thread.is_alive()

            worker.stop(graceful=True)
            assert not worker._running

    def test_worker_get_status(self, app, db):
        """get_status should return correct worker state."""
        with app.app_context():
            worker = Worker(app)
            status = worker.get_status()
            assert status['is_running'] is False
            assert status['running_jobs'] == []
            assert status['running_count'] == 0
            assert status['max_concurrent_jobs'] == Worker.MAX_CONCURRENT_JOBS

    def test_worker_get_status_while_running(self, app, db):
        """get_status should reflect running state."""
        with app.app_context():
            worker = Worker(app)
            worker.start()
            try:
                status = worker.get_status()
                assert status['is_running'] is True
            finally:
                worker.stop(graceful=True)

    def test_worker_double_start(self, app, db):
        """Starting an already-running worker should be a no-op."""
        with app.app_context():
            worker = Worker(app)
            worker.start()
            try:
                # Starting again should not raise or create a second thread
                worker.start()
                assert worker._running
            finally:
                worker.stop(graceful=True)

    def test_worker_stop_when_not_running(self, app, db):
        """Stopping a non-running worker should not raise."""
        with app.app_context():
            worker = Worker(app)
            worker.stop()  # Should not raise

    def test_execute_job_with_mock_runner(self, app, db):
        """Worker should execute a job using a registered tool runner."""
        with app.app_context():
            data = _setup_scan_job(db, status='queued')

            # Create a fake runner that succeeds with findings
            fake_result = {
                'exit_code': 0,
                'findings': [
                    {
                        'title': 'Test Finding',
                        'severity': 'medium',
                        'category': 'recon',
                        'description': 'A test finding',
                    }
                ],
                'output_files': [],
                'stats': {},
            }

            def make_runner():
                return FakeRunner(result=fake_result)

            ScanService.TOOL_RUNNERS['nmap'] = make_runner

            worker = Worker(app)
            worker._queue = TaskQueue()

            # Mark job as running and execute
            worker._queue.mark_running(data['job'].id)
            worker._execute_job(data['job'].id)

            # Refresh from DB
            _db.session.expire_all()
            job = ScanJob.query.get(data['job'].id)
            assert job.status == 'completed'

            # Verify finding was stored
            finding = Finding.query.filter_by(scan_job_id=job.id).first()
            assert finding is not None
            assert finding.title == 'Test Finding'
            assert finding.severity == 'medium'

            # Verify execution log
            log = ExecutionLog.query.filter_by(scan_job_id=job.id).first()
            assert log is not None

            # Clean up
            ScanService.TOOL_RUNNERS.pop('nmap', None)

    def test_execute_job_no_runner(self, app, db):
        """Worker should mark job as failed when no runner is registered."""
        with app.app_context():
            data = _setup_scan_job(db, status='queued', tool_name='unknown_tool')

            # Ensure no runner for unknown_tool
            ScanService.TOOL_RUNNERS.pop('unknown_tool', None)

            worker = Worker(app)
            worker._queue = TaskQueue()
            worker._queue.mark_running(data['job'].id)
            worker._execute_job(data['job'].id)

            _db.session.expire_all()
            job = ScanJob.query.get(data['job'].id)
            assert job.status == 'failed'
            assert 'No runner' in job.error_message

    def test_execute_job_runner_exception(self, app, db):
        """Worker should handle runner exceptions gracefully."""
        with app.app_context():
            data = _setup_scan_job(db, status='queued', tool_name='nmap')

            def make_crashing_runner():
                return FakeRunner(side_effect=RuntimeError('Tool crashed'))

            ScanService.TOOL_RUNNERS['nmap'] = make_crashing_runner

            worker = Worker(app)
            worker._queue = TaskQueue()
            worker._queue.mark_running(data['job'].id)
            worker._execute_job(data['job'].id)

            _db.session.expire_all()
            job = ScanJob.query.get(data['job'].id)
            # After the exception, the job should be marked as failed
            # (then retry might re-queue it since exit_code -1 is retryable)
            assert job.status in ('failed', 'queued')

            # Clean up
            ScanService.TOOL_RUNNERS.pop('nmap', None)

    def test_is_retryable(self, app, db):
        """_is_retryable should correctly identify retryable failures."""
        with app.app_context():
            worker = Worker(app)

            data = _setup_scan_job(db, status='failed')

            # Retryable exit code, no non-retryable pattern
            result = {'exit_code': 1, 'error': 'network timeout'}
            assert worker._is_retryable(data['job'], result) is True

            # Exit code 0 is not retryable (not in list)
            result = {'exit_code': 0, 'error': ''}
            assert worker._is_retryable(data['job'], result) is False

            # Non-retryable pattern in error
            result = {'exit_code': 1, 'error': 'command not found'}
            assert worker._is_retryable(data['job'], result) is False

            # Permission denied pattern
            result = {'exit_code': 2, 'error': 'permission denied'}
            assert worker._is_retryable(data['job'], result) is False

            # No such file pattern
            result = {'exit_code': -1, 'error': 'no such file or directory'}
            assert worker._is_retryable(data['job'], result) is False

    def test_is_retryable_max_retries(self, app, db):
        """_is_retryable should return False when max_retries exceeded."""
        with app.app_context():
            worker = Worker(app)
            data = _setup_scan_job(db, status='failed', max_retries=2)
            data['job'].retry_count = 2
            _db.session.commit()

            result = {'exit_code': 1, 'error': 'network timeout'}
            assert worker._is_retryable(data['job'], result) is False

    def test_execute_job_with_timeout(self, app, db):
        """Worker should mark job as timeout when tool times out."""
        with app.app_context():
            data = _setup_scan_job(db, status='queued', tool_name='nmap', max_retries=0)

            # Create a fake runner that returns a timeout result
            fake_result = {
                'exit_code': -1,
                'error': 'Timeout after 600 seconds',
                'findings': [],
                'output_files': [],
                'stats': {},
            }

            def make_runner():
                return FakeRunner(result=fake_result)

            ScanService.TOOL_RUNNERS['nmap'] = make_runner

            worker = Worker(app)
            worker._queue = TaskQueue()
            worker._queue.mark_running(data['job'].id)
            worker._execute_job(data['job'].id)

            _db.session.expire_all()
            job = ScanJob.query.get(data['job'].id)
            assert job.status == 'timeout'

            # Clean up
            ScanService.TOOL_RUNNERS.pop('nmap', None)

    def test_execute_job_with_timeout_retries(self, app, db):
        """Worker should retry a timed-out job if retries remain."""
        with app.app_context():
            data = _setup_scan_job(db, status='queued', tool_name='nmap', max_retries=2)

            fake_result = {
                'exit_code': -1,
                'error': 'Timeout after 600 seconds',
                'findings': [],
                'output_files': [],
                'stats': {},
            }

            def make_runner():
                return FakeRunner(result=fake_result)

            ScanService.TOOL_RUNNERS['nmap'] = make_runner

            worker = Worker(app)
            worker._queue = TaskQueue()
            worker._queue.mark_running(data['job'].id)
            worker._execute_job(data['job'].id)

            _db.session.expire_all()
            job = ScanJob.query.get(data['job'].id)
            # Job should be re-queued for retry since max_retries > 0
            assert job.status == 'queued'
            assert job.retry_count == 1

            # Clean up
            ScanService.TOOL_RUNNERS.pop('nmap', None)

    def test_worker_polls_and_dispatches(self, app, db):
        """Worker should automatically dequeue and start queued jobs."""
        with app.app_context():
            data = _setup_scan_job(db, status='queued')

            # Create a fake runner
            def make_runner():
                return FakeRunner(result={
                    'exit_code': 0,
                    'findings': [],
                    'output_files': [],
                    'stats': {},
                })

            ScanService.TOOL_RUNNERS['nmap'] = make_runner

            worker = Worker(app)
            worker.POLL_INTERVAL = 1  # Speed up for testing
            worker.start()

            # Wait for the worker to pick up the job
            time.sleep(3)

            worker.stop(graceful=True)

            # Verify the job was executed
            _db.session.expire_all()
            job = ScanJob.query.get(data['job'].id)
            # It should no longer be 'queued' – at least started
            assert job.status in ('running', 'completed', 'failed', 'timeout')

            # Clean up
            ScanService.TOOL_RUNNERS.pop('nmap', None)
