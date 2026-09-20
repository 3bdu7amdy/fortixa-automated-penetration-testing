"""Tests for TaskQueue."""
import pytest
from app import create_app
from app.extensions import db as _db
from app.engine.task_queue import TaskQueue
from app.models.scan import Scan
from app.models.scan_job import ScanJob
from app.models.target import Target
from app.models.project import Project
from app.models.user import User
from app.models.configuration import Configuration


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


@pytest.fixture(scope='function')
def queue(db):
    """Create a TaskQueue instance."""
    return TaskQueue()


_counter = 0


def _create_job(db, status='queued', tool_name='nmap', max_retries=2):
    """Helper: create a ScanJob with minimal dependencies."""
    global _counter
    _counter += 1
    uid = _counter
    # Create user (unique per call)
    user = User(username=f'testuser{uid}', email=f'test{uid}@example.com', role='admin')
    user.password = 'TestPass123!'
    db.session.add(user)
    db.session.commit()

    # Create project
    project = Project(name=f'Test Project {uid}', owner_id=user.id)
    db.session.add(project)
    db.session.commit()

    # Create target
    target = Target(project_id=project.id, value=f'example{uid}.com', type='domain', is_approved=True)
    db.session.add(target)
    db.session.commit()

    # Create scan
    scan = Scan(
        target_id=target.id,
        initiated_by=user.id,
        name=f'Test Scan {uid}',
        scan_type='recon',
        status='pending',
    )
    db.session.add(scan)
    db.session.commit()

    # Create scan job
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

    return job


class TestTaskQueue:
    """Test suite for TaskQueue."""

    def test_enqueue(self, app, db, queue):
        """enqueue should set job status to 'queued'."""
        with app.app_context():
            job = _create_job(db, status='pending')
            result = queue.enqueue(job.id)
            assert result is True

            updated = ScanJob.query.get(job.id)
            assert updated.status == 'queued'

    def test_enqueue_nonexistent_job(self, app, db, queue):
        """enqueue should return False for nonexistent job."""
        with app.app_context():
            result = queue.enqueue(99999)
            assert result is False

    def test_dequeue(self, app, db, queue):
        """dequeue should return the oldest queued job (FIFO)."""
        with app.app_context():
            job1 = _create_job(db, tool_name='nmap')
            job2 = _create_job(db, tool_name='subfinder')

            # job1 was created first, should be dequeued first
            result = queue.dequeue()
            assert result is not None
            assert result.id == job1.id
            assert result.tool_name == 'nmap'

    def test_dequeue_empty(self, app, db, queue):
        """dequeue should return None when no queued jobs exist."""
        with app.app_context():
            result = queue.dequeue()
            assert result is None

    def test_dequeue_by_scan(self, app, db, queue):
        """dequeue_by_scan should return next queued job for a specific scan."""
        with app.app_context():
            job1 = _create_job(db, tool_name='nmap')
            # Create a second job in the same scan
            job2 = ScanJob(
                scan_id=job1.scan_id,
                tool_name='subfinder',
                status='queued',
                command='subfinder -d example.com',
                max_retries=2,
                timeout_seconds=600,
                output_dir='output/example.com/subfinder',
            )
            db.session.add(job2)
            db.session.commit()

            result = queue.dequeue_by_scan(job1.scan_id)
            assert result is not None
            assert result.id == job1.id

    def test_dequeue_by_scan_no_jobs(self, app, db, queue):
        """dequeue_by_scan should return None if no queued jobs for the scan."""
        with app.app_context():
            result = queue.dequeue_by_scan(99999)
            assert result is None

    def test_get_running_count(self, app, db, queue):
        """get_running_count should return number of running jobs."""
        with app.app_context():
            job = _create_job(db, status='running')
            assert queue.get_running_count() == 1

    def test_get_running_count_zero(self, app, db, queue):
        """get_running_count should return 0 when no running jobs."""
        with app.app_context():
            job = _create_job(db, status='queued')
            assert queue.get_running_count() == 0

    def test_get_queued_count(self, app, db, queue):
        """get_queued_count should return number of queued jobs."""
        with app.app_context():
            job = _create_job(db, status='queued')
            assert queue.get_queued_count() == 1

    def test_mark_running(self, app, db, queue):
        """mark_running should set status='running' and started_at."""
        with app.app_context():
            job = _create_job(db, status='queued')
            queue.mark_running(job.id)

            updated = ScanJob.query.get(job.id)
            assert updated.status == 'running'
            assert updated.started_at is not None

    def test_mark_completed(self, app, db, queue):
        """mark_completed should set status='completed' and completed_at."""
        with app.app_context():
            job = _create_job(db, status='running')
            queue.mark_completed(job.id, exit_code=0)

            updated = ScanJob.query.get(job.id)
            assert updated.status == 'completed'
            assert updated.completed_at is not None
            assert updated.exit_code == 0

    def test_mark_completed_with_exit_code(self, app, db, queue):
        """mark_completed should store the exit_code."""
        with app.app_context():
            job = _create_job(db, status='running')
            queue.mark_completed(job.id, exit_code=1)

            updated = ScanJob.query.get(job.id)
            assert updated.exit_code == 1

    def test_mark_failed(self, app, db, queue):
        """mark_failed should set status='failed' and error_message."""
        with app.app_context():
            job = _create_job(db, status='running')
            queue.mark_failed(job.id, 'Something went wrong')

            updated = ScanJob.query.get(job.id)
            assert updated.status == 'failed'
            assert updated.completed_at is not None
            assert updated.error_message == 'Something went wrong'

    def test_mark_timeout(self, app, db, queue):
        """mark_timeout should set status='timeout' and error_message."""
        with app.app_context():
            job = _create_job(db, status='running')
            queue.mark_timeout(job.id)

            updated = ScanJob.query.get(job.id)
            assert updated.status == 'timeout'
            assert updated.completed_at is not None
            assert 'timed out' in updated.error_message.lower()

    def test_increment_retry_requeues(self, app, db, queue):
        """increment_retry should re-queue job if under max_retries."""
        with app.app_context():
            job = _create_job(db, status='failed', max_retries=2)
            job.status = 'failed'
            db.session.commit()

            result = queue.increment_retry(job.id)
            assert result is True

            updated = ScanJob.query.get(job.id)
            assert updated.status == 'queued'
            assert updated.retry_count == 1
            assert updated.started_at is None
            assert updated.completed_at is None

    def test_increment_retry_exceeds_max(self, app, db, queue):
        """increment_retry should mark failed when max_retries exceeded."""
        with app.app_context():
            job = _create_job(db, status='failed', max_retries=2)
            job.retry_count = 2  # already at max
            job.status = 'failed'
            db.session.commit()

            result = queue.increment_retry(job.id)
            assert result is False

            updated = ScanJob.query.get(job.id)
            assert updated.status == 'failed'
            assert 'max retries exceeded' in (updated.error_message or '')

    def test_increment_retry_nonexistent(self, app, db, queue):
        """increment_retry should return False for nonexistent job."""
        with app.app_context():
            result = queue.increment_retry(99999)
            assert result is False
