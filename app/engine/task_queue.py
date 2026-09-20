"""SQLite-based task queue using the scan_jobs table."""
import logging
from datetime import datetime, timezone
from app.extensions import db
from app.models.scan_job import ScanJob

logger = logging.getLogger(__name__)


def _utcnow():
    """Return current UTC time as a naive datetime (SQLite-compatible)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class TaskQueue:
    """SQLite-based task queue that uses the scan_jobs table.

    Provides FIFO dequeue semantics ordered by created_at and supports
    status transitions for the full job lifecycle:
    queued -> running -> completed / failed / timeout.
    """

    def enqueue(self, job_id):
        """Mark a job as 'queued' so it can be picked up by the worker.

        Args:
            job_id: Primary key of the ScanJob.

        Returns:
            True if the job was successfully enqueued, False otherwise.
        """
        job = db.session.get(ScanJob, job_id)
        if job is None:
            logger.warning(f"enqueue: job {job_id} not found.")
            return False
        job.status = 'queued'
        db.session.commit()
        logger.info(f"Job {job_id} ({job.tool_name}) enqueued.")
        return True

    def dequeue(self):
        """Get the next 'queued' job (FIFO by created_at).

        Returns:
            ScanJob instance or None if no queued jobs exist.
        """
        job = ScanJob.query.filter_by(status='queued')\
            .order_by(ScanJob.created_at.asc())\
            .first()
        return job

    def dequeue_by_scan(self, scan_id):
        """Get the next 'queued' job for a specific scan.

        Args:
            scan_id: The scan to fetch a job for.

        Returns:
            ScanJob instance or None.
        """
        job = ScanJob.query.filter_by(status='queued', scan_id=scan_id)\
            .order_by(ScanJob.created_at.asc())\
            .first()
        return job

    def get_running_count(self):
        """Return count of currently 'running' jobs."""
        return ScanJob.query.filter_by(status='running').count()

    def get_queued_count(self):
        """Return count of 'queued' jobs waiting to be processed."""
        return ScanJob.query.filter_by(status='queued').count()

    def mark_running(self, job_id):
        """Set job status='running' and record started_at.

        Args:
            job_id: Primary key of the ScanJob.
        """
        job = db.session.get(ScanJob, job_id)
        if job is None:
            logger.warning(f"mark_running: job {job_id} not found.")
            return
        job.status = 'running'
        job.started_at = _utcnow()
        db.session.commit()
        logger.info(f"Job {job_id} ({job.tool_name}) marked as running.")

    def mark_completed(self, job_id, exit_code=0):
        """Set job status='completed' and record completion time.

        Args:
            job_id: Primary key of the ScanJob.
            exit_code: Process exit code from the tool.
        """
        job = db.session.get(ScanJob, job_id)
        if job is None:
            logger.warning(f"mark_completed: job {job_id} not found.")
            return
        job.status = 'completed'
        job.completed_at = _utcnow()
        job.exit_code = exit_code
        db.session.commit()
        logger.info(f"Job {job_id} ({job.tool_name}) completed (exit={exit_code}).")

    def mark_failed(self, job_id, error_message):
        """Set job status='failed' and store the error message.

        Args:
            job_id: Primary key of the ScanJob.
            error_message: Description of the failure.
        """
        job = db.session.get(ScanJob, job_id)
        if job is None:
            logger.warning(f"mark_failed: job {job_id} not found.")
            return
        job.status = 'failed'
        job.completed_at = _utcnow()
        job.error_message = error_message
        db.session.commit()
        logger.info(f"Job {job_id} ({job.tool_name}) failed: {error_message}")

    def mark_timeout(self, job_id):
        """Set job status='timeout'.

        Args:
            job_id: Primary key of the ScanJob.
        """
        job = db.session.get(ScanJob, job_id)
        if job is None:
            logger.warning(f"mark_timeout: job {job_id} not found.")
            return
        job.status = 'timeout'
        job.completed_at = _utcnow()
        job.error_message = 'Job timed out'
        db.session.commit()
        logger.info(f"Job {job_id} ({job.tool_name}) timed out.")

    def increment_retry(self, job_id):
        """Increment retry_count and re-queue if under max_retries.

        If the job has exceeded its max_retries, it is marked as failed
        instead of being re-queued.

        Args:
            job_id: Primary key of the ScanJob.

        Returns:
            True if the job was re-queued, False if it has been marked failed
            (max retries exceeded) or not found.
        """
        job = db.session.get(ScanJob, job_id)
        if job is None:
            logger.warning(f"increment_retry: job {job_id} not found.")
            return False

        job.retry_count += 1
        if job.retry_count >= job.max_retries:
            job.status = 'failed'
            job.completed_at = _utcnow()
            job.error_message = (job.error_message or '') + ' (max retries exceeded)'
            db.session.commit()
            logger.info(
                f"Job {job_id} ({job.tool_name}) exceeded max_retries "
                f"({job.retry_count}/{job.max_retries}). Marked failed."
            )
            return False
        else:
            job.status = 'queued'
            job.started_at = None
            job.completed_at = None
            db.session.commit()
            logger.info(
                f"Job {job_id} ({job.tool_name}) retry {job.retry_count}/"
                f"{job.max_retries}. Re-queued."
            )
            return True
