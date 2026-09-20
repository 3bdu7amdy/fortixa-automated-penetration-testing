"""ExecutionLog model - detailed logs of tool execution."""
from app.extensions import db
from app.models.base import BaseModel


class ExecutionLog(BaseModel):
    """ExecutionLog model.

    Stores detailed logs of what happened during tool execution.
    This is the audit trail for scan jobs.
    """
    __tablename__ = 'execution_logs'

    scan_job_id = db.Column(db.Integer, db.ForeignKey('scan_jobs.id'), nullable=False, index=True)
    level = db.Column(db.String(10), nullable=False, index=True)  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    message = db.Column(db.Text, nullable=False)
    details = db.Column(db.Text, nullable=True)  # JSON

    def __repr__(self):
        return f'<ExecutionLog [{self.level}] {self.message[:50]}>'
