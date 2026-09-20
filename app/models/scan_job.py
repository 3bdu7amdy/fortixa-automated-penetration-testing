"""ScanJob model - a single tool execution within a scan."""
from app.extensions import db
from app.models.base import BaseModel


class ScanJob(BaseModel):
    """ScanJob model.

    Each scan is composed of multiple jobs - one per tool.
    Tracks execution details including command, output paths, and retry info.
    """
    __tablename__ = 'scan_jobs'

    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False, index=True)
    tool_name = db.Column(db.String(50), nullable=False, index=True)
    status = db.Column(db.String(20), nullable=False, default='queued', index=True)
    command = db.Column(db.Text, nullable=False)
    tool_options = db.Column(db.Text, nullable=True)  # JSON string with tool-specific options
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    exit_code = db.Column(db.Integer, nullable=True)
    stdout_path = db.Column(db.String(512), nullable=True)
    stderr_path = db.Column(db.String(512), nullable=True)
    output_dir = db.Column(db.String(512), nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    retry_count = db.Column(db.Integer, nullable=False, default=0)
    max_retries = db.Column(db.Integer, nullable=False, default=1)
    timeout_seconds = db.Column(db.Integer, nullable=False, default=600)

    # Relationships
    findings = db.relationship('Finding', backref='scan_job', lazy='dynamic')
    tool_outputs = db.relationship('ToolOutput', backref='scan_job', lazy='dynamic')
    execution_logs = db.relationship('ExecutionLog', backref='scan_job', lazy='dynamic')

    @property
    def duration_seconds(self):
        """Calculate job duration in seconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    def get_tool_options(self):
        """Parse tool_options JSON string into a dict."""
        if self.tool_options:
            import json
            try:
                return json.loads(self.tool_options)
            except (json.JSONDecodeError, TypeError):
                pass
        return {}

    def __repr__(self):
        return f'<ScanJob {self.tool_name} [{self.status}]>'
