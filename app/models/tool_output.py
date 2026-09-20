"""ToolOutput model - references to raw tool output files."""
from app.extensions import db
from app.models.base import BaseModel


class ToolOutput(BaseModel):
    """ToolOutput model.

    Stores structured references to tool output files. While findings
    store parsed data, ToolOutput stores references to raw, unparsed output.
    """
    __tablename__ = 'tool_outputs'

    scan_job_id = db.Column(db.Integer, db.ForeignKey('scan_jobs.id'), nullable=False, index=True)
    output_type = db.Column(db.String(30), nullable=False, index=True)
    file_path = db.Column(db.String(512), nullable=False)
    file_size = db.Column(db.Integer, nullable=True)
    record_count = db.Column(db.Integer, nullable=True)

    def __repr__(self):
        return f'<ToolOutput {self.output_type} job={self.scan_job_id}>'
