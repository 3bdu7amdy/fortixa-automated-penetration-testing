"""AIAnalysisResult model - AI analysis results for findings."""
from app.extensions import db
from app.models.base import BaseModel


class AIAnalysisResult(BaseModel):
    """AIAnalysisResult model.

    Stores AI analysis results for findings including deduplication,
    severity suggestion, false positive detection, and recommendations.
    """
    __tablename__ = 'ai_analysis_results'

    finding_id = db.Column(db.Integer, db.ForeignKey('findings.id'), nullable=False, index=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False, index=True)
    analysis_type = db.Column(db.String(30), nullable=False, index=True)  # deduplication, severity_suggestion, false_positive, recommendation
    result = db.Column(db.Text, nullable=False)  # JSON
    confidence_score = db.Column(db.Float, nullable=True)
    reasoning = db.Column(db.Text, nullable=True)
    is_accepted = db.Column(db.Boolean, default=None)  # NULL=not reviewed, True/False

    scan = db.relationship('Scan', backref='ai_analyses')

    def __repr__(self):
        return f'<AIAnalysisResult {self.analysis_type} finding={self.finding_id}>'
