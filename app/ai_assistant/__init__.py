"""AI Assistant Module - Self-contained AI-powered security analysis."""
from flask import Blueprint

ai_assistant_bp = Blueprint('ai_assistant', __name__,
                            url_prefix='/ai-assistant',
                            template_folder='templates',
                            static_folder='static')

from app.ai_assistant import routes  # noqa: E402,F401
