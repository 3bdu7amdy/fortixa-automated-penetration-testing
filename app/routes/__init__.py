"""Routes package."""
from app.routes.auth import auth_bp
from app.routes.dashboard import dashboard_bp
from app.routes.projects import projects_bp
from app.routes.scans import scans_bp
from app.routes.api import api_bp

__all__ = ['auth_bp', 'dashboard_bp', 'projects_bp', 'scans_bp', 'api_bp']
