"""Project service - handles project CRUD business logic."""
import logging
from app.extensions import db
from app.models.project import Project
from app.models.user import User

logger = logging.getLogger(__name__)


class ProjectService:
    """Handles all project-related business logic."""

    def create(self, user_id, name, description=None):
        """Create a new project."""
        errors = []
        if not name or len(name.strip()) < 3:
            errors.append('Project name must be at least 3 characters')
        if errors:
            return {'success': False, 'errors': errors}

        project = Project(
            name=name.strip(),
            description=description,
            owner_id=user_id,
            status='active'
        )
        project.save()
        logger.info(f"Project '{name}' created by user {user_id}")
        return {'success': True, 'project': project}

    def get_by_id(self, project_id, user_id):
        """Get a project by ID, verifying ownership."""
        project = db.session.get(Project, project_id)
        if not project:
            return {'success': False, 'errors': ['Project not found']}
        if project.owner_id != user_id:
            return {'success': False, 'errors': ['Access denied']}
        return {'success': True, 'project': project}

    def list_projects(self, user_id, status=None):
        """List all projects for a user."""
        query = Project.query.filter_by(owner_id=user_id)
        if status:
            query = query.filter_by(status=status)
        return query.order_by(Project.updated_at.desc()).all()

    def update(self, project_id, user_id, **kwargs):
        """Update a project."""
        result = self.get_by_id(project_id, user_id)
        if not result['success']:
            return result

        project = result['project']
        if 'name' in kwargs:
            project.name = kwargs['name'].strip()
        if 'description' in kwargs:
            project.description = kwargs['description']
        if 'status' in kwargs:
            project.status = kwargs['status']
        project.save()
        logger.info(f"Project {project_id} updated by user {user_id}")
        return {'success': True, 'project': project}

    def delete(self, project_id, user_id):
        """Delete a project."""
        result = self.get_by_id(project_id, user_id)
        if not result['success']:
            return result

        result['project'].delete()
        logger.info(f"Project {project_id} deleted by user {user_id}")
        return {'success': True}
