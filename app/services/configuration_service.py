"""Configuration service - handles scan configuration business logic."""
import json
import logging
from app.extensions import db
from app.models.configuration import Configuration

logger = logging.getLogger(__name__)


class ConfigurationService:
    """Handles all configuration-related business logic."""

    def create(self, user_id, name, config_type, tool_settings, project_id=None):
        """Create a new scan configuration."""
        errors = []
        if not name or len(name.strip()) < 3:
            errors.append('Configuration name must be at least 3 characters')
        if config_type not in ['recon', 'vuln_scan', 'full', 'custom']:
            errors.append(f'Invalid configuration type: {config_type}')

        if isinstance(tool_settings, str):
            try:
                tool_settings = json.loads(tool_settings)
            except json.JSONDecodeError:
                errors.append('Invalid tool settings JSON')
                return {'success': False, 'errors': errors}

        if errors:
            return {'success': False, 'errors': errors}

        config = Configuration(
            name=name.strip(),
            config_type=config_type,
            tool_settings=json.dumps(tool_settings, indent=2),
            is_default=False,
            project_id=project_id
        )
        config.save()
        logger.info(f"Configuration '{name}' created by user {user_id}")
        return {'success': True, 'configuration': config}

    def get_by_id(self, config_id, user_id=None):
        """Get a configuration by ID."""
        config = db.session.get(Configuration, config_id)
        if not config:
            return {'success': False, 'errors': ['Configuration not found']}
        if config.is_default:
            return {'success': True, 'configuration': config}
        if config.project_id:
            from app.models.project import Project
            project = Project.query.filter_by(id=config.project_id, owner_id=user_id).first()
            if not project:
                return {'success': False, 'errors': ['Configuration not found']}
        return {'success': True, 'configuration': config}

    def list_configs(self, user_id=None, project_id=None, config_type=None):
        """List available configurations."""
        query = Configuration.query
        if project_id:
            query = query.filter(
                db.or_(Configuration.project_id == project_id, Configuration.is_default == True)
            )
        if config_type:
            query = query.filter_by(config_type=config_type)
        return query.order_by(Configuration.is_default.desc(), Configuration.name).all()

    def update(self, config_id, user_id, **kwargs):
        """Update a configuration."""
        result = self.get_by_id(config_id, user_id)
        if not result['success']:
            return result
        config = result['configuration']
        if config.is_default:
            return {'success': False, 'errors': ['Cannot modify default configurations']}

        if 'name' in kwargs:
            config.name = kwargs['name'].strip()
        if 'config_type' in kwargs:
            config.config_type = kwargs['config_type']
        if 'tool_settings' in kwargs:
            if isinstance(kwargs['tool_settings'], str):
                config.tool_settings = kwargs['tool_settings']
            else:
                config.tool_settings = json.dumps(kwargs['tool_settings'], indent=2)
        config.save()
        return {'success': True, 'configuration': config}

    def delete(self, config_id, user_id):
        """Delete a configuration."""
        result = self.get_by_id(config_id, user_id)
        if not result['success']:
            return result
        config = result['configuration']
        if config.is_default:
            return {'success': False, 'errors': ['Cannot delete default configurations']}
        config.delete()
        return {'success': True}

    def clone(self, config_id, user_id, new_name, project_id=None):
        """Clone a configuration."""
        result = self.get_by_id(config_id, user_id)
        if not result['success']:
            return result
        original = result['configuration']
        new_config = Configuration(
            name=new_name.strip(),
            config_type=original.config_type,
            tool_settings=original.tool_settings,
            is_default=False,
            project_id=project_id
        )
        new_config.save()
        return {'success': True, 'configuration': new_config}
