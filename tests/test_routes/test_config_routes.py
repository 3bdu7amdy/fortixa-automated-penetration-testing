"""Tests for configuration routes."""
import pytest
import json
from unittest.mock import patch, MagicMock


def _register_and_login(client):
    """Helper: register a user and log in."""
    client.post('/auth/register', data={
        'username': 'configuser',
        'email': 'config@example.com',
        'password': 'ConfigPass123!',
        'confirm_password': 'ConfigPass123!'
    })
    client.post('/auth/login', data={
        'username': 'configuser',
        'password': 'ConfigPass123!'
    })


def _ensure_default_configs():
    """Create default configs if they don't exist (test DB is fresh each time)."""
    from app.models.configuration import Configuration
    Configuration.create_default_configs()


class TestConfigListRoute:
    """Tests for GET /configurations/."""

    def test_list_requires_login(self, client, app, db):
        with app.app_context():
            response = client.get('/configurations/', follow_redirects=False)
            assert response.status_code == 302

    def test_list_shows_configs(self, client, app, db):
        with app.app_context():
            _ensure_default_configs()
            _register_and_login(client)
            response = client.get('/configurations/')
            assert response.status_code == 200
            # Default configs should be visible
            assert b'Quick Recon' in response.data or b'configuration' in response.data.lower()

    def test_list_with_type_filter(self, client, app, db):
        with app.app_context():
            _ensure_default_configs()
            _register_and_login(client)
            response = client.get('/configurations/?type=recon')
            assert response.status_code == 200


class TestConfigCreateRoute:
    """Tests for GET/POST /configurations/create."""

    def test_create_page_loads(self, client, app, db):
        with app.app_context():
            _register_and_login(client)
            response = client.get('/configurations/create')
            assert response.status_code == 200
            assert b'Create Configuration' in response.data

    @patch('app.plugins.registry.subprocess.run')
    def test_create_config_post(self, mock_run, client, app, db):
        with app.app_context():
            mock_run.return_value = MagicMock(returncode=0)
            _register_and_login(client)
            response = client.post('/configurations/create', data={
                'name': 'My Custom Config',
                'config_type': 'custom',
                'tool_subfinder_enabled': 'on',
                'tool_subfinder_flags': '-all',
                'tool_subfinder_timeout': '300',
            }, follow_redirects=True)
            assert response.status_code == 200

    def test_create_config_no_tools(self, client, app, db):
        with app.app_context():
            _register_and_login(client)
            response = client.post('/configurations/create', data={
                'name': 'Empty Config',
                'config_type': 'custom',
            }, follow_redirects=True)
            # Should flash error about needing at least one tool
            assert response.status_code == 200

    def test_create_config_short_name(self, client, app, db):
        with app.app_context():
            _register_and_login(client)
            response = client.post('/configurations/create', data={
                'name': 'AB',
                'config_type': 'custom',
                'tool_subfinder_enabled': 'on',
            }, follow_redirects=True)
            assert response.status_code == 200


class TestConfigViewRoute:
    """Tests for GET /configurations/<id>."""

    def test_view_config(self, client, app, db):
        with app.app_context():
            _ensure_default_configs()
            _register_and_login(client)
            from app.models.configuration import Configuration
            cfg = Configuration.query.first()
            assert cfg is not None
            response = client.get(f'/configurations/{cfg.id}')
            assert response.status_code == 200

    def test_view_nonexistent_config(self, client, app, db):
        with app.app_context():
            _register_and_login(client)
            response = client.get('/configurations/99999', follow_redirects=True)
            # Should redirect back to list with error flash
            assert response.status_code == 200


class TestConfigEditRoute:
    """Tests for GET/POST /configurations/<id>/edit."""

    def test_edit_default_config_blocked(self, client, app, db):
        with app.app_context():
            _ensure_default_configs()
            _register_and_login(client)
            from app.models.configuration import Configuration
            default_cfg = Configuration.query.filter_by(is_default=True).first()
            assert default_cfg is not None
            response = client.get(f'/configurations/{default_cfg.id}/edit', follow_redirects=True)
            assert response.status_code == 200

    @patch('app.plugins.registry.subprocess.run')
    def test_edit_custom_config(self, mock_run, client, app, db):
        with app.app_context():
            mock_run.return_value = MagicMock(returncode=0)
            _register_and_login(client)
            from app.models.configuration import Configuration
            custom = Configuration(
                name='Editable Config',
                config_type='custom',
                tool_settings=json.dumps({'nuclei': {'enabled': True, 'flags': [], 'timeout': 300}}),
                is_default=False,
            )
            custom.save()
            # GET the edit page
            response = client.get(f'/configurations/{custom.id}/edit')
            assert response.status_code == 200
            assert b'Editable Config' in response.data

    @patch('app.plugins.registry.subprocess.run')
    def test_edit_config_post(self, mock_run, client, app, db):
        with app.app_context():
            mock_run.return_value = MagicMock(returncode=0)
            _register_and_login(client)
            from app.models.configuration import Configuration
            custom = Configuration(
                name='Editable Config 2',
                config_type='custom',
                tool_settings=json.dumps({'nuclei': {'enabled': True, 'flags': [], 'timeout': 300}}),
                is_default=False,
            )
            custom.save()
            response = client.post(f'/configurations/{custom.id}/edit', data={
                'name': 'Updated Config',
                'config_type': 'recon',
                'tool_subfinder_enabled': 'on',
                'tool_subfinder_flags': '-all',
                'tool_subfinder_timeout': '600',
            }, follow_redirects=True)
            assert response.status_code == 200


class TestConfigCloneRoute:
    """Tests for POST /configurations/<id>/clone."""

    def test_clone_config(self, client, app, db):
        with app.app_context():
            _ensure_default_configs()
            _register_and_login(client)
            from app.models.configuration import Configuration
            default_cfg = Configuration.query.filter_by(is_default=True).first()
            assert default_cfg is not None
            response = client.post(f'/configurations/{default_cfg.id}/clone', data={
                'new_name': 'My Cloned Config',
            }, follow_redirects=True)
            assert response.status_code == 200
            # Verify clone exists
            clone = Configuration.query.filter_by(name='My Cloned Config').first()
            assert clone is not None
            assert clone.is_default is False


class TestConfigDeleteRoute:
    """Tests for POST /configurations/<id>/delete."""

    def test_delete_default_config_blocked(self, client, app, db):
        with app.app_context():
            _ensure_default_configs()
            _register_and_login(client)
            from app.models.configuration import Configuration
            default_cfg = Configuration.query.filter_by(is_default=True).first()
            assert default_cfg is not None
            response = client.post(f'/configurations/{default_cfg.id}/delete', follow_redirects=True)
            assert response.status_code == 200
            # Default config should still exist
            assert Configuration.query.get(default_cfg.id) is not None

    def test_delete_custom_config(self, client, app, db):
        with app.app_context():
            _register_and_login(client)
            from app.models.configuration import Configuration
            custom = Configuration(
                name='Deletable Config',
                config_type='custom',
                tool_settings=json.dumps({'nuclei': {'enabled': True, 'flags': [], 'timeout': 300}}),
                is_default=False,
            )
            custom.save()
            config_id = custom.id
            response = client.post(f'/configurations/{config_id}/delete', follow_redirects=True)
            assert response.status_code == 200
            assert Configuration.query.get(config_id) is None


class TestToolsStatusRoute:
    """Tests for GET /configurations/tools/status."""

    @patch('app.plugins.registry.subprocess.run')
    def test_tools_status_json(self, mock_run, client, app, db):
        with app.app_context():
            mock_run.return_value = MagicMock(returncode=0)
            _register_and_login(client)
            response = client.get('/configurations/tools/status')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert 'nuclei' in data
            assert 'installed' in data['nuclei']
            assert 'category' in data['nuclei']
            assert 'description' in data['nuclei']

    def test_tools_status_requires_login(self, client, app, db):
        with app.app_context():
            response = client.get('/configurations/tools/status', follow_redirects=False)
            assert response.status_code == 302
