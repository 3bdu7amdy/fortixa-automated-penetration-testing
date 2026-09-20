"""Configuration routes - CRUD for scan configurations and tool status."""
import json
import logging
from flask import Blueprint, render_template, redirect, url_for, request, flash, session, jsonify
from app.services.configuration_service import ConfigurationService
from app.plugins.registry import tool_registry
from app.utils.decorators import login_required

logger = logging.getLogger(__name__)

configs_bp = Blueprint('configs', __name__, url_prefix='/configurations')
config_service = ConfigurationService()


@configs_bp.route('/')
@login_required
def list_configs():
    """List all configurations, optionally filtered by type."""
    config_type = request.args.get('type', '')
    user_id = session['user_id']
    configs = config_service.list_configs(user_id=user_id, config_type=config_type or None)
    return render_template('configurations/list.html', configs=configs, current_type=config_type)


@configs_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_config():
    """Create a new scan configuration."""
    if request.method == 'POST':
        user_id = session['user_id']
        name = request.form.get('name', '').strip()
        config_type = request.form.get('config_type', 'custom')

        # Build tool_settings from form data
        tool_settings = {}
        for tool_name in tool_registry.SUPPORTED_TOOLS:
            enabled = request.form.get(f'tool_{tool_name}_enabled') == 'on'
            if enabled:
                flags_raw = request.form.get(f'tool_{tool_name}_flags', '').strip()
                flags = [f.strip() for f in flags_raw.split() if f.strip()] if flags_raw else []
                timeout_raw = request.form.get(f'tool_{tool_name}_timeout', '300').strip()
                try:
                    timeout = int(timeout_raw)
                except ValueError:
                    timeout = 300
                tool_settings[tool_name] = {
                    'enabled': True,
                    'flags': flags,
                    'timeout': timeout,
                }

        if not tool_settings:
            flash('You must enable at least one tool.', 'error')
            return redirect(url_for('configs.create_config'))

        result = config_service.create(
            user_id=user_id,
            name=name,
            config_type=config_type,
            tool_settings=tool_settings,
        )
        if result['success']:
            flash('Configuration created successfully!', 'success')
            return redirect(url_for('configs.view_config', config_id=result['configuration'].id))
        for error in result['errors']:
            flash(error, 'error')

    # GET – show the creation form
    categories = tool_registry.get_categories()
    return render_template('configurations/create.html',
                           tools=tool_registry.SUPPORTED_TOOLS,
                           categories=categories,
                           tool_registry=tool_registry)


@configs_bp.route('/<int:config_id>')
@login_required
def view_config(config_id):
    """View a single configuration."""
    result = config_service.get_by_id(config_id, session['user_id'])
    if not result['success']:
        flash(result['errors'][0], 'error')
        return redirect(url_for('configs.list_configs'))

    config = result['configuration']
    tool_settings = config.get_tool_settings()
    enabled_tools = config.get_enabled_tools()

    return render_template('configurations/view.html',
                           config=config,
                           tool_settings=tool_settings,
                           enabled_tools=enabled_tools,
                           tool_registry=tool_registry)


@configs_bp.route('/<int:config_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_config(config_id):
    """Edit an existing (non-default) configuration."""
    result = config_service.get_by_id(config_id, session['user_id'])
    if not result['success']:
        flash(result['errors'][0], 'error')
        return redirect(url_for('configs.list_configs'))

    config = result['configuration']

    if config.is_default:
        flash('Default configurations cannot be edited. Clone it instead.', 'error')
        return redirect(url_for('configs.view_config', config_id=config_id))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        config_type = request.form.get('config_type', config.config_type)

        # Build tool_settings from form data
        tool_settings = {}
        for tool_name in tool_registry.SUPPORTED_TOOLS:
            enabled = request.form.get(f'tool_{tool_name}_enabled') == 'on'
            if enabled:
                flags_raw = request.form.get(f'tool_{tool_name}_flags', '').strip()
                flags = [f.strip() for f in flags_raw.split() if f.strip()] if flags_raw else []
                timeout_raw = request.form.get(f'tool_{tool_name}_timeout', '300').strip()
                try:
                    timeout = int(timeout_raw)
                except ValueError:
                    timeout = 300
                tool_settings[tool_name] = {
                    'enabled': True,
                    'flags': flags,
                    'timeout': timeout,
                }

        if not tool_settings:
            flash('You must enable at least one tool.', 'error')
            return redirect(url_for('configs.edit_config', config_id=config_id))

        result = config_service.update(
            config_id=config_id,
            user_id=session['user_id'],
            name=name,
            config_type=config_type,
            tool_settings=tool_settings,
        )
        if result['success']:
            flash('Configuration updated!', 'success')
            return redirect(url_for('configs.view_config', config_id=config_id))
        for error in result['errors']:
            flash(error, 'error')

    # GET – show edit form with pre-filled data
    tool_settings = config.get_tool_settings()
    categories = tool_registry.get_categories()
    return render_template('configurations/edit.html',
                           config=config,
                           tool_settings=tool_settings,
                           tools=tool_registry.SUPPORTED_TOOLS,
                           categories=categories,
                           tool_registry=tool_registry)


@configs_bp.route('/<int:config_id>/clone', methods=['POST'])
@login_required
def clone_config(config_id):
    """Clone an existing configuration."""
    new_name = request.form.get('new_name', '').strip()
    if not new_name:
        new_name = 'Cloned Config'

    result = config_service.clone(
        config_id=config_id,
        user_id=session['user_id'],
        new_name=new_name,
    )
    if result['success']:
        flash(f"Configuration cloned as '{new_name}'.", 'success')
        return redirect(url_for('configs.view_config', config_id=result['configuration'].id))
    for error in result['errors']:
        flash(error, 'error')
    return redirect(url_for('configs.list_configs'))


@configs_bp.route('/<int:config_id>/delete', methods=['POST'])
@login_required
def delete_config(config_id):
    """Delete a (non-default) configuration."""
    result = config_service.delete(config_id, session['user_id'])
    if result['success']:
        flash('Configuration deleted.', 'success')
    else:
        for error in result['errors']:
            flash(error, 'error')
    return redirect(url_for('configs.list_configs'))


@configs_bp.route('/tools/status')
@login_required
def tools_status():
    """JSON API endpoint – returns tool installation status."""
    status = tool_registry.check_all_tools()
    result = {}
    for tool_name, info in tool_registry.SUPPORTED_TOOLS.items():
        result[tool_name] = {
            'category': info['category'],
            'description': info['description'],
            'installed': status.get(tool_name, False),
            'tool': info.get('tool', tool_name),
            'input_type': info.get('input_type', ''),
        }
    return jsonify(result)
