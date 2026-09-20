"""AI Assistant Routes - API endpoints and page rendering.

All routes are under /ai-assistant prefix.
CSRF protection is exempted for this blueprint.
"""
from flask import Blueprint, render_template, jsonify, request
from app.ai_assistant import ai_assistant_bp
from app.ai_assistant import services
from app.ai_assistant.providers import list_providers, PROVIDERS
from app.utils.decorators import login_required


# ─── Page Routes ────────────────────────────────────────────────

@ai_assistant_bp.route('/', methods=['GET'])
@login_required
def index():
    """Render the AI Assistant main page."""
    skills = services.list_skills()
    providers = list_providers()
    selected_provider = services.get_selected_provider()
    selected_model = services.get_selected_model(selected_provider)

    # Get API key status for each provider
    provider_status = []
    for p in providers:
        key = services.get_api_key(p['id'])
        provider_status.append({
            'id': p['id'],
            'name': p['name'],
            'models': p['models'],
            'default_model': p['default_model'],
            'get_key_url': p['get_key_url'],
            'key_set': bool(key),
            'masked_key': (key[:4] + '...' + key[-4:]) if key and len(key) > 8 else ('***' if key else ''),
        })

    return render_template('ai_assistant/index.html',
                           skills=skills,
                           providers=provider_status,
                           selected_provider=selected_provider,
                           selected_model=selected_model)


# ─── API Endpoints ──────────────────────────────────────────────

@ai_assistant_bp.route('/api/scan', methods=['POST'])
@login_required
def api_scan():
    """Run an AI-assisted scan on a target URL."""
    data = request.get_json(silent=True)
    if not data:
        data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({'success': False, 'error': 'No JSON data provided'}), 400

    url = (data.get('url') or '').strip()
    cookie = (data.get('cookie') or '').strip()
    custom_prompt = (data.get('prompt') or '').strip()

    if not url:
        return jsonify({'success': False, 'error': 'Target URL is required'}), 400
    if not url.startswith('http://') and not url.startswith('https://'):
        return jsonify({'success': False, 'error': 'URL must start with http:// or https://'}), 400

    try:
        result = services.run_scan(url, cookie, custom_prompt)
        if result.get('error'):
            return jsonify({
                'success': False,
                'error': result['error'],
                'target_data': result.get('target_data', ''),
            }), 200
        return jsonify({
            'success': True,
            'target_data': result.get('target_data', ''),
            'router_result': result.get('router_result', ''),
            'analyzer_result': result.get('analyzer_result', ''),
            'triage_result': result.get('triage_result', ''),
            'error': None,
        })
    except Exception as exc:
        return jsonify({'success': False, 'error': str(exc)}), 500


@ai_assistant_bp.route('/api/skills', methods=['GET'])
@login_required
def api_list_skills():
    """List all available skills."""
    skills = services.list_skills()
    return jsonify({'success': True, 'skills': skills})


@ai_assistant_bp.route('/api/skills', methods=['POST'])
@login_required
def api_add_skill():
    """Add a new skill (train the agent)."""
    data = request.get_json(silent=True)
    if not data:
        data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({'success': False, 'error': 'No JSON data provided'}), 400

    category = (data.get('category') or '').strip()
    content = (data.get('content') or '').strip()

    if not category or not content:
        return jsonify({'success': False, 'error': 'Category and content are required'}), 400

    if services.save_skill(category, content):
        return jsonify({'success': True, 'message': f'Skill "{category}" saved successfully'})
    return jsonify({'success': False, 'error': 'Failed to save skill'}), 500


@ai_assistant_bp.route('/api/skills/<category>', methods=['DELETE'])
@login_required
def api_delete_skill(category):
    """Delete a skill by category name."""
    if services.delete_skill(category):
        return jsonify({'success': True, 'message': f'Skill "{category}" deleted'})
    return jsonify({'success': False, 'error': 'Skill not found or could not be deleted'}), 404


# ─── Provider & Config Endpoints ────────────────────────────────

@ai_assistant_bp.route('/api/providers', methods=['GET'])
@login_required
def api_list_providers():
    """List all available AI providers."""
    providers = list_providers()
    # Add key status
    for p in providers:
        key = services.get_api_key(p['id'])
        p['key_set'] = bool(key)
        p['masked_key'] = (key[:4] + '...' + key[-4:]) if key and len(key) > 8 else ('***' if key else '')
        p['selected_model'] = services.get_selected_model(p['id'])

    return jsonify({
        'success': True,
        'providers': providers,
        'selected_provider': services.get_selected_provider(),
    })


@ai_assistant_bp.route('/api/config/provider', methods=['POST'])
@login_required
def api_set_provider():
    """Set the selected AI provider."""
    data = request.get_json(silent=True)
    if not data:
        data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({'success': False, 'error': 'No JSON data provided'}), 400

    provider_id = (data.get('provider_id') or '').strip()
    model = (data.get('model') or '').strip()

    if provider_id not in PROVIDERS:
        return jsonify({'success': False, 'error': f'Unknown provider: {provider_id}'}), 400

    services.set_selected_provider(provider_id)
    if model:
        services.set_selected_model(provider_id, model)

    return jsonify({'success': True, 'message': f'Provider set to {PROVIDERS[provider_id]["name"]}'})


@ai_assistant_bp.route('/api/config/api-key', methods=['POST'])
@login_required
def api_set_api_key():
    """Save an API key for a specific provider."""
    data = request.get_json(silent=True)
    if not data:
        data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({'success': False, 'error': 'No JSON data provided'}), 400

    provider_id = (data.get('provider_id') or '').strip()
    api_key = (data.get('api_key') or '').strip()

    if not provider_id or not api_key:
        return jsonify({'success': False, 'error': 'Provider ID and API key are required'}), 400

    if provider_id not in PROVIDERS:
        return jsonify({'success': False, 'error': f'Unknown provider: {provider_id}'}), 400

    if services.set_api_key(provider_id, api_key):
        return jsonify({'success': True, 'message': f'API key saved for {PROVIDERS[provider_id]["name"]}'})
    return jsonify({'success': False, 'error': 'Failed to save API key'}), 500


@ai_assistant_bp.route('/api/save-results', methods=['POST'])
@login_required
def api_save_results():
    """Save AI analysis results to a file on disk."""
    data = request.get_json(silent=True)
    if not data:
        data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({'success': False, 'error': 'No JSON data provided'}), 400

    results_text = (data.get('results') or '').strip()
    if not results_text:
        return jsonify({'success': False, 'error': 'No results to save'}), 400

    import os
    from datetime import datetime

    # Save to output directory
    output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'output', 'ai_reports')
    os.makedirs(output_dir, exist_ok=True)

    filename = f'ai_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
    filepath = os.path.join(output_dir, filename)

    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(results_text)
        return jsonify({
            'success': True,
            'filepath': filepath,
            'filename': filename,
            'message': f'Report saved as {filename}'
        })
    except Exception as exc:
        return jsonify({'success': False, 'error': str(exc)}), 500


@ai_assistant_bp.route('/api/reports', methods=['GET'])
@login_required
def api_list_reports():
    """List all saved AI reports."""
    import os
    output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'output', 'ai_reports')
    reports = []
    if os.path.exists(output_dir):
        for filename in sorted(os.listdir(output_dir), reverse=True):
            if filename.endswith('.txt'):
                filepath = os.path.join(output_dir, filename)
                reports.append({
                    'id': filename.replace('.txt', ''),
                    'filename': filename,
                    'size': os.path.getsize(filepath),
                    'date': os.path.getmtime(filepath),
                })
    return jsonify({'success': True, 'reports': reports})


@ai_assistant_bp.route('/api/reports/<report_id>', methods=['GET'])
@login_required
def api_get_report(report_id):
    """Get a saved AI report content."""
    import os
    # Sanitize report_id
    safe_id = ''.join(c for c in report_id if c.isalnum() or c in '_-')
    filename = f'{safe_id}.txt'
    output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'output', 'ai_reports')
    filepath = os.path.join(output_dir, filename)

    if not os.path.exists(filepath):
        return jsonify({'success': False, 'error': 'Report not found'}), 404

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        return jsonify({'success': True, 'content': content, 'filename': filename})
    except Exception as exc:
        return jsonify({'success': False, 'error': str(exc)}), 500


@ai_assistant_bp.route('/api/reports/<report_id>/download', methods=['GET'])
@login_required
def api_download_report(report_id):
    """Download a saved AI report."""
    import os
    from flask import send_file
    safe_id = ''.join(c for c in report_id if c.isalnum() or c in '_-')
    filename = f'{safe_id}.txt'
    output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'output', 'ai_reports')
    filepath = os.path.join(output_dir, filename)

    if not os.path.exists(filepath):
        return 'Report not found', 404

    return send_file(filepath, as_attachment=True, download_name=filename)


@ai_assistant_bp.route('/api/reports/<report_id>', methods=['DELETE'])
@login_required
def api_delete_report(report_id):
    """Delete a saved AI report."""
    import os
    safe_id = ''.join(c for c in report_id if c.isalnum() or c in '_-')
    filename = f'{safe_id}.txt'
    output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'output', 'ai_reports')
    filepath = os.path.join(output_dir, filename)

    if not os.path.exists(filepath):
        return jsonify({'success': False, 'error': 'Report not found'}), 404

    try:
        os.remove(filepath)
        return jsonify({'success': True, 'message': 'Report deleted'})
    except Exception as exc:
        return jsonify({'success': False, 'error': str(exc)}), 500


@ai_assistant_bp.route('/api/status', methods=['GET'])
@login_required
def api_status():
    """Check if the AI Assistant is configured and ready."""
    selected = services.get_selected_provider()
    api_key = services.get_api_key(selected)
    skills = services.list_skills()
    provider_name = PROVIDERS.get(selected, {}).get('name', selected)

    return jsonify({
        'success': True,
        'selected_provider': selected,
        'provider_name': provider_name,
        'gemini_configured': bool(api_key),
        'skills_count': len(skills),
        'skills': [s['name'] for s in skills],
    })
