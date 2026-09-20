"""Pentest AI Platform - Flask Application Factory."""
import json
import os
from flask import Flask
from app.extensions import db, login_manager, csrf


def create_app(config_name=None):
    """Create and configure the Flask application.

    Args:
        config_name: Configuration name ('development', 'testing', 'production').
                     Defaults to FLASK_ENV environment variable or 'development'.

    Returns:
        Configured Flask application instance.
    """
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')

    app = Flask(__name__)
    app.config.from_object(get_config(config_name))

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    # Configure login manager
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'

    # Register blueprints
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.projects import projects_bp
    from app.routes.scans import scans_bp
    from app.routes.api import api_bp
    from app.routes.configurations import configs_bp
    from app.routes.engine import engine_bp
    from app.routes.ai import ai_bp
    from app.routes.reports import reports_bp
    from app.routes.profile import profile_bp
    from app.ai_assistant import ai_assistant_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(projects_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(configs_bp)
    app.register_blueprint(engine_bp)
    app.register_blueprint(ai_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(ai_assistant_bp)

    # ─── Exempt AI Assistant routes from CSRF protection ────────
    # The AI Assistant accepts raw security payloads (e.g., <script>
    # tags, SQL injection strings) via JSON APIs.
    for endpoint, view_func in list(app.view_functions.items()):
        if endpoint.startswith('ai_assistant.'):
            csrf.exempt(view_func)

    # Register template filters
    @app.template_filter('from_json')
    def from_json_filter(value):
        """Parse a JSON string into a Python object."""
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return {}

    # Apply security headers middleware
    if app.config.get('SECURITY_HEADERS_ENABLED', True):
        from app.middleware.security import add_security_headers
        app.after_request(add_security_headers)

    # Initialize rate limiter
    from app.utils.rate_limiter import get_rate_limiter
    app.rate_limiter = get_rate_limiter()

    # Register error handlers (built-in HTTP errors)
    register_error_handlers(app)

    # Register custom error handlers for application exceptions
    from app.utils.error_handlers import register_custom_error_handlers
    register_custom_error_handlers(app)

    # Setup logging
    from app.utils.logger import setup_logging
    setup_logging(app)

    # Create database tables
    with app.app_context():
        from app.models import user, project, target, scan, scan_job, finding, tool_output, report, configuration, execution_log, ai_analysis_result, notification, session as session_model, password_reset_token
        db.create_all()

        # Apply schema migrations for existing databases
        _apply_migrations(app, db)

        # Create default configurations
        from app.models.configuration import Configuration
        Configuration.create_default_configs()

        # Create default admin user if no users exist
        from app.models.user import User
        if User.query.count() == 0:
            admin_user = User(
                username='admin',
                email='admin@pentest.local',
                role='admin',
                is_active=True
            )
            admin_user.password = 'Admin@123456'
            admin_user.save()
            app.logger.info('Default admin account created — username: admin / password: Admin@123456')

    # Start the execution engine worker (not in testing mode)
    if config_name != 'testing':
        from app.engine import start_worker
        start_worker(app)

    return app


def get_config(config_name):
    """Get configuration class by name."""
    from app.config import config_by_name
    return config_by_name.get(config_name, config_by_name['development'])


def register_error_handlers(app):
    """Register centralized error handlers."""
    from flask import render_template

    @app.errorhandler(400)
    def bad_request(e):
        return render_template('errors/400.html'), 400

    @app.errorhandler(401)
    def unauthorized(e):
        return render_template('errors/401.html'), 401

    @app.errorhandler(403)
    def forbidden(e):
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(e):
        return render_template('errors/500.html'), 500


def _apply_migrations(app, db):
    """Apply incremental schema migrations for existing databases.

    SQLite doesn't support ALTER TABLE ADD COLUMN in all cases, but
    for simple nullable columns it works fine. This function checks
    if each migration is needed and applies it idempotently.
    """
    migrations_applied = []

    # Migration 1: Add tool_options column to scan_jobs table
    try:
        result = db.session.execute(db.text("PRAGMA table_info(scan_jobs)"))
        columns = [row[1] for row in result]
        if 'tool_options' not in columns:
            db.session.execute(db.text(
                "ALTER TABLE scan_jobs ADD COLUMN tool_options TEXT"
            ))
            db.session.commit()
            migrations_applied.append('scan_jobs.tool_options')
    except Exception as exc:
        app.logger.warning(f"Migration scan_jobs.tool_options failed: {exc}")
        db.session.rollback()

    # Migration 2: Add manual_target columns to scans table
    try:
        result = db.session.execute(db.text("PRAGMA table_info(scans)"))
        columns = [row[1] for row in result]
        if 'manual_target' not in columns:
            db.session.execute(db.text(
                "ALTER TABLE scans ADD COLUMN manual_target VARCHAR(255)"
            ))
            db.session.commit()
            migrations_applied.append('scans.manual_target')
        if 'manual_target_type' not in columns:
            db.session.execute(db.text(
                "ALTER TABLE scans ADD COLUMN manual_target_type VARCHAR(20)"
            ))
            db.session.commit()
            migrations_applied.append('scans.manual_target_type')
    except Exception as exc:
        app.logger.warning(f"Migration scans.manual_target* failed: {exc}")
        db.session.rollback()

    # Migration 3: Add vuln_category column to findings table
    try:
        result = db.session.execute(db.text("PRAGMA table_info(findings)"))
        columns = [row[1] for row in result]
        if 'vuln_category' not in columns:
            db.session.execute(db.text(
                "ALTER TABLE findings ADD COLUMN vuln_category VARCHAR(80)"
            ))
            db.session.commit()
            migrations_applied.append('findings.vuln_category')
    except Exception as exc:
        app.logger.warning(f"Migration findings.vuln_category failed: {exc}")
        db.session.rollback()

    # Migration 4: Add pipeline-related columns to scans table
    try:
        result = db.session.execute(db.text("PRAGMA table_info(scans)"))
        columns = [row[1] for row in result]
        for col_def in [
            ('pipeline_mode', 'BOOLEAN DEFAULT 0'),
            ('current_phase', 'INTEGER DEFAULT 0'),
            ('pipeline_scan_id', 'INTEGER'),
        ]:
            if col_def[0] not in columns:
                db.session.execute(db.text(
                    f"ALTER TABLE scans ADD COLUMN {col_def[0]} {col_def[1]}"
                ))
                db.session.commit()
                migrations_applied.append(f'scans.{col_def[0]}')
    except Exception as exc:
        app.logger.warning(f"Migration scans.pipeline* failed: {exc}")
        db.session.rollback()

    if migrations_applied:
        app.logger.info(f"Applied DB migrations: {', '.join(migrations_applied)}")
