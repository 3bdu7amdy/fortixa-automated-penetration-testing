"""Authentication routes - login, register, logout."""
from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from app.services.auth_service import AuthService
from app.utils.decorators import login_required

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
auth_service = AuthService()


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'

        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('auth/login.html')

        result = auth_service.login(username, password, remember)
        if result['success']:
            flash(f'Welcome back, {result["user"].username}!', 'success')
            next_page = request.args.get('next', url_for('dashboard.index'))
            return redirect(next_page)
        else:
            for error in result['errors']:
                flash(error, 'error')

    return render_template('auth/login.html')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('auth/register.html')

        result = auth_service.register(username, email, password)
        if result['success']:
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('auth.login'))
        else:
            for error in result['errors']:
                flash(error, 'error')

    return render_template('auth/register.html')


@auth_bp.route('/logout')
@login_required
def logout():
    """Handle user logout."""
    user_id = session.get('user_id')
    auth_service.logout(user_id)
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password_request():
    """Handle password reset request."""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        result = auth_service.request_password_reset(email)
        flash('If the email exists, a reset link will be sent.', 'info')
        return redirect(url_for('auth.login'))

    return render_template('auth/reset_password.html')
