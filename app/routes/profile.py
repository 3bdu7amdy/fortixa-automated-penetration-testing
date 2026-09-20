"""Profile routes - user profile management."""
from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from app.extensions import db
from app.models.user import User
from app.utils.decorators import login_required

profile_bp = Blueprint('profile', __name__, url_prefix='/profile')


@profile_bp.route('/')
@login_required
def view_profile():
    """View user profile."""
    user = db.session.get(User, session['user_id'])
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('auth.login'))
    return render_template('profile/view.html', profile_user=user)


@profile_bp.route('/update', methods=['POST'])
@login_required
def update_profile():
    """Update username and email."""
    user = db.session.get(User, session['user_id'])
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('auth.login'))

    new_username = request.form.get('username', '').strip()
    new_email = request.form.get('email', '').strip()

    errors = []
    if not new_username or len(new_username) < 3:
        errors.append('Username must be at least 3 characters')
    if not new_email or '@' not in new_email:
        errors.append('Valid email address is required')

    # Check uniqueness (excluding current user)
    existing_user = User.query.filter(User.username == new_username, User.id != user.id).first()
    if existing_user:
        errors.append('Username already taken')
    existing_email = User.query.filter(User.email == new_email, User.id != user.id).first()
    if existing_email:
        errors.append('Email already registered')

    if errors:
        for error in errors:
            flash(error, 'error')
        return redirect(url_for('profile.view_profile'))

    user.username = new_username
    user.email = new_email
    user.save()
    flash('Profile updated successfully!', 'success')
    return redirect(url_for('profile.view_profile'))


@profile_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password - requires old password."""
    user = db.session.get(User, session['user_id'])
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('auth.login'))

    old_password = request.form.get('old_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not user.verify_password(old_password):
        flash('Current password is incorrect.', 'error')
        return redirect(url_for('profile.view_profile'))

    if not new_password or len(new_password) < 8:
        flash('New password must be at least 8 characters.', 'error')
        return redirect(url_for('profile.view_profile'))

    if new_password != confirm_password:
        flash('New passwords do not match.', 'error')
        return redirect(url_for('profile.view_profile'))

    user.password = new_password
    user.save()
    flash('Password changed successfully!', 'success')
    return redirect(url_for('profile.view_profile'))
