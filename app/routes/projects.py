"""Project routes - CRUD for projects and targets."""
from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from app.extensions import db
from app.services.project_service import ProjectService
from app.models.user import User
from app.models.target import Target
from app.utils.validators import validate_target_value
from app.utils.decorators import login_required

projects_bp = Blueprint('projects', __name__, url_prefix='/projects')
project_service = ProjectService()


@projects_bp.route('/')
@login_required
def list_projects():
    """List all projects for the current user."""
    user_id = session['user_id']
    projects = project_service.list_projects(user_id)
    return render_template('projects/list.html', projects=projects)


@projects_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_project():
    """Create a new project."""
    if request.method == 'POST':
        result = project_service.create(
            user_id=session['user_id'],
            name=request.form.get('name', ''),
            description=request.form.get('description', '')
        )
        if result['success']:
            flash('Project created successfully!', 'success')
            return redirect(url_for('projects.view_project', project_id=result['project'].id))
        for error in result['errors']:
            flash(error, 'error')

    return render_template('projects/create.html')


@projects_bp.route('/<int:project_id>')
@login_required
def view_project(project_id):
    """View a project's details."""
    result = project_service.get_by_id(project_id, session['user_id'])
    if not result['success']:
        flash(result['errors'][0], 'error')
        return redirect(url_for('projects.list_projects'))

    project = result['project']
    targets = Target.query.filter_by(project_id=project_id).all()
    findings_summary = project.get_findings_by_severity()

    return render_template('projects/view.html',
                           project=project,
                           targets=targets,
                           findings_summary=findings_summary)


@projects_bp.route('/<int:project_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    """Edit a project."""
    result = project_service.get_by_id(project_id, session['user_id'])
    if not result['success']:
        flash(result['errors'][0], 'error')
        return redirect(url_for('projects.list_projects'))

    if request.method == 'POST':
        result = project_service.update(
            project_id=project_id,
            user_id=session['user_id'],
            name=request.form.get('name', ''),
            description=request.form.get('description', ''),
            status=request.form.get('status', '')
        )
        if result['success']:
            flash('Project updated!', 'success')
            return redirect(url_for('projects.view_project', project_id=project_id))
        for error in result['errors']:
            flash(error, 'error')

    return render_template('projects/edit.html', project=result['project'])


@projects_bp.route('/<int:project_id>/delete', methods=['POST'])
@login_required
def delete_project(project_id):
    """Delete a project."""
    result = project_service.delete(project_id, session['user_id'])
    if result['success']:
        flash('Project deleted.', 'success')
    else:
        flash(result['errors'][0], 'error')
    return redirect(url_for('projects.list_projects'))


@projects_bp.route('/<int:project_id>/targets/add', methods=['POST'])
@login_required
def add_target(project_id):
    """Add a target to a project."""
    result = project_service.get_by_id(project_id, session['user_id'])
    if not result['success']:
        flash(result['errors'][0], 'error')
        return redirect(url_for('projects.list_projects'))

    value = request.form.get('value', '').strip()
    target_type = request.form.get('type', 'domain')

    is_valid, message = validate_target_value(value, target_type)
    if not is_valid:
        flash(message, 'error')
        return redirect(url_for('projects.view_project', project_id=project_id))

    existing = Target.query.filter_by(value=value, project_id=project_id).first()
    if existing:
        flash('Target already exists in this project.', 'error')
        return redirect(url_for('projects.view_project', project_id=project_id))

    target = Target(
        project_id=project_id,
        value=value,
        type=target_type,
        description=request.form.get('description', ''),
        is_approved=True
    )
    target.save()
    flash('Target added successfully!', 'success')
    return redirect(url_for('projects.view_project', project_id=project_id))


@projects_bp.route('/<int:project_id>/targets/<int:target_id>/edit', methods=['POST'])
@login_required
def edit_target(project_id, target_id):
    """Edit a target's value."""
    target = db.session.get(Target, target_id)
    if not target or target.project_id != project_id:
        flash('Target not found.', 'error')
        return redirect(url_for('projects.view_project', project_id=project_id))

    # Verify project ownership
    result = project_service.get_by_id(project_id, session['user_id'])
    if not result['success']:
        flash('Access denied.', 'error')
        return redirect(url_for('projects.list_projects'))

    new_value = request.form.get('value', '').strip()
    target_type = request.form.get('type', target.type)

    is_valid, message = validate_target_value(new_value, target_type)
    if not is_valid:
        flash(message, 'error')
        return redirect(url_for('projects.view_project', project_id=project_id))

    target.value = new_value
    target.type = target_type
    target.save()
    flash('Target updated.', 'success')
    return redirect(url_for('projects.view_project', project_id=project_id))


@projects_bp.route('/<int:project_id>/targets/<int:target_id>/delete', methods=['POST'])
@login_required
def delete_target(project_id, target_id):
    """Delete a target from a project."""
    target = db.session.get(Target, target_id)
    if not target or target.project_id != project_id:
        flash('Target not found.', 'error')
        return redirect(url_for('projects.view_project', project_id=project_id))

    # Verify project ownership
    result = project_service.get_by_id(project_id, session['user_id'])
    if not result['success']:
        flash('Access denied.', 'error')
        return redirect(url_for('projects.list_projects'))

    db.session.delete(target)
    db.session.commit()
    flash('Target deleted.', 'success')
    return redirect(url_for('projects.view_project', project_id=project_id))


@projects_bp.route('/<int:project_id>/targets/<int:target_id>/approve', methods=['POST'])
@login_required
def approve_target(project_id, target_id):
    """Approve a target for scanning (admin only)."""
    user = db.session.get(User, session['user_id'])
    if not user or not user.is_admin:
        flash('Admin access required.', 'error')
        return redirect(url_for('projects.view_project', project_id=project_id))

    target = db.session.get(Target, target_id)
    if target and target.project_id == project_id:
        target.is_approved = True
        target.save()
        flash('Target approved for scanning.', 'success')
    return redirect(url_for('projects.view_project', project_id=project_id))
