"""API route tests - Phase 10 dashboard enhancement endpoints."""
import pytest
import json
from app.models.notification import Notification
from app.models.project import Project
from app.models.target import Target
from app.models.scan import Scan
from app.models.scan_job import ScanJob
from app.models.finding import Finding


class TestDashboardChartsAPI:
    """Tests for GET /api/dashboard/charts endpoint."""

    def test_charts_requires_login(self, client, app, db):
        with app.app_context():
            response = client.get('/api/dashboard/charts')
            assert response.status_code == 302  # redirect to login

    def test_charts_returns_json(self, authenticated_client, app, db):
        with app.app_context():
            response = authenticated_client.get('/api/dashboard/charts')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert 'severity_distribution' in data
            assert 'total_findings' in data
            assert 'active_scans' in data

    def test_charts_severity_data_structure(self, authenticated_client, app, db):
        with app.app_context():
            response = authenticated_client.get('/api/dashboard/charts')
            data = json.loads(response.data)
            severities = data['severity_distribution']
            assert len(severities) == 5
            for item in severities:
                assert 'severity' in item
                assert 'count' in item
                assert 'color' in item
            sev_names = [s['severity'] for s in severities]
            assert sev_names == ['critical', 'high', 'medium', 'low', 'info']

    def test_charts_with_findings(self, authenticated_client, app, db):
        with app.app_context():
            # Create project, target, scan, job, and finding
            from app.models.user import User
            user = User.query.filter_by(username='testuser').first()

            project = Project(name='ChartProj', owner_id=user.id)
            project.save()

            target = Target(project_id=project.id, value='chart.example.com', type='domain', is_approved=True)
            target.save()

            scan = Scan(target_id=target.id, initiated_by=user.id, name='Chart Scan',
                       scan_type='full', status='completed')
            scan.save()

            job = ScanJob(scan_id=scan.id, tool_name='nuclei', status='completed',
                         command='nuclei -u chart.example.com')
            job.save()

            finding = Finding(title='Test XSS', severity='high', project_id=project.id,
                            scan_id=scan.id, scan_job_id=job.id, target_id=target.id,
                            tool_name='nuclei', category='xss',
                            url='http://chart.example.com/xss',
                            is_false_positive=False, is_duplicate=False)
            finding.save()

            response = authenticated_client.get('/api/dashboard/charts')
            data = json.loads(response.data)
            assert data['total_findings'] >= 1
            high_items = [s for s in data['severity_distribution'] if s['severity'] == 'high']
            assert high_items[0]['count'] >= 1

    def test_charts_active_scans(self, authenticated_client, app, db):
        with app.app_context():
            from app.models.user import User
            user = User.query.filter_by(username='testuser').first()

            project = Project(name='ActiveProj', owner_id=user.id)
            project.save()

            target = Target(project_id=project.id, value='active.example.com', type='domain', is_approved=True)
            target.save()

            scan = Scan(target_id=target.id, initiated_by=user.id, name='Active Scan',
                       scan_type='recon', status='running', total_jobs=3, completed_jobs=1)
            scan.save()

            response = authenticated_client.get('/api/dashboard/charts')
            data = json.loads(response.data)
            assert len(data['active_scans']) >= 1
            active_scan = data['active_scans'][0]
            assert active_scan['name'] == 'Active Scan'
            assert active_scan['status'] == 'running'
            assert 'progress' in active_scan


class TestScanStatusAPI:
    """Tests for GET /api/scans/<id>/status endpoint."""

    def test_scan_status_requires_login(self, client, app, db):
        with app.app_context():
            response = client.get('/api/scans/1/status')
            assert response.status_code == 302

    def test_scan_status_not_found(self, authenticated_client, app, db):
        with app.app_context():
            response = authenticated_client.get('/api/scans/9999/status')
            assert response.status_code == 404

    def test_scan_status_returns_json(self, authenticated_client, app, db):
        with app.app_context():
            from app.models.user import User
            user = User.query.filter_by(username='testuser').first()

            project = Project(name='StatusProj', owner_id=user.id)
            project.save()

            target = Target(project_id=project.id, value='status.example.com', type='domain', is_approved=True)
            target.save()

            scan = Scan(target_id=target.id, initiated_by=user.id, name='Status Scan',
                       scan_type='recon', status='running', total_jobs=2, completed_jobs=0)
            scan.save()

            response = authenticated_client.get('/api/scans/' + str(scan.id) + '/status')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['scan_id'] == scan.id
            assert data['status'] == 'running'
            assert 'progress' in data
            assert 'jobs' in data
            assert 'total_jobs' in data
            assert 'completed_jobs' in data
            assert 'failed_jobs' in data


class TestNotificationReadAllAPI:
    """Tests for POST /api/notifications/read-all endpoint."""

    def test_read_all_requires_login(self, client, app, db):
        with app.app_context():
            response = client.post('/api/notifications/read-all')
            assert response.status_code == 302

    def test_read_all_marks_notifications_read(self, authenticated_client, app, db):
        with app.app_context():
            from app.models.user import User
            user = User.query.filter_by(username='testuser').first()

            # Create unread notifications
            n1 = Notification(user_id=user.id, title='Test1', message='Msg1', type='system')
            n1.save()
            n2 = Notification(user_id=user.id, title='Test2', message='Msg2', type='finding')
            n2.save()

            # Verify unread
            unread_before = Notification.query.filter_by(user_id=user.id, is_read=False).count()
            assert unread_before == 2

            # Call read-all
            response = authenticated_client.post('/api/notifications/read-all')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['success'] is True
            assert data['marked_count'] == 2

            # Verify all read
            unread_after = Notification.query.filter_by(user_id=user.id, is_read=False).count()
            assert unread_after == 0

    def test_read_all_no_unread(self, authenticated_client, app, db):
        with app.app_context():
            response = authenticated_client.post('/api/notifications/read-all')
            data = json.loads(response.data)
            assert data['success'] is True
            assert data['marked_count'] == 0


class TestNotificationCountAPI:
    """Tests for GET /api/notifications/count endpoint."""

    def test_count_requires_login(self, client, app, db):
        with app.app_context():
            response = client.get('/api/notifications/count')
            assert response.status_code == 302

    def test_count_returns_zero(self, authenticated_client, app, db):
        with app.app_context():
            response = authenticated_client.get('/api/notifications/count')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['unread_count'] == 0

    def test_count_returns_correct_number(self, authenticated_client, app, db):
        with app.app_context():
            from app.models.user import User
            user = User.query.filter_by(username='testuser').first()

            n1 = Notification(user_id=user.id, title='N1', message='M1', type='system')
            n1.save()
            n2 = Notification(user_id=user.id, title='N2', message='M2', type='warning')
            n2.save()
            # Already read
            n3 = Notification(user_id=user.id, title='N3', message='M3', type='scan_complete', is_read=True)
            n3.save()

            response = authenticated_client.get('/api/notifications/count')
            data = json.loads(response.data)
            assert data['unread_count'] == 2


class TestDashboardTemplateEnhancement:
    """Tests for enhanced dashboard template rendering."""

    def test_dashboard_has_quick_actions(self, authenticated_client, app, db):
        with app.app_context():
            response = authenticated_client.get('/dashboard')
            assert response.status_code == 200
            assert b'Quick Actions' in response.data
            assert b'New Project' in response.data
            assert b'Start Scan' in response.data
            assert b'Generate Report' in response.data

    def test_dashboard_has_severity_chart(self, authenticated_client, app, db):
        with app.app_context():
            response = authenticated_client.get('/dashboard')
            assert response.status_code == 200
            assert b'severity-chart' in response.data
            assert b'Severity Distribution' in response.data

    def test_dashboard_has_active_scans_section(self, authenticated_client, app, db):
        with app.app_context():
            response = authenticated_client.get('/dashboard')
            assert response.status_code == 200
            assert b'Active Scans' in response.data

    def test_dashboard_has_recent_scans_section(self, authenticated_client, app, db):
        with app.app_context():
            response = authenticated_client.get('/dashboard')
            assert response.status_code == 200
            # The recent scans section header always exists
            assert b'Recent Scans' in response.data


class TestScanViewEnhancement:
    """Tests for enhanced scan detail view."""

    def test_scan_view_has_running_indicator(self, authenticated_client, app, db):
        with app.app_context():
            from app.models.user import User
            user = User.query.filter_by(username='testuser').first()

            project = Project(name='ViewProj', owner_id=user.id)
            project.save()

            target = Target(project_id=project.id, value='view.example.com', type='domain', is_approved=True)
            target.save()

            scan = Scan(target_id=target.id, initiated_by=user.id, name='View Scan',
                       scan_type='recon', status='running', total_jobs=1)
            scan.save()

            response = authenticated_client.get('/scans/' + str(scan.id))
            assert response.status_code == 200
            assert b'running-dot' in response.data or b'running-indicator' in response.data

    def test_scan_view_has_progress_section(self, authenticated_client, app, db):
        with app.app_context():
            from app.models.user import User
            user = User.query.filter_by(username='testuser').first()

            project = Project(name='ProgressProj', owner_id=user.id)
            project.save()

            target = Target(project_id=project.id, value='progress.example.com', type='domain', is_approved=True)
            target.save()

            scan = Scan(target_id=target.id, initiated_by=user.id, name='Progress Scan',
                       scan_type='full', status='pending')
            scan.save()

            response = authenticated_client.get('/scans/' + str(scan.id))
            assert response.status_code == 200
            assert b'scan-detail-progress' in response.data
            assert b'data-scan-total' in response.data
            assert b'data-scan-completed' in response.data

    def test_scan_view_has_ai_analysis_button(self, authenticated_client, app, db):
        with app.app_context():
            from app.models.user import User
            user = User.query.filter_by(username='testuser').first()

            project = Project(name='AIProj', owner_id=user.id)
            project.save()

            target = Target(project_id=project.id, value='ai.example.com', type='domain', is_approved=True)
            target.save()

            scan = Scan(target_id=target.id, initiated_by=user.id, name='AI Scan',
                       scan_type='full', status='completed', total_jobs=1, completed_jobs=1)
            scan.save()

            response = authenticated_client.get('/scans/' + str(scan.id))
            assert response.status_code == 200
            assert b'Analyze with AI' in response.data


class TestBaseTemplateNotification:
    """Tests for notification bell in base template."""

    def test_authenticated_page_has_notification_bell(self, authenticated_client, app, db):
        with app.app_context():
            response = authenticated_client.get('/dashboard')
            assert response.status_code == 200
            assert b'nav-notification' in response.data
            assert b'notification-dropdown' in response.data
            assert b'notification-list' in response.data

    def test_authenticated_page_has_csrf_meta(self, authenticated_client, app, db):
        with app.app_context():
            response = authenticated_client.get('/dashboard')
            assert response.status_code == 200
            assert b'csrf-token' in response.data

    def test_unauthenticated_page_no_notification_bell(self, client, app, db):
        with app.app_context():
            response = client.get('/auth/login')
            assert response.status_code == 200
            assert b'nav-notification' not in response.data
