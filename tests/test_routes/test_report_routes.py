"""Tests for report routes."""
import json
import os
import pytest
from app.models.user import User
from app.models.project import Project
from app.models.target import Target
from app.models.scan import Scan
from app.models.scan_job import ScanJob
from app.models.finding import Finding
from app.models.report import Report


def _register_and_login(client):
    """Helper: register a user and log in."""
    client.post('/auth/register', data={
        'username': 'reportrouteuser',
        'email': 'reportroute@example.com',
        'password': 'RoutePass123!',
        'confirm_password': 'RoutePass123!'
    })
    client.post('/auth/login', data={
        'username': 'reportrouteuser',
        'password': 'RoutePass123!'
    })


def _create_scan_with_findings(app, db):
    """Helper: create a scan with findings for testing."""
    with app.app_context():
        user = User.query.filter_by(username='reportrouteuser').first()
        project = Project(name='Report Route Project', description='Test', owner_id=user.id)
        project.save()

        target = Target(project_id=project.id, value='test.example.com', type='domain', is_approved=True)
        target.save()

        scan = Scan(
            target_id=target.id,
            initiated_by=user.id,
            name='Route Test Scan',
            scan_type='full',
            status='completed',
        )
        scan.save()

        job = ScanJob(
            scan_id=scan.id,
            tool_name='test_tool',
            status='completed',
            command='test_tool -t test.example.com',
        )
        job.save()

        finding = Finding(
            scan_id=scan.id,
            scan_job_id=job.id,
            target_id=target.id,
            project_id=project.id,
            title='Test Finding',
            severity='high',
            category='xss',
            tool_name='test_tool',
        )
        db.session.add(finding)
        db.session.commit()

        return scan.id, user.id


class TestReportListRoute:
    """Tests for GET /reports/."""

    def test_list_requires_login(self, client, app, db):
        with app.app_context():
            response = client.get('/reports/', follow_redirects=False)
            assert response.status_code == 302

    def test_list_shows_page(self, client, app, db):
        with app.app_context():
            _register_and_login(client)
            response = client.get('/reports/')
            assert response.status_code == 200
            assert b'Reports' in response.data

    def test_list_shows_reports(self, client, app, db):
        with app.app_context():
            _register_and_login(client)
            scan_id, user_id = _create_scan_with_findings(app, db)

            # Generate a report via POST
            client.post('/reports/generate', data={
                'scan_id': scan_id,
                'format': 'html',
                'title': 'Route Test Report',
            })

            db.session.expire_all()
            response = client.get('/reports/')
            assert response.status_code == 200
            assert b'Route Test Report' in response.data


class TestReportGenerateRoute:
    """Tests for GET/POST /reports/generate."""

    def test_generate_page_loads(self, client, app, db):
        with app.app_context():
            _register_and_login(client)
            response = client.get('/reports/generate')
            assert response.status_code == 200
            assert b'Generate Report' in response.data

    def test_generate_html_report(self, client, app, db):
        with app.app_context():
            _register_and_login(client)
            scan_id, user_id = _create_scan_with_findings(app, db)

            response = client.post('/reports/generate', data={
                'scan_id': scan_id,
                'format': 'html',
                'title': 'My Test Report',
                'includes_executive_summary': 'on',
                'includes_remediation': 'on',
            }, follow_redirects=True)
            assert response.status_code == 200
            assert b'My Test Report' in response.data or b'successfully' in response.data

    def test_generate_json_report(self, client, app, db):
        with app.app_context():
            _register_and_login(client)
            scan_id, user_id = _create_scan_with_findings(app, db)

            response = client.post('/reports/generate', data={
                'scan_id': scan_id,
                'format': 'json',
                'title': 'JSON Report',
            }, follow_redirects=True)
            assert response.status_code == 200

    def test_generate_without_scan(self, client, app, db):
        with app.app_context():
            _register_and_login(client)
            response = client.post('/reports/generate', data={
                'format': 'html',
            }, follow_redirects=True)
            assert response.status_code == 200

    def test_generate_with_preselected_scan(self, client, app, db):
        with app.app_context():
            _register_and_login(client)
            scan_id, _ = _create_scan_with_findings(app, db)
            response = client.get(f'/reports/generate?scan_id={scan_id}')
            assert response.status_code == 200
            assert b'Generate Report' in response.data


class TestReportViewRoute:
    """Tests for GET /reports/<id>."""

    def test_view_report(self, client, app, db):
        with app.app_context():
            _register_and_login(client)
            scan_id, user_id = _create_scan_with_findings(app, db)

            # Generate a report
            client.post('/reports/generate', data={
                'scan_id': scan_id,
                'format': 'html',
                'title': 'View Test Report',
            }, follow_redirects=True)

            # Get the report
            db.session.expire_all()
            report = Report.query.filter_by(title='View Test Report').first()
            assert report is not None

            response = client.get(f'/reports/{report.id}')
            assert response.status_code == 200
            assert b'View Test Report' in response.data

    def test_view_nonexistent_report(self, client, app, db):
        with app.app_context():
            _register_and_login(client)
            response = client.get('/reports/99999', follow_redirects=True)
            assert response.status_code == 200


class TestReportDownloadRoute:
    """Tests for GET /reports/<id>/download."""

    def test_download_report(self, client, app, db):
        with app.app_context():
            _register_and_login(client)
            scan_id, user_id = _create_scan_with_findings(app, db)

            # Generate a report
            client.post('/reports/generate', data={
                'scan_id': scan_id,
                'format': 'json',
                'title': 'Download Test Report',
            }, follow_redirects=True)

            db.session.expire_all()
            report = Report.query.filter_by(title='Download Test Report').first()
            assert report is not None

            response = client.get(f'/reports/{report.id}/download')
            assert response.status_code == 200

    def test_download_nonexistent_report(self, client, app, db):
        with app.app_context():
            _register_and_login(client)
            response = client.get('/reports/99999/download', follow_redirects=True)
            assert response.status_code == 200


class TestReportDeleteRoute:
    """Tests for POST /reports/<id>/delete."""

    def test_delete_report(self, client, app, db):
        with app.app_context():
            _register_and_login(client)
            scan_id, user_id = _create_scan_with_findings(app, db)

            # Generate a report
            client.post('/reports/generate', data={
                'scan_id': scan_id,
                'format': 'html',
                'title': 'Delete Test Report',
            }, follow_redirects=True)

            db.session.expire_all()
            report = Report.query.filter_by(title='Delete Test Report').first()
            assert report is not None
            report_id = report.id

            response = client.post(f'/reports/{report_id}/delete', follow_redirects=True)
            assert response.status_code == 200
            db.session.expire_all()
            assert Report.query.get(report_id) is None

    def test_delete_nonexistent_report(self, client, app, db):
        with app.app_context():
            _register_and_login(client)
            response = client.post('/reports/99999/delete', follow_redirects=True)
            assert response.status_code == 200
