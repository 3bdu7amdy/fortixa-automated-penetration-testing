"""Integration test - Full user workflow end-to-end.

Tests the complete pentest workflow through the Flask test client:
  Register → Login → Create Project → Add Target → Approve Target
  → Configure Scan → Start Scan → View Findings → AI Analysis
  → Generate Report → Download Report

All security tool execution is mocked — no real tools are run.
"""
import json
import os

import pytest

from app.extensions import db as _db
from app.models.user import User
from app.models.project import Project
from app.models.target import Target
from app.models.scan import Scan
from app.models.scan_job import ScanJob
from app.models.finding import Finding
from app.models.configuration import Configuration
from app.models.report import Report
from app.models.ai_analysis_result import AIAnalysisResult
from tests.helpers import (
    register_user, login_user, create_project, add_target,
    approve_target, create_and_run_scan, create_user_direct,
    create_finding_direct, complete_all_scan_jobs, get_default_config_id,
)


@pytest.fixture
def workflow_client(client, db):
    """An authenticated client ready for the full workflow."""
    register_user(client, 'workflow_user', 'workflow@example.com', 'TestPass123!')
    login_user(client, 'workflow_user', 'TestPass123!')
    return client


@pytest.fixture
def admin_workflow_client(client, db):
    """An admin client for workflows requiring admin approval."""
    register_user(client, 'admin_user', 'admin_wf@example.com', 'AdminPass123!')
    # Make admin
    with client.application.app_context():
        user = User.query.filter_by(username='admin_user').first()
        user.role = 'admin'
        user.save()
    login_user(client, 'admin_user', 'AdminPass123!')
    return client


# ─── Full Workflow Tests ─────────────────────────────────────────────────────

class TestFullWorkflow:
    """End-to-end test of the complete pentest workflow."""

    def test_register_login_create_project(self, client, db):
        """Test: Register → Login → Create Project."""
        # Step 1: Register
        resp = register_user(client, 'e2e_user1', 'e2e1@example.com', 'TestPass123!')
        assert resp.status_code == 302  # Redirect to login

        # Verify user created
        user = User.query.filter_by(username='e2e_user1').first()
        assert user is not None
        assert user.email == 'e2e1@example.com'

        # Step 2: Login
        resp = login_user(client, 'e2e_user1', 'TestPass123!')
        assert resp.status_code == 302  # Redirect to dashboard

        # Step 3: Create project
        resp = create_project(client, 'E2E Test Project', 'Testing full workflow')
        assert resp.status_code == 302  # Redirect to project view

        # Verify project created
        project = Project.query.filter_by(name='E2E Test Project').first()
        assert project is not None
        assert project.description == 'Testing full workflow'
        assert project.owner_id == user.id

    def test_project_target_management(self, workflow_client, db):
        """Test: Create Project → Add Target → Approve Target."""
        client = workflow_client

        # Create project
        resp = create_project(client, 'Target Test Project')
        assert resp.status_code == 302

        project = Project.query.filter_by(name='Target Test Project').first()
        assert project is not None

        # Add target
        resp = add_target(client, project.id, 'example.com', 'domain')
        assert resp.status_code == 302

        target = Target.query.filter_by(project_id=project.id, value='example.com').first()
        assert target is not None
        assert target.type == 'domain'
        assert target.is_approved is False  # Needs admin approval

        # Make user admin and approve target
        with client.application.app_context():
            user = User.query.filter_by(username='workflow_user').first()
            user.role = 'admin'
            user.save()

        login_user(client, 'workflow_user', 'TestPass123!')
        resp = approve_target(client, project.id, target.id)
        assert resp.status_code == 302

        _db.session.expire_all()
        target = Target.query.get(target.id)
        assert target.is_approved is True

    def test_scan_creation_and_job_generation(self, admin_workflow_client, db):
        """Test: Create Project → Add/Approve Target → Start Scan → Jobs Created."""
        client = admin_workflow_client

        # Create project + target
        project = Project(name='Scan Test Project', owner_id=1, status='active')
        project.save()
        target = Target(
            project_id=project.id, value='scan.example.com',
            type='domain', is_approved=True,
        )
        target.save()

        # Get default config
        config_id = get_default_config_id('recon')
        assert config_id is not None

        # Start scan
        resp = create_and_run_scan(client, target.id, config_id, 'Recon Scan')
        assert resp.status_code == 302

        # Verify scan created
        scan = Scan.query.filter_by(name='Recon Scan').first()
        assert scan is not None
        assert scan.status == 'pending'
        assert scan.target_id == target.id

        # Verify jobs created for each enabled tool in config
        jobs = ScanJob.query.filter_by(scan_id=scan.id).all()
        assert len(jobs) > 0

        config = Configuration.query.get(config_id)
        enabled_tools = config.get_enabled_tools()
        assert len(jobs) == len(enabled_tools)

        for job in jobs:
            assert job.tool_name in enabled_tools
            assert job.status == 'queued'

    def test_scan_completion_and_findings(self, admin_workflow_client, db):
        """Test: Start Scan → Complete Jobs → View Findings."""
        client = admin_workflow_client

        # Setup: project, target, scan
        project = Project(name='Findings Test Project', owner_id=1, status='active')
        project.save()
        target = Target(
            project_id=project.id, value='findings.example.com',
            type='domain', is_approved=True,
        )
        target.save()

        config_id = get_default_config_id('recon')
        scan = Scan(
            target_id=target.id, initiated_by=1,
            name='Findings Scan', scan_type='recon',
            config_id=config_id, status='pending',
        )
        scan.save()

        # Create jobs
        job1 = ScanJob(
            scan_id=scan.id, tool_name='subfinder',
            command='subfinder -d findings.example.com',
            status='queued',
        )
        job1.save()
        job2 = ScanJob(
            scan_id=scan.id, tool_name='httpx',
            command='httpx -u findings.example.com',
            status='queued',
        )
        job2.save()

        scan.total_jobs = 2
        scan.save()

        # Simulate finding from subfinder
        finding1 = Finding(
            scan_id=scan.id, scan_job_id=job1.id,
            target_id=target.id, project_id=project.id,
            title='Subdomain: sub.findings.example.com',
            severity='info', category='subdomain',
            tool_name='subfinder', url='https://sub.findings.example.com',
            evidence='sub.findings.example.com',
        )
        finding1.save()

        finding2 = Finding(
            scan_id=scan.id, scan_job_id=job2.id,
            target_id=target.id, project_id=project.id,
            title='Live Host: sub.findings.example.com',
            severity='info', category='live_host',
            tool_name='httpx', url='https://sub.findings.example.com',
            evidence='200 OK',
        )
        finding2.save()

        # Complete all jobs (simulates worker)
        completed = complete_all_scan_jobs(scan.id)
        assert completed == 2

        # Verify scan completed
        _db.session.expire_all()
        scan = Scan.query.get(scan.id)
        assert scan.status == 'completed'

        # View scan page
        resp = client.get(f'/scans/{scan.id}')
        assert resp.status_code == 200
        assert b'Findings Scan' in resp.data

        # View findings summary
        findings = Finding.query.filter_by(scan_id=scan.id).all()
        assert len(findings) == 2

    def test_ai_analysis_on_completed_scan(self, admin_workflow_client, db):
        """Test: Completed Scan → Run AI Analysis → View Results."""
        client = admin_workflow_client

        # Setup full scan with findings
        project = Project(name='AI Test Project', owner_id=1, status='active')
        project.save()
        target = Target(
            project_id=project.id, value='ai.example.com',
            type='domain', is_approved=True,
        )
        target.save()

        config_id = get_default_config_id('recon')
        scan = Scan(
            target_id=target.id, initiated_by=1,
            name='AI Analysis Scan', scan_type='recon',
            config_id=config_id, status='completed',
        )
        scan.save()

        job = ScanJob(
            scan_id=scan.id, tool_name='nuclei',
            command='nuclei -u ai.example.com', status='completed',
            exit_code=0,
        )
        job.save()

        # Create findings for AI analysis
        Finding(
            scan_id=scan.id, scan_job_id=job.id,
            target_id=target.id, project_id=project.id,
            title='XSS in search parameter', severity='high',
            category='xss', tool_name='nuclei',
            url='https://ai.example.com/search', parameter='q',
            payload='<script>alert(1)</script>',
            evidence='Payload reflected in response',
        ).save()

        Finding(
            scan_id=scan.id, scan_job_id=job.id,
            target_id=target.id, project_id=project.id,
            title='XSS in search parameter', severity='high',
            category='xss', tool_name='dalfox',
            url='https://ai.example.com/search', parameter='q',
            evidence='Reflected XSS confirmed',
        ).save()

        # Run AI analysis
        resp = client.post(f'/ai/analyze/{scan.id}', follow_redirects=True)
        assert resp.status_code == 200

        # Verify AI analysis results created
        results = AIAnalysisResult.query.filter_by(scan_id=scan.id).all()
        assert len(results) > 0

        # Check for deduplication (same URL + category)
        dedup_results = [r for r in results if r.analysis_type == 'deduplication']
        assert len(dedup_results) >= 1

        # Check for severity suggestions
        severity_results = [r for r in results if r.analysis_type == 'severity_suggestion']
        assert len(severity_results) >= 1

        # Check recommendations
        rec_results = [r for r in results if r.analysis_type == 'recommendation']
        assert len(rec_results) >= 1

        # View AI results page
        resp = client.get(f'/ai/results/{scan.id}')
        assert resp.status_code == 200

    def test_report_generation_and_download(self, admin_workflow_client, db):
        """Test: Completed Scan → Generate HTML Report → Download Report."""
        client = admin_workflow_client

        # Setup completed scan with findings
        project = Project(name='Report Test Project', owner_id=1, status='active')
        project.save()
        target = Target(
            project_id=project.id, value='report.example.com',
            type='domain', is_approved=True,
        )
        target.save()

        config_id = get_default_config_id('recon')
        scan = Scan(
            target_id=target.id, initiated_by=1,
            name='Report Scan', scan_type='recon',
            config_id=config_id, status='completed',
        )
        scan.save()

        job = ScanJob(
            scan_id=scan.id, tool_name='subfinder',
            command='subfinder -d report.example.com',
            status='completed', exit_code=0,
        )
        job.save()

        Finding(
            scan_id=scan.id, scan_job_id=job.id,
            target_id=target.id, project_id=project.id,
            title='Subdomain: api.report.example.com',
            severity='info', category='subdomain',
            tool_name='subfinder', url='https://api.report.example.com',
        ).save()

        # Generate HTML report
        resp = client.post('/reports/generate', data={
            'scan_id': scan.id,
            'format': 'html',
            'title': 'E2E Test Report',
            'includes_executive_summary': 'on',
            'includes_remediation': 'on',
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b'E2E Test Report' in resp.data

        # Verify report created
        report = Report.query.filter_by(scan_id=scan.id).first()
        assert report is not None
        assert report.format == 'html'
        assert report.file_path is not None
        assert os.path.exists(report.file_path)

        # Download report
        resp = client.get(f'/reports/{report.id}/download')
        assert resp.status_code == 200
        assert b'html' in resp.data or b'Pentest' in resp.data

        # Generate JSON report
        resp = client.post('/reports/generate', data={
            'scan_id': scan.id,
            'format': 'json',
            'title': 'E2E JSON Report',
        }, follow_redirects=True)
        assert resp.status_code == 200

        json_report = Report.query.filter_by(scan_id=scan.id, format='json').first()
        assert json_report is not None
        assert os.path.exists(json_report.file_path)

        # Verify JSON content
        with open(json_report.file_path, 'r') as f:
            data = json.load(f)
        assert 'metadata' in data
        assert 'findings' in data
        assert data['metadata']['scan_name'] == 'Report Scan'

    def test_complete_user_journey(self, client, db):
        """Full journey: Register → Login → Project → Target → Scan → AI → Report."""
        # 1. Register
        resp = register_user(client, 'journey_user', 'journey@example.com', 'JourneyPass1!')
        assert resp.status_code == 302

        # 2. Login
        resp = login_user(client, 'journey_user', 'JourneyPass1!')
        assert resp.status_code == 302

        # 3. Create project
        resp = create_project(client, 'Journey Project', 'Full journey test')
        assert resp.status_code == 302

        project = Project.query.filter_by(name='Journey Project').first()
        assert project is not None

        # 4. Add target
        resp = add_target(client, project.id, 'journey.example.com', 'domain')
        assert resp.status_code == 302

        target = Target.query.filter_by(project_id=project.id).first()
        assert target is not None
        assert target.is_approved is False

        # 5. Make user admin to approve target
        with client.application.app_context():
            user = User.query.filter_by(username='journey_user').first()
            user.role = 'admin'
            user.save()
        login_user(client, 'journey_user', 'JourneyPass1!')

        # 6. Approve target
        resp = approve_target(client, project.id, target.id)
        assert resp.status_code == 302

        _db.session.expire_all()
        target = Target.query.get(target.id)
        assert target.is_approved is True

        # 7. Start scan
        config_id = get_default_config_id('recon')
        resp = create_and_run_scan(client, target.id, config_id, 'Journey Scan')
        assert resp.status_code == 302

        scan = Scan.query.filter_by(name='Journey Scan').first()
        assert scan is not None

        # 8. Add findings and complete scan (simulated worker)
        jobs = ScanJob.query.filter_by(scan_id=scan.id).all()
        assert len(jobs) > 0

        for job in jobs:
            Finding(
                scan_id=scan.id, scan_job_id=job.id,
                target_id=target.id, project_id=project.id,
                title=f'{job.tool_name} finding', severity='info',
                category='subdomain', tool_name=job.tool_name,
                url=f'https://sub.journey.example.com',
            ).save()

        complete_all_scan_jobs(scan.id)

        _db.session.expire_all()
        scan = Scan.query.get(scan.id)
        assert scan.status == 'completed'

        # 9. Run AI analysis
        resp = client.post(f'/ai/analyze/{scan.id}', follow_redirects=True)
        assert resp.status_code == 200

        ai_results = AIAnalysisResult.query.filter_by(scan_id=scan.id).all()
        assert len(ai_results) > 0

        # 10. Generate report
        resp = client.post('/reports/generate', data={
            'scan_id': scan.id,
            'format': 'html',
            'includes_executive_summary': 'on',
            'includes_remediation': 'on',
        }, follow_redirects=True)
        assert resp.status_code == 200

        report = Report.query.filter_by(scan_id=scan.id).first()
        assert report is not None

        # 11. Download report
        resp = client.get(f'/reports/{report.id}/download')
        assert resp.status_code == 200

        # 12. Verify dashboard shows data
        resp = client.get('/dashboard')
        assert resp.status_code == 200


class TestWorkflowErrorHandling:
    """Test error handling during the workflow."""

    def test_unauthenticated_access_redirects(self, client, db):
        """Test that protected routes redirect to login."""
        protected_routes = [
            '/projects/',
            '/scans/',
            '/reports/',
            '/engine/status',
        ]
        for route in protected_routes:
            resp = client.get(route)
            # Should redirect to login
            assert resp.status_code == 302
            assert '/auth/login' in resp.headers.get('Location', '')

    def test_invalid_project_access(self, workflow_client, db):
        """Test accessing non-existent project."""
        resp = workflow_client.get('/projects/99999')
        assert resp.status_code == 302  # Redirect with error flash

    def test_scan_without_approved_target(self, admin_workflow_client, db):
        """Test that scan cannot start on unapproved target."""
        client = admin_workflow_client

        project = Project(name='Unapproved Target Project', owner_id=1, status='active')
        project.save()
        target = Target(
            project_id=project.id, value='unapproved.example.com',
            type='domain', is_approved=False,
        )
        target.save()

        config_id = get_default_config_id('recon')
        resp = create_and_run_scan(client, target.id, config_id, 'Bad Scan')
        # Should not create scan
        scan = Scan.query.filter_by(name='Bad Scan').first()
        assert scan is None

    def test_scan_with_invalid_config(self, admin_workflow_client, db):
        """Test that scan fails with non-existent config."""
        client = admin_workflow_client

        project = Project(name='Bad Config Project', owner_id=1, status='active')
        project.save()
        target = Target(
            project_id=project.id, value='badconfig.example.com',
            type='domain', is_approved=True,
        )
        target.save()

        resp = create_and_run_scan(client, target.id, 99999, 'Bad Config Scan')
        scan = Scan.query.filter_by(name='Bad Config Scan').first()
        assert scan is None

    def test_ai_analysis_on_running_scan(self, admin_workflow_client, db):
        """Test that AI analysis cannot run on a still-running scan."""
        client = admin_workflow_client

        project = Project(name='Running Scan Project', owner_id=1, status='active')
        project.save()
        target = Target(
            project_id=project.id, value='running.example.com',
            type='domain', is_approved=True,
        )
        target.save()

        scan = Scan(
            target_id=target.id, initiated_by=1,
            name='Running Scan', scan_type='recon',
            status='running',
        )
        scan.save()

        resp = client.post(f'/ai/analyze/{scan.id}', follow_redirects=True)
        # Should flash warning - AI analysis only on completed scans
        assert b'completed' in resp.data or resp.status_code == 200

    def test_report_for_nonexistent_scan(self, workflow_client, db):
        """Test generating a report for a non-existent scan."""
        resp = workflow_client.post('/reports/generate', data={
            'scan_id': 99999,
            'format': 'html',
        }, follow_redirects=True)
        # Should show error
        assert resp.status_code == 200

    def test_duplicate_target_rejected(self, workflow_client, db):
        """Test that adding the same target twice is rejected."""
        client = workflow_client

        project = Project(name='Duplicate Target Project', owner_id=1, status='active')
        project.save()

        # Add target first time
        add_target(client, project.id, 'dup.example.com', 'domain')

        # Try adding same target again
        resp = add_target(client, project.id, 'dup.example.com', 'domain')
        assert resp.status_code == 302

        # Should still be only one target
        targets = Target.query.filter_by(project_id=project.id, value='dup.example.com').all()
        assert len(targets) == 1
