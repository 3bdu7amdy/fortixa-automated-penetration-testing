"""Tests for ReportService."""
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
from app.services.report_service import ReportService


def _create_test_data(db):
    """Helper: create user, project, target, scan, and findings."""
    user = User(username='reportuser', email='report@example.com')
    user.password = 'TestPass123!'
    user.save()

    project = Project(name='Test Project', description='Test', owner_id=user.id)
    project.save()

    target = Target(project_id=project.id, value='example.com', type='domain', is_approved=True)
    target.save()

    scan = Scan(
        target_id=target.id,
        initiated_by=user.id,
        name='Test Scan',
        scan_type='full',
        status='completed',
    )
    scan.save()

    # Create a scan job (required by Finding FK)
    job = ScanJob(
        scan_id=scan.id,
        tool_name='test_tool',
        status='completed',
        command='test_tool -t example.com',
    )
    job.save()

    findings = []
    for i, (sev, cat) in enumerate([
        ('critical', 'xss'), ('high', 'sqli'), ('medium', 'lfi'),
        ('low', 'info'), ('info', 'subdomain')
    ]):
        f = Finding(
            scan_id=scan.id,
            scan_job_id=job.id,
            target_id=target.id,
            project_id=project.id,
            title=f'Test Finding {i+1}',
            severity=sev,
            category=cat,
            tool_name='test_tool',
            description=f'Description for finding {i+1}',
            url=f'https://example.com/page{i}',
            evidence=f'Evidence for finding {i+1}',
        )
        findings.append(f)

    for f in findings:
        db.session.add(f)
    db.session.commit()

    return user, project, target, scan, findings


class TestReportServiceGenerateHTML:
    """Tests for HTML report generation."""

    def test_generate_html_report(self, app, db):
        with app.app_context():
            user, project, target, scan, findings = _create_test_data(db)
            service = ReportService()
            result = service.generate_report(
                scan_id=scan.id,
                user_id=user.id,
                format='html',
                title='Test HTML Report',
                includes_executive_summary=True,
                includes_remediation=True,
            )
            assert result['success'] is True
            report = result['report']
            assert report.format == 'html'
            assert report.title == 'Test HTML Report'
            assert report.finding_count == 5
            assert report.critical_count == 1
            assert report.high_count == 1
            assert report.medium_count == 1
            assert report.low_count == 1
            assert report.info_count == 1
            assert report.includes_executive_summary is True
            assert report.includes_remediation is True
            assert os.path.exists(report.file_path)
            # Verify HTML content
            with open(report.file_path, 'r') as f:
                content = f.read()
            assert 'Test HTML Report' in content
            assert 'example.com' in content

    def test_generate_html_without_summary(self, app, db):
        with app.app_context():
            user, project, target, scan, findings = _create_test_data(db)
            service = ReportService()
            result = service.generate_report(
                scan_id=scan.id,
                user_id=user.id,
                format='html',
                includes_executive_summary=False,
                includes_remediation=True,
            )
            assert result['success'] is True
            report = result['report']
            assert report.includes_executive_summary is False
            with open(report.file_path, 'r') as f:
                content = f.read()
            assert 'id="executive-summary"' not in content


class TestReportServiceGenerateJSON:
    """Tests for JSON report generation."""

    def test_generate_json_report(self, app, db):
        with app.app_context():
            user, project, target, scan, findings = _create_test_data(db)
            service = ReportService()
            result = service.generate_report(
                scan_id=scan.id,
                user_id=user.id,
                format='json',
                title='Test JSON Report',
            )
            assert result['success'] is True
            report = result['report']
            assert report.format == 'json'
            assert report.finding_count == 5
            assert os.path.exists(report.file_path)

            with open(report.file_path, 'r') as f:
                data = json.load(f)

            assert data['metadata']['title'] == 'Test JSON Report'
            assert data['metadata']['scan_id'] == scan.id
            assert len(data['findings']) == 5
            assert data['summary']['total_findings'] == 5
            assert data['summary']['critical'] == 1
            assert data['summary']['high'] == 1
            assert 'executive_summary' in data
            assert 'recommendations' in data

    def test_generate_json_without_extras(self, app, db):
        with app.app_context():
            user, project, target, scan, findings = _create_test_data(db)
            service = ReportService()
            result = service.generate_report(
                scan_id=scan.id,
                user_id=user.id,
                format='json',
                includes_executive_summary=False,
                includes_remediation=False,
            )
            assert result['success'] is True
            with open(result['report'].file_path, 'r') as f:
                data = json.load(f)
            assert 'executive_summary' not in data
            assert 'recommendations' not in data


class TestReportServiceGeneratePDF:
    """Tests for PDF report generation."""

    def test_generate_pdf_report_fallback(self, app, db):
        """Test PDF generation falls back to HTML if weasyprint not available."""
        with app.app_context():
            user, project, target, scan, findings = _create_test_data(db)
            service = ReportService()
            result = service.generate_report(
                scan_id=scan.id,
                user_id=user.id,
                format='pdf',
                title='Test PDF Report',
            )
            assert result['success'] is True
            report = result['report']
            assert report.format == 'pdf'
            assert os.path.exists(report.file_path)


class TestReportServiceValidation:
    """Tests for report service validation."""

    def test_invalid_format(self, app, db):
        with app.app_context():
            user, project, target, scan, findings = _create_test_data(db)
            service = ReportService()
            result = service.generate_report(
                scan_id=scan.id,
                user_id=user.id,
                format='docx',
            )
            assert result['success'] is False
            assert 'Unsupported' in result['errors'][0]

    def test_nonexistent_scan(self, app, db):
        with app.app_context():
            service = ReportService()
            result = service.generate_report(
                scan_id=99999,
                user_id=1,
                format='html',
            )
            assert result['success'] is False
            assert 'not found' in result['errors'][0].lower()

    def test_auto_title(self, app, db):
        with app.app_context():
            user, project, target, scan, findings = _create_test_data(db)
            service = ReportService()
            result = service.generate_report(
                scan_id=scan.id,
                user_id=user.id,
                format='json',
            )
            assert result['success'] is True
            assert 'Test Scan' in result['report'].title


class TestReportServiceListGet:
    """Tests for list and get report methods."""

    def test_list_reports(self, app, db):
        with app.app_context():
            user, project, target, scan, findings = _create_test_data(db)
            service = ReportService()
            service.generate_report(scan_id=scan.id, user_id=user.id, format='html')
            service.generate_report(scan_id=scan.id, user_id=user.id, format='json')

            reports = service.list_reports(user_id=user.id)
            assert len(reports) == 2

    def test_list_reports_by_scan(self, app, db):
        with app.app_context():
            user, project, target, scan, findings = _create_test_data(db)
            service = ReportService()
            service.generate_report(scan_id=scan.id, user_id=user.id, format='html')

            reports = service.list_reports(scan_id=scan.id)
            assert len(reports) == 1

    def test_get_report_success(self, app, db):
        with app.app_context():
            user, project, target, scan, findings = _create_test_data(db)
            service = ReportService()
            gen_result = service.generate_report(
                scan_id=scan.id, user_id=user.id, format='html'
            )
            report_id = gen_result['report'].id

            result = service.get_report(report_id, user.id)
            assert result['success'] is True
            assert result['report'].id == report_id

    def test_get_report_wrong_user(self, app, db):
        with app.app_context():
            user, project, target, scan, findings = _create_test_data(db)
            service = ReportService()
            gen_result = service.generate_report(
                scan_id=scan.id, user_id=user.id, format='html'
            )
            report_id = gen_result['report'].id

            result = service.get_report(report_id, 99999)
            assert result['success'] is False
            assert 'Access denied' in result['errors'][0]

    def test_get_report_nonexistent(self, app, db):
        with app.app_context():
            service = ReportService()
            result = service.get_report(99999, 1)
            assert result['success'] is False
            assert 'not found' in result['errors'][0].lower()


class TestReportServiceDownload:
    """Tests for download report method."""

    def test_download_report_success(self, app, db):
        with app.app_context():
            user, project, target, scan, findings = _create_test_data(db)
            service = ReportService()
            gen_result = service.generate_report(
                scan_id=scan.id, user_id=user.id, format='html'
            )
            report_id = gen_result['report'].id

            result = service.download_report(report_id, user.id)
            assert result['success'] is True
            assert os.path.exists(result['file_path'])

    def test_download_report_wrong_user(self, app, db):
        with app.app_context():
            user, project, target, scan, findings = _create_test_data(db)
            service = ReportService()
            gen_result = service.generate_report(
                scan_id=scan.id, user_id=user.id, format='html'
            )
            report_id = gen_result['report'].id

            result = service.download_report(report_id, 99999)
            assert result['success'] is False


class TestReportServiceDelete:
    """Tests for delete report method."""

    def test_delete_report(self, app, db):
        with app.app_context():
            user, project, target, scan, findings = _create_test_data(db)
            service = ReportService()
            gen_result = service.generate_report(
                scan_id=scan.id, user_id=user.id, format='html'
            )
            report_id = gen_result['report'].id
            file_path = gen_result['report'].file_path

            result = service.delete_report(report_id, user.id)
            assert result['success'] is True
            assert Report.query.get(report_id) is None
            assert not os.path.exists(file_path)

    def test_delete_report_wrong_user(self, app, db):
        with app.app_context():
            user, project, target, scan, findings = _create_test_data(db)
            service = ReportService()
            gen_result = service.generate_report(
                scan_id=scan.id, user_id=user.id, format='html'
            )
            report_id = gen_result['report'].id

            result = service.delete_report(report_id, 99999)
            assert result['success'] is False
            assert Report.query.get(report_id) is not None


class TestReportServiceHelpers:
    """Tests for helper methods."""

    def test_count_severities(self, app, db):
        with app.app_context():
            service = ReportService()
            # Create mock findings
            class MockFinding:
                def __init__(self, severity):
                    self.severity = severity

            findings = [
                MockFinding('critical'), MockFinding('critical'),
                MockFinding('high'), MockFinding('medium'),
                MockFinding('low'), MockFinding('info'),
            ]
            counts = service._count_severities(findings)
            assert counts['critical'] == 2
            assert counts['high'] == 1
            assert counts['medium'] == 1
            assert counts['low'] == 1
            assert counts['info'] == 1

    def test_generate_executive_summary(self, app, db):
        with app.app_context():
            service = ReportService()

            class MockTarget:
                value = 'example.com'

            class MockScan:
                scan_type = 'full'
                target = MockTarget()

            class MockFinding:
                def __init__(self, category):
                    self.category = category

            findings = [MockFinding('xss'), MockFinding('sqli')]
            summary = service._generate_executive_summary(
                scan=MockScan(),
                findings=findings,
                severity_counts={'critical': 1, 'high': 2, 'medium': 0, 'low': 0, 'info': 0},
            )
            assert 'CRITICAL' in summary
            assert '2 finding(s)' in summary
            assert 'example.com' in summary

    def test_generate_executive_summary_no_findings(self, app, db):
        with app.app_context():
            service = ReportService()

            class MockTarget:
                value = 'example.com'

            class MockScan:
                scan_type = 'recon'
                target = MockTarget()

            summary = service._generate_executive_summary(
                scan=MockScan(),
                findings=[],
                severity_counts={'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            )
            assert 'MINIMAL' in summary
            assert '0 finding(s)' in summary

    def test_generate_remediation(self, app, db):
        with app.app_context():
            service = ReportService()
            findings = [
                type('F', (), {'severity': 'critical', 'title': 'XSS', 'category': 'xss',
                                'url': 'https://example.com', 'remediation': None})(),
                type('F', (), {'severity': 'high', 'title': 'SQLi', 'category': 'sqli',
                                'url': None, 'remediation': 'Use prepared statements'})(),
            ]
            recs = service._generate_remediation(findings)
            assert len(recs) == 2
            # Should be sorted by severity
            assert recs[0]['severity'] == 'critical'
            assert recs[1]['severity'] == 'high'
            # Default remediation for XSS
            assert 'output encoding' in recs[0]['recommendation'].lower()
            # Custom remediation for SQLi
            assert 'prepared statements' in recs[1]['recommendation']

    def test_default_remediation_by_category(self, app, db):
        with app.app_context():
            service = ReportService()
            f = type('F', (), {'category': 'xss', 'severity': 'high'})()
            rec = service._default_remediation(f)
            assert 'output encoding' in rec.lower() or 'CSP' in rec

    def test_default_remediation_critical_no_category(self, app, db):
        with app.app_context():
            service = ReportService()
            f = type('F', (), {'category': 'unknown', 'severity': 'critical'})()
            rec = service._default_remediation(f)
            assert 'high priority' in rec.lower()
