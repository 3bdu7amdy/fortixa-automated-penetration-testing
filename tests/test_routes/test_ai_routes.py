"""Tests for AI analysis routes."""
import json
import pytest

from app.models.user import User
from app.models.project import Project
from app.models.target import Target
from app.models.scan import Scan
from app.models.scan_job import ScanJob
from app.models.finding import Finding
from app.models.ai_analysis_result import AIAnalysisResult


@pytest.fixture(scope='function')
def auth_client(client, db):
    """Authenticated test client - registers and logs in a user."""
    client.post('/auth/register', data={
        'username': 'aiuser',
        'email': 'aiuser@test.com',
        'password': 'TestPass123!',
        'confirm_password': 'TestPass123!',
    })
    client.post('/auth/login', data={
        'username': 'aiuser',
        'password': 'TestPass123!',
    })
    return client


def _create_scan_via_db(client, db, status='completed'):
    """Create a scan + finding via direct DB access within app context.
    Returns (scan_id, finding_id or None).
    """
    with client.application.app_context():
        user = User.query.filter_by(username='aiuser').first()
        project = Project(name='AI Test Project', owner_id=user.id)
        db.session.add(project)
        db.session.commit()

        target = Target(
            project_id=project.id,
            value='ai-test.example.com',
            type='domain',
            is_approved=True,
        )
        db.session.add(target)
        db.session.commit()

        scan = Scan(
            target_id=target.id,
            initiated_by=user.id,
            name='AI Test Scan',
            scan_type='full',
            status=status,
        )
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

        finding_id = None
        if status == 'completed':
            job = ScanJob(
                scan_id=scan.id,
                tool_name='dalfox',
                command='dalfox -u ai-test.example.com',
                status='completed',
            )
            db.session.add(job)
            db.session.commit()

            finding = Finding(
                scan_id=scan.id,
                scan_job_id=job.id,
                target_id=target.id,
                project_id=project.id,
                title='XSS on /search',
                severity='high',
                category='xss',
                tool_name='dalfox',
                confidence='firm',
                url='http://ai-test.example.com/search',
            )
            db.session.add(finding)
            db.session.commit()
            finding_id = finding.id

        return scan_id, finding_id


class TestAIAnalyzeRoute:
    def test_analyze_requires_login(self, client, db):
        response = client.post('/ai/analyze/1', follow_redirects=False)
        assert response.status_code == 302
        assert '/auth/login' in response.headers['Location']

    def test_analyze_scan(self, auth_client, db):
        scan_id, _ = _create_scan_via_db(auth_client, db)
        response = auth_client.post(f'/ai/analyze/{scan_id}', follow_redirects=True)
        assert response.status_code == 200
        assert b'AI analysis complete' in response.data

    def test_analyze_nonexistent_scan(self, auth_client, db):
        response = auth_client.post('/ai/analyze/99999', follow_redirects=False)
        assert response.status_code == 404

    def test_analyze_running_scan_rejected(self, auth_client, db):
        scan_id, _ = _create_scan_via_db(auth_client, db, status='running')
        response = auth_client.post(f'/ai/analyze/{scan_id}', follow_redirects=True)
        assert response.status_code == 200
        assert b'only be run on completed scans' in response.data


class TestAIResultsRoute:
    def test_results_requires_login(self, client, db):
        response = client.get('/ai/results/1', follow_redirects=False)
        assert response.status_code == 302
        assert '/auth/login' in response.headers['Location']

    def test_results_page(self, auth_client, db):
        scan_id, _ = _create_scan_via_db(auth_client, db)
        response = auth_client.get(f'/ai/results/{scan_id}')
        assert response.status_code == 200
        assert b'AI Analysis' in response.data

    def test_results_nonexistent_scan(self, auth_client, db):
        response = auth_client.get('/ai/results/99999')
        assert response.status_code == 404

    def test_results_shows_analysis_data(self, auth_client, db):
        scan_id, _ = _create_scan_via_db(auth_client, db)
        # Run analysis first
        auth_client.post(f'/ai/analyze/{scan_id}', follow_redirects=True)
        # Check results page
        response = auth_client.get(f'/ai/results/{scan_id}')
        assert response.status_code == 200


class TestAIReviewRoute:
    def test_review_requires_login(self, client, db):
        response = client.post('/ai/findings/1/review', follow_redirects=False)
        assert response.status_code == 302
        assert '/auth/login' in response.headers['Location']

    def test_review_accept_suggestion(self, auth_client, db):
        scan_id, finding_id = _create_scan_via_db(auth_client, db)

        # Create a pending FP analysis result
        with auth_client.application.app_context():
            analysis = AIAnalysisResult(
                finding_id=finding_id,
                scan_id=scan_id,
                analysis_type='false_positive',
                result=json.dumps({
                    'fp_score': 0.5,
                    'reasons': ['test'],
                    'category': 'xss',
                    'tool_name': 'dalfox',
                }),
                confidence_score=0.5,
                reasoning='Test reasoning',
                is_accepted=None,
            )
            db.session.add(analysis)
            db.session.commit()

        response = auth_client.post(f'/ai/findings/{finding_id}/review', data={
            'analysis_type': 'false_positive',
            'action': 'accept',
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b'accepted' in response.data

    def test_review_reject_suggestion(self, auth_client, db):
        scan_id, finding_id = _create_scan_via_db(auth_client, db)

        with auth_client.application.app_context():
            analysis = AIAnalysisResult(
                finding_id=finding_id,
                scan_id=scan_id,
                analysis_type='severity_suggestion',
                result=json.dumps({
                    'current_severity': 'high',
                    'suggested_severity': 'medium',
                    'suggested_cvss': 5.0,
                    'category': 'xss',
                    'changed': True,
                }),
                confidence_score=0.7,
                reasoning='Test',
                is_accepted=None,
            )
            db.session.add(analysis)
            db.session.commit()

        response = auth_client.post(f'/ai/findings/{finding_id}/review', data={
            'analysis_type': 'severity_suggestion',
            'action': 'reject',
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b'rejected' in response.data

    def test_review_invalid_params(self, auth_client, db):
        scan_id, finding_id = _create_scan_via_db(auth_client, db)
        response = auth_client.post(f'/ai/findings/{finding_id}/review', data={
            'analysis_type': '',
            'action': 'bad_action',
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b'Invalid review parameters' in response.data

    def test_review_nonexistent_finding(self, auth_client, db):
        response = auth_client.post('/ai/findings/99999/review', data={
            'analysis_type': 'deduplication',
            'action': 'accept',
        }, follow_redirects=False)
        assert response.status_code == 404
