"""Tests for AIService - deduplication, severity, false positives, recommendations."""
import json
import pytest

from app.models.user import User
from app.models.project import Project
from app.models.target import Target
from app.models.scan import Scan
from app.models.scan_job import ScanJob
from app.models.finding import Finding
from app.models.ai_analysis_result import AIAnalysisResult
from app.services.ai_service import AIService, _cvss_to_severity
from app.extensions import db as _db


# ── Helpers ──────────────────────────────────────────────────────────────────

def _create_user(db, username='testuser', email='test@example.com'):
    user = User(username=username, email=email)
    user.password = 'TestPass123!'
    db.session.add(user)
    db.session.commit()
    return user


def _create_project(db, user):
    project = Project(name='Test Project', owner_id=user.id)
    db.session.add(project)
    db.session.commit()
    return project


def _create_target(db, project):
    target = Target(project_id=project.id, value='example.com', type='domain', is_approved=True)
    db.session.add(target)
    db.session.commit()
    return target


def _create_scan(db, user, target, status='completed'):
    scan = Scan(
        target_id=target.id, initiated_by=user.id,
        name='Test Scan', scan_type='full', status=status,
    )
    db.session.add(scan)
    db.session.commit()
    return scan


def _create_scan_job(db, scan, tool_name='nuclei'):
    job = ScanJob(
        scan_id=scan.id, tool_name=tool_name,
        command=f'{tool_name} -u example.com', status='completed',
    )
    db.session.add(job)
    db.session.commit()
    return job


def _create_finding(db, scan, job, target, project, **kwargs):
    defaults = {
        'title': 'Test Finding', 'severity': 'high',
        'category': 'xss', 'tool_name': 'dalfox', 'confidence': 'firm',
    }
    defaults.update(kwargs)
    finding = Finding(
        scan_id=scan.id, scan_job_id=job.id,
        target_id=target.id, project_id=project.id, **defaults,
    )
    db.session.add(finding)
    db.session.commit()
    return finding


def _setup_scan_with_findings(db, findings_data):
    user = _create_user(db)
    project = _create_project(db, user)
    target = _create_target(db, project)
    scan = _create_scan(db, user, target)
    job = _create_scan_job(db, scan)
    findings = []
    for fd in findings_data:
        f = _create_finding(db, scan, job, target, project, **fd)
        findings.append(f)
    return scan, findings


# ── CVSS-to-severity helper ────────────────────────────────────────────────

class TestCvssToSeverity:
    def test_critical(self, db):
        assert _cvss_to_severity(9.8) == 'critical'

    def test_high(self, db):
        assert _cvss_to_severity(7.5) == 'high'

    def test_medium(self, db):
        assert _cvss_to_severity(5.0) == 'medium'

    def test_low(self, db):
        assert _cvss_to_severity(2.5) == 'low'

    def test_info(self, db):
        assert _cvss_to_severity(0.0) == 'info'


# ── Deduplication ───────────────────────────────────────────────────────────

class TestDeduplicateFindings:
    def test_no_findings(self, db):
        user = _create_user(db)
        project = _create_project(db, user)
        target = _create_target(db, project)
        scan = _create_scan(db, user, target)
        service = AIService()
        result = service.deduplicate_findings(scan.id)
        assert result['duplicates_found'] == 0

    def test_single_finding_no_duplicates(self, db):
        scan, findings = _setup_scan_with_findings(db, [
            {'title': 'XSS on /search', 'url': 'http://example.com/search', 'category': 'xss'},
        ])
        service = AIService()
        result = service.deduplicate_findings(scan.id)
        assert result['duplicates_found'] == 0

    def test_duplicate_findings_same_url_category(self, db):
        scan, findings = _setup_scan_with_findings(db, [
            {'title': 'XSS on /search', 'url': 'http://example.com/search', 'category': 'xss', 'confidence': 'certain'},
            {'title': 'XSS found in /search', 'url': 'http://example.com/search', 'category': 'xss', 'confidence': 'tentative'},
        ])
        service = AIService()
        result = service.deduplicate_findings(scan.id)
        assert result['duplicates_found'] == 1

        db.session.expire_all()
        original = Finding.query.filter_by(id=findings[0].id).first()
        dup = Finding.query.filter_by(id=findings[1].id).first()
        assert original.is_duplicate is False
        assert dup.is_duplicate is True
        assert dup.duplicate_of_id == original.id

    def test_duplicate_creates_analysis_result(self, db):
        scan, findings = _setup_scan_with_findings(db, [
            {'title': 'XSS on /search', 'url': 'http://ex.com/search', 'category': 'xss'},
            {'title': 'XSS /search', 'url': 'http://ex.com/search', 'category': 'xss'},
        ])
        service = AIService()
        service.deduplicate_findings(scan.id)

        analyses = AIAnalysisResult.query.filter_by(scan_id=scan.id, analysis_type='deduplication').all()
        assert len(analyses) == 1
        assert analyses[0].confidence_score == 0.9
        data = json.loads(analyses[0].result)
        assert data['original_finding_id'] == findings[0].id
        assert data['duplicate_finding_id'] == findings[1].id

    def test_different_url_not_duplicate(self, db):
        scan, findings = _setup_scan_with_findings(db, [
            {'title': 'XSS on /search', 'url': 'http://ex.com/search', 'category': 'xss'},
            {'title': 'XSS on /login', 'url': 'http://ex.com/login', 'category': 'xss'},
        ])
        service = AIService()
        result = service.deduplicate_findings(scan.id)
        assert result['duplicates_found'] == 0

    def test_different_category_not_duplicate(self, db):
        scan, findings = _setup_scan_with_findings(db, [
            {'title': 'XSS on /search', 'url': 'http://ex.com/search', 'category': 'xss'},
            {'title': 'SQLi on /search', 'url': 'http://ex.com/search', 'category': 'sqli'},
        ])
        service = AIService()
        result = service.deduplicate_findings(scan.id)
        assert result['duplicates_found'] == 0


# ── Severity Suggestion ─────────────────────────────────────────────────────

class TestSuggestSeverities:
    def test_no_findings(self, db):
        user = _create_user(db)
        project = _create_project(db, user)
        target = _create_target(db, project)
        scan = _create_scan(db, user, target)
        service = AIService()
        result = service.suggest_severities(scan.id)
        assert result['suggestions_made'] == 0

    def test_suggest_cvss_for_xss(self, db):
        scan, _ = _setup_scan_with_findings(db, [
            {'title': 'XSS on /search', 'category': 'xss', 'severity': 'high'},
        ])
        service = AIService()
        result = service.suggest_severities(scan.id)
        assert result['suggestions_made'] == 1
        analysis = AIAnalysisResult.query.filter_by(scan_id=scan.id, analysis_type='severity_suggestion').first()
        data = json.loads(analysis.result)
        assert data['category'] == 'xss'
        assert data['suggested_cvss'] == 6.1

    def test_suggest_cvss_for_sqli(self, db):
        scan, _ = _setup_scan_with_findings(db, [
            {'title': 'SQLi on /login', 'category': 'sqli', 'severity': 'critical'},
        ])
        service = AIService()
        result = service.suggest_severities(scan.id)
        assert result['suggestions_made'] == 1
        analysis = AIAnalysisResult.query.filter_by(scan_id=scan.id, analysis_type='severity_suggestion').first()
        data = json.loads(analysis.result)
        assert data['suggested_cvss'] == 9.8

    def test_skip_if_cvss_already_set(self, db):
        scan, _ = _setup_scan_with_findings(db, [
            {'title': 'XSS', 'category': 'xss', 'severity': 'high', 'cvss_score': 6.5},
        ])
        service = AIService()
        result = service.suggest_severities(scan.id)
        assert result['suggestions_made'] == 0

    def test_exploit_evidence_increases_cvss(self, db):
        scan, _ = _setup_scan_with_findings(db, [
            {'title': 'XSS', 'category': 'xss', 'severity': 'medium',
             'evidence': 'payload reflected in response, script executed'},
        ])
        service = AIService()
        service.suggest_severities(scan.id)
        analysis = AIAnalysisResult.query.filter_by(scan_id=scan.id, analysis_type='severity_suggestion').first()
        data = json.loads(analysis.result)
        assert data['suggested_cvss'] == 7.1

    def test_mitigation_evidence_decreases_cvss(self, db):
        scan, _ = _setup_scan_with_findings(db, [
            {'title': 'XSS', 'category': 'xss', 'severity': 'high',
             'evidence': 'waf blocked the payload'},
        ])
        service = AIService()
        service.suggest_severities(scan.id)
        analysis = AIAnalysisResult.query.filter_by(scan_id=scan.id, analysis_type='severity_suggestion').first()
        data = json.loads(analysis.result)
        assert data['suggested_cvss'] == 4.6

    def test_recon_category_suggests_info(self, db):
        scan, _ = _setup_scan_with_findings(db, [
            {'title': 'Subdomain found', 'category': 'subdomain', 'severity': 'info'},
        ])
        service = AIService()
        service.suggest_severities(scan.id)
        analysis = AIAnalysisResult.query.filter_by(scan_id=scan.id, analysis_type='severity_suggestion').first()
        data = json.loads(analysis.result)
        assert data['suggested_cvss'] == 0.0
        assert data['suggested_severity'] == 'info'


# ── False Positive Detection ────────────────────────────────────────────────

class TestDetectFalsePositives:
    def test_no_findings(self, db):
        user = _create_user(db)
        project = _create_project(db, user)
        target = _create_target(db, project)
        scan = _create_scan(db, user, target)
        service = AIService()
        result = service.detect_false_positives(scan.id)
        assert result['potential_fps'] == 0

    def test_xss_no_reflection_detected(self, db):
        scan, _ = _setup_scan_with_findings(db, [
            {'title': 'XSS', 'category': 'xss', 'severity': 'high',
             'evidence': 'parameter not reflected in response'},
        ])
        service = AIService()
        result = service.detect_false_positives(scan.id)
        assert result['potential_fps'] == 1
        analysis = AIAnalysisResult.query.filter_by(scan_id=scan.id, analysis_type='false_positive').first()
        data = json.loads(analysis.result)
        assert data['category'] == 'xss'
        assert data['fp_score'] > 0

    def test_sqli_generic_error_only(self, db):
        scan, _ = _setup_scan_with_findings(db, [
            {'title': 'SQLi', 'category': 'sqli', 'severity': 'high',
             'evidence': 'internal server error 500'},
        ])
        service = AIService()
        result = service.detect_false_positives(scan.id)
        assert result['potential_fps'] >= 1

    def test_sqli_specific_error_not_fp(self, db):
        scan, _ = _setup_scan_with_findings(db, [
            {'title': 'SQLi', 'category': 'sqli', 'severity': 'high',
             'evidence': 'sql syntax error mysql union select information_schema',
             'confidence': 'certain'},
        ])
        service = AIService()
        result = service.detect_false_positives(scan.id)
        assert result['potential_fps'] == 0

    def test_tentative_no_evidence_fp(self, db):
        scan, _ = _setup_scan_with_findings(db, [
            {'title': 'Possible vuln', 'category': 'xss', 'severity': 'medium',
             'confidence': 'tentative', 'evidence': None},
        ])
        service = AIService()
        result = service.detect_false_positives(scan.id)
        assert result['potential_fps'] == 1

    def test_already_flagged_fp_skipped(self, db):
        scan, _ = _setup_scan_with_findings(db, [
            {'title': 'XSS', 'category': 'xss', 'severity': 'high',
             'is_false_positive': True},
        ])
        service = AIService()
        result = service.detect_false_positives(scan.id)
        assert result['potential_fps'] == 0

    def test_legitimate_finding_not_fp(self, db):
        scan, _ = _setup_scan_with_findings(db, [
            {'title': 'Confirmed XSS', 'category': 'xss', 'severity': 'high',
             'confidence': 'certain', 'evidence': 'payload reflected, script executed',
             'payload': '<script>alert(1)</script>'},
        ])
        service = AIService()
        result = service.detect_false_positives(scan.id)
        assert result['potential_fps'] == 0


# ── Recommendations ─────────────────────────────────────────────────────────

class TestGenerateRecommendations:
    def test_no_findings(self, db):
        user = _create_user(db)
        project = _create_project(db, user)
        target = _create_target(db, project)
        scan = _create_scan(db, user, target)
        service = AIService()
        result = service.generate_recommendations(scan.id)
        assert result['recommendations_generated'] == 0

    def test_critical_finding_gets_recommendation(self, db):
        scan, _ = _setup_scan_with_findings(db, [
            {'title': 'RCE', 'category': 'rce', 'severity': 'critical'},
        ])
        service = AIService()
        result = service.generate_recommendations(scan.id)
        assert result['recommendations_generated'] == 1
        analysis = AIAnalysisResult.query.filter_by(scan_id=scan.id, analysis_type='recommendation').first()
        data = json.loads(analysis.result)
        assert data['recommendation_type'] == 'manual_verification'
        assert data['severity'] == 'critical'

    def test_high_finding_gets_recommendation(self, db):
        scan, _ = _setup_scan_with_findings(db, [
            {'title': 'SQLi', 'category': 'sqli', 'severity': 'high'},
        ])
        service = AIService()
        result = service.generate_recommendations(scan.id)
        assert result['recommendations_generated'] == 1

    def test_medium_finding_gets_recommendation(self, db):
        scan, _ = _setup_scan_with_findings(db, [
            {'title': 'Info Disclosure', 'category': 'info_disclosure', 'severity': 'medium'},
        ])
        service = AIService()
        result = service.generate_recommendations(scan.id)
        assert result['recommendations_generated'] == 1

    def test_recon_finding_gets_recommendation(self, db):
        scan, _ = _setup_scan_with_findings(db, [
            {'title': 'Subdomain found', 'category': 'subdomain', 'severity': 'info'},
        ])
        service = AIService()
        result = service.generate_recommendations(scan.id)
        assert result['recommendations_generated'] == 1
        analysis = AIAnalysisResult.query.filter_by(scan_id=scan.id, analysis_type='recommendation').first()
        data = json.loads(analysis.result)
        assert data['recommendation_type'] == 'follow_up_testing'

    def test_duplicate_finding_skipped(self, db):
        scan, _ = _setup_scan_with_findings(db, [
            {'title': 'XSS', 'category': 'xss', 'severity': 'high', 'is_duplicate': True},
        ])
        service = AIService()
        result = service.generate_recommendations(scan.id)
        assert result['recommendations_generated'] == 0

    def test_fp_finding_skipped(self, db):
        scan, _ = _setup_scan_with_findings(db, [
            {'title': 'XSS', 'category': 'xss', 'severity': 'high', 'is_false_positive': True},
        ])
        service = AIService()
        result = service.generate_recommendations(scan.id)
        assert result['recommendations_generated'] == 0

    def test_low_severity_without_recon_category_no_recommendation(self, db):
        scan, _ = _setup_scan_with_findings(db, [
            {'title': 'Cookie flag', 'category': 'cookie', 'severity': 'low'},
        ])
        service = AIService()
        result = service.generate_recommendations(scan.id)
        assert result['recommendations_generated'] == 0


# ── Full analyze_scan ───────────────────────────────────────────────────────

class TestAnalyzeScan:
    def test_analyze_scan_not_found(self, db):
        service = AIService()
        result = service.analyze_scan(99999)
        assert result['success'] is False
        assert 'Scan not found' in result['errors']

    def test_analyze_scan_full(self, db):
        scan, _ = _setup_scan_with_findings(db, [
            {'title': 'XSS on /search', 'url': 'http://ex.com/search', 'category': 'xss',
             'severity': 'high', 'confidence': 'certain',
             'evidence': 'payload reflected in response'},
            {'title': 'XSS /search dup', 'url': 'http://ex.com/search', 'category': 'xss',
             'severity': 'medium', 'confidence': 'tentative',
             'evidence': 'parameter not reflected'},
        ])
        service = AIService()
        result = service.analyze_scan(scan.id)
        assert result['success'] is True
        assert result['duplicates_found'] >= 1
        assert result['severity_suggestions'] >= 1
        assert result['recommendations_generated'] >= 1


# ── Review / Accept/Reject ──────────────────────────────────────────────────

class TestReviewFinding:
    def test_review_finding_not_found(self, db):
        service = AIService()
        result = service.review_finding(99999, 'deduplication', True)
        assert result['success'] is False

    def test_accept_deduplication(self, db):
        scan, findings = _setup_scan_with_findings(db, [
            {'title': 'XSS A', 'url': 'http://ex.com/search', 'category': 'xss',
             'confidence': 'certain', 'severity': 'high'},
            {'title': 'XSS B', 'url': 'http://ex.com/search', 'category': 'xss',
             'confidence': 'tentative', 'severity': 'medium'},
        ])
        service = AIService()
        service.deduplicate_findings(scan.id)
        result = service.review_finding(findings[1].id, 'deduplication', True)
        assert result['success'] is True
        db.session.expire_all()
        dup = Finding.query.get(findings[1].id)
        assert dup.is_duplicate is True

    def test_reject_false_positive(self, db):
        scan, findings = _setup_scan_with_findings(db, [
            {'title': 'XSS', 'category': 'xss', 'severity': 'high',
             'confidence': 'tentative', 'evidence': None},
        ])
        service = AIService()
        service.detect_false_positives(scan.id)
        result = service.review_finding(findings[0].id, 'false_positive', False)
        assert result['success'] is True
        analysis = AIAnalysisResult.query.filter_by(finding_id=findings[0].id, analysis_type='false_positive').first()
        assert analysis.is_accepted is False

    def test_accept_severity_suggestion(self, db):
        scan, findings = _setup_scan_with_findings(db, [
            {'title': 'XSS', 'category': 'xss', 'severity': 'medium'},
        ])
        service = AIService()
        service.suggest_severities(scan.id)
        result = service.review_finding(findings[0].id, 'severity_suggestion', True)
        assert result['success'] is True
        db.session.expire_all()
        f = Finding.query.get(findings[0].id)
        assert f.severity != 'medium' or f.cvss_score is not None

    def test_accept_false_positive_marks_finding(self, db):
        scan, findings = _setup_scan_with_findings(db, [
            {'title': 'XSS', 'category': 'xss', 'severity': 'high',
             'confidence': 'tentative', 'evidence': None},
        ])
        service = AIService()
        service.detect_false_positives(scan.id)
        result = service.review_finding(findings[0].id, 'false_positive', True)
        assert result['success'] is True
        db.session.expire_all()
        f = Finding.query.get(findings[0].id)
        assert f.is_false_positive is True

    def test_no_pending_analysis(self, db):
        scan, findings = _setup_scan_with_findings(db, [
            {'title': 'XSS', 'category': 'xss', 'severity': 'high',
             'confidence': 'certain', 'evidence': 'payload reflected',
             'cvss_score': 7.5},
        ])
        service = AIService()
        result = service.review_finding(findings[0].id, 'deduplication', True)
        assert result['success'] is False


# ── Get Analysis Results ────────────────────────────────────────────────────

class TestGetAnalysisResults:
    def test_get_results_empty(self, db):
        user = _create_user(db)
        project = _create_project(db, user)
        target = _create_target(db, project)
        scan = _create_scan(db, user, target)
        service = AIService()
        results = service.get_analysis_results(scan.id)
        assert len(results) == 0

    def test_get_results_filtered_by_type(self, db):
        scan, _ = _setup_scan_with_findings(db, [
            {'title': 'XSS', 'category': 'xss', 'severity': 'high'},
        ])
        service = AIService()
        service.suggest_severities(scan.id)
        results = service.get_analysis_results(scan.id, analysis_type='severity_suggestion')
        assert len(results) == 1
        assert results[0].analysis_type == 'severity_suggestion'
        results = service.get_analysis_results(scan.id, analysis_type='deduplication')
        assert len(results) == 0
