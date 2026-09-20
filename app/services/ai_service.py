"""AI service - handles AI analysis business logic using rule-based heuristics."""
import json
import logging
from collections import defaultdict

from app.extensions import db
from app.models.finding import Finding
from app.models.ai_analysis_result import AIAnalysisResult
from app.models.scan import Scan

logger = logging.getLogger(__name__)


# ── Severity / CVSS mapping tables ──────────────────────────────────────────

CATEGORY_CVSS_DEFAULTS = {
    'xss': 6.1,
    'sqli': 9.8,
    'ssrf': 7.5,
    'rce': 9.9,
    'lfi': 7.5,
    'rfi': 8.6,
    'xxe': 7.5,
    'csrf': 4.3,
    'open_redirect': 3.4,
    'info_disclosure': 5.3,
    'misconfig': 5.0,
    'broken_auth': 7.5,
    'sensitive_data': 6.5,
    'subdomain': 0.0,
    'live_host': 0.0,
    'url': 0.0,
    'port': 0.0,
    'header': 0.0,
    'ssl': 3.7,
    'cookie': 4.3,
    'cors': 4.3,
    'clickjacking': 2.4,
}

CVSS_SEVERITY_MAP = [
    (9.0, 'critical'),
    (7.0, 'high'),
    (4.0, 'medium'),
    (0.1, 'low'),
    (0.0, 'info'),
]

# Patterns that suggest a finding is a false positive
FP_PATTERNS = {
    'xss': {
        'no_reflection_markers': [
            'no reflection', 'parameter not reflected',
            'response unchanged', 'mirrored input not found',
        ],
        'generic_evidence': [
            'timeout', 'connection refused',
        ],
    },
    'sqli': {
        'generic_error_only': [
            'internal server error', '500', '403 forbidden',
            '401 unauthorized', '404 not found',
        ],
        'no_injection_evidence': [
            'no injection', 'parameter not injectable',
            'not vulnerable',
        ],
    },
}

# Tools considered less reliable for certain categories
LOW_CONFIDENCE_TOOLS = {
    'xss': {'generic_scanner', 'web_fuzzer'},
    'sqli': {'generic_scanner', 'web_fuzzer'},
}

# Recommendation templates by severity
RECOMMENDATION_TEMPLATES = {
    'critical': {
        'title': 'Manual Verification Required - Critical Finding',
        'template': (
            'Critical finding "{title}" detected by {tool_name} on {url}. '
            'This requires immediate manual verification by a senior pentester. '
            'Validate the exploit chain end-to-end and document proof of concept.'
        ),
    },
    'high': {
        'title': 'Manual Verification Recommended - High Finding',
        'template': (
            'High severity finding "{title}" detected by {tool_name} on {url}. '
            'Manual verification recommended to confirm exploitability. '
            'Test with real-world attack scenarios.'
        ),
    },
    'medium': {
        'title': 'Further Testing Suggested - Medium Finding',
        'template': (
            'Medium severity finding "{title}" detected by {tool_name} on {url}. '
            'Consider additional manual testing to assess the full impact. '
            'Review the evidence and test for privilege escalation potential.'
        ),
    },
}

# Recon-specific recommendations
RECON_RECOMMENDATIONS = {
    'subdomain': (
        'New subdomains discovered. Recommended next steps: '
        'probe each subdomain for live hosts, test for subdomain takeover, '
        'and perform port scanning on discovered hosts.'
    ),
    'live_host': (
        'Live hosts identified. Recommended next steps: '
        'perform directory brute-forcing, test for common vulnerabilities, '
        'and fingerprint technologies and versions.'
    ),
    'url': (
        'URLs discovered. Recommended next steps: '
        'test identified parameters for injection, '
        'check for authentication bypass on restricted paths, '
        'and look for sensitive file exposure.'
    ),
    'port': (
        'Open ports detected. Recommended next steps: '
        'service version fingerprinting, default credential testing, '
        'and known-CVE lookup for identified services.'
    ),
}


def _cvss_to_severity(cvss_score):
    """Convert a CVSS score to a severity label."""
    for threshold, label in CVSS_SEVERITY_MAP:
        if cvss_score >= threshold:
            return label
    return 'info'


class AIService:
    """AI-powered analysis of scan findings using rule-based heuristics.

    All analysis is performed locally without external AI/ML APIs.
    """

    # ── Orchestration ────────────────────────────────────────────────────

    def analyze_scan(self, scan_id):
        """Run all analysis steps on a completed scan.

        Returns a summary dict with counts for each analysis type.
        """
        scan = db.session.get(Scan, scan_id)
        if not scan:
            return {'success': False, 'errors': ['Scan not found']}

        logger.info("AI analysis started for scan %s", scan_id)

        dedup_result = self.deduplicate_findings(scan_id)
        severity_result = self.suggest_severities(scan_id)
        fp_result = self.detect_false_positives(scan_id)
        rec_result = self.generate_recommendations(scan_id)

        summary = {
            'success': True,
            'scan_id': scan_id,
            'duplicates_found': dedup_result.get('duplicates_found', 0),
            'severity_suggestions': severity_result.get('suggestions_made', 0),
            'potential_false_positives': fp_result.get('potential_fps', 0),
            'recommendations_generated': rec_result.get('recommendations_generated', 0),
        }

        logger.info("AI analysis completed for scan %s: %s", scan_id, summary)
        return summary

    # ── Deduplication ────────────────────────────────────────────────────

    def deduplicate_findings(self, scan_id):
        """Find and mark duplicate findings based on URL + category + tool.

        For each group of findings sharing the same (url, category):
          - Keep the one with the highest confidence as original
          - Mark others as is_duplicate=True, set duplicate_of_id
          - Create an AIAnalysisResult with type='deduplication'

        Returns dict with count of duplicates found.
        """
        findings = Finding.query.filter_by(scan_id=scan_id, is_duplicate=False).all()
        if not findings:
            return {'duplicates_found': 0}

        # Confidence ranking for sorting
        CONFIDENCE_ORDER = {'certain': 5, 'firm': 4, 'tentative': 3}

        # Group by (url, category)
        groups = defaultdict(list)
        for f in findings:
            key = (f.url or '', f.category)
            groups[key].append(f)

        duplicates_found = 0

        for key, group in groups.items():
            if len(group) <= 1:
                continue

            # Sort: best finding first (highest confidence, most severe)
            group.sort(
                key=lambda f: (
                    -CONFIDENCE_ORDER.get(f.confidence, 0),
                    Finding.SEVERITY_ORDER.get(f.severity, 99),
                ),
            )

            original = group[0]

            for duplicate in group[1:]:
                duplicate.is_duplicate = True
                duplicate.duplicate_of_id = original.id

                result_data = json.dumps({
                    'duplicate_finding_id': duplicate.id,
                    'original_finding_id': original.id,
                    'url': duplicate.url,
                    'category': duplicate.category,
                    'original_title': original.title,
                    'duplicate_title': duplicate.title,
                })

                self._create_analysis_result(
                    finding_id=duplicate.id,
                    scan_id=scan_id,
                    analysis_type='deduplication',
                    result=result_data,
                    confidence_score=0.9,
                    reasoning=(
                        f"Finding duplicates original (ID {original.id}) "
                        f"based on same URL '{duplicate.url or ''}' "
                        f"and category '{duplicate.category}'."
                    ),
                )
                duplicates_found += 1

        db.session.commit()
        return {'duplicates_found': duplicates_found}

    # ── Severity Suggestion ──────────────────────────────────────────────

    def suggest_severities(self, scan_id):
        """Suggest severity adjustments based on CVSS, exploitability, and context.

        For each finding without a CVSS score, assign a suggested CVSS based on
        category. Adjust based on evidence content. Create an AIAnalysisResult
        with type='severity_suggestion'.

        Returns dict with count of suggestions made.
        """
        findings = Finding.query.filter_by(scan_id=scan_id).all()
        if not findings:
            return {'suggestions_made': 0}

        suggestions_made = 0

        for finding in findings:
            # Only suggest if the finding doesn't already have a CVSS score
            if finding.cvss_score is not None:
                continue

            # Determine suggested CVSS based on category
            suggested_cvss = CATEGORY_CVSS_DEFAULTS.get(finding.category, 3.0)

            # Adjust based on evidence content
            evidence = (finding.evidence or '').lower()
            if evidence:
                # Evidence of exploitability → increase score
                exploit_markers = [
                    'executed', 'exploit', 'shell', 'command executed',
                    'payload reflected', 'database error', 'sql syntax',
                ]
                for marker in exploit_markers:
                    if marker in evidence:
                        suggested_cvss = min(suggested_cvss + 1.0, 10.0)
                        break

                # Evidence of mitigations → decrease score
                mitigation_markers = [
                    'waf blocked', 'filtered', 'sanitized',
                    'input validation', 'blocked by',
                ]
                for marker in mitigation_markers:
                    if marker in evidence:
                        suggested_cvss = max(suggested_cvss - 1.5, 0.0)
                        break

            suggested_severity = _cvss_to_severity(suggested_cvss)

            # Only create a suggestion if it differs from current severity
            if suggested_severity == finding.severity and finding.cvss_score is not None:
                continue

            result_data = json.dumps({
                'current_severity': finding.severity,
                'suggested_severity': suggested_severity,
                'suggested_cvss': round(suggested_cvss, 1),
                'category': finding.category,
                'changed': suggested_severity != finding.severity,
            })

            confidence = 0.7
            if finding.evidence:
                confidence = 0.8

            self._create_analysis_result(
                finding_id=finding.id,
                scan_id=scan_id,
                analysis_type='severity_suggestion',
                result=result_data,
                confidence_score=confidence,
                reasoning=(
                    f"Based on category '{finding.category}', suggested CVSS "
                    f"{suggested_cvss:.1f} → severity '{suggested_severity}'. "
                    f"Current severity is '{finding.severity}'."
                    + (" Evidence-based adjustment applied." if finding.evidence else "")
                ),
            )
            suggestions_made += 1

        db.session.commit()
        return {'suggestions_made': suggestions_made}

    # ── False Positive Detection ─────────────────────────────────────────

    def detect_false_positives(self, scan_id):
        """Detect likely false positives using rule-based heuristics.

        Rules:
          - XSS findings without actual payload reflection → likely FP
          - SQLi findings with generic error messages only → likely FP
          - Findings from low-confidence tools → lower confidence
          - Duplicate findings already marked as FP → FP

        Returns dict with count of potential FPs.
        """
        findings = Finding.query.filter_by(scan_id=scan_id).all()
        if not findings:
            return {'potential_fps': 0}

        potential_fps = 0

        for finding in findings:
            fp_score = 0.0  # 0 = not FP, 1.0 = definitely FP
            reasons = []

            # Rule 1: Already marked as FP
            if finding.is_false_positive:
                continue  # Skip already flagged ones

            # Rule 2: Check category-specific FP patterns
            evidence = (finding.evidence or '').lower()
            category = finding.category

            if category in FP_PATTERNS:
                patterns = FP_PATTERNS[category]

                # Check for no-reflection / no-injection evidence
                no_evidence_key = (
                    'no_reflection_markers' if category == 'xss'
                    else 'no_injection_evidence'
                )
                for marker in patterns.get(no_evidence_key, []):
                    if marker in evidence:
                        fp_score += 0.5
                        reasons.append(
                            f"Evidence contains '{marker}' suggesting no real vulnerability"
                        )
                        break

                # Check for generic error only
                generic_key = 'generic_error_only'
                if category == 'sqli':
                    is_generic_only = True
                    specific_markers = [
                        'sql syntax', 'mysql', 'postgresql', 'oracle',
                        'union select', 'information_schema', 'table_name',
                    ]
                    for marker in specific_markers:
                        if marker in evidence:
                            is_generic_only = False
                            break
                    if is_generic_only:
                        for marker in patterns.get(generic_key, []):
                            if marker in evidence:
                                fp_score += 0.4
                                reasons.append(
                                    f"Only generic error '{marker}' found, no SQL-specific indicators"
                                )
                                break

            # Rule 3: Low-confidence tool for this category
            if category in LOW_CONFIDENCE_TOOLS:
                if finding.tool_name in LOW_CONFIDENCE_TOOLS[category]:
                    fp_score += 0.2
                    reasons.append(
                        f"Tool '{finding.tool_name}' has low confidence for {category} findings"
                    )

            # Rule 4: Finding with 'tentative' confidence and no evidence
            if finding.confidence == 'tentative' and not finding.evidence:
                fp_score += 0.5
                reasons.append("Tentative confidence with no evidence provided")

            # Rule 5: XSS with payload but no evidence of reflection
            if category == 'xss' and finding.payload:
                payload_lower = (finding.payload or '').lower()
                if payload_lower not in evidence and evidence:
                    fp_score += 0.3
                    reasons.append(
                        "Payload not found reflected in evidence"
                    )

            # Only flag as potential FP if score exceeds threshold
            if fp_score >= 0.4:
                result_data = json.dumps({
                    'fp_score': round(fp_score, 2),
                    'reasons': reasons,
                    'category': finding.category,
                    'tool_name': finding.tool_name,
                    'recommendation': (
                        'Review this finding manually to confirm or reject '
                        'the false positive suggestion.'
                    ),
                })

                self._create_analysis_result(
                    finding_id=finding.id,
                    scan_id=scan_id,
                    analysis_type='false_positive',
                    result=result_data,
                    confidence_score=round(min(fp_score, 1.0), 2),
                    reasoning='; '.join(reasons) if reasons else 'No specific reason identified.',
                )
                potential_fps += 1

        db.session.commit()
        return {'potential_fps': potential_fps}

    # ── Recommendations ──────────────────────────────────────────────────

    def generate_recommendations(self, scan_id):
        """Generate manual testing recommendations based on findings.

        - For critical/high findings: recommend manual verification
        - For recon findings: recommend specific test paths
        - Create AIAnalysisResult with type='recommendation'

        Returns dict with count of recommendations generated.
        """
        findings = Finding.query.filter_by(scan_id=scan_id, is_duplicate=False)\
            .filter(db.or_(Finding.is_false_positive == False, Finding.is_false_positive.is_(None))).all()
        if not findings:
            return {'recommendations_generated': 0}

        recommendations_generated = 0

        for finding in findings:
            # Critical / High → manual verification recommendation
            if finding.severity in ('critical', 'high', 'medium'):
                template_info = RECOMMENDATION_TEMPLATES.get(finding.severity, {})
                template = template_info.get('template', 'Review finding {title}.')
                recommendation_text = template.format(
                    title=finding.title,
                    tool_name=finding.tool_name,
                    url=finding.url or 'N/A',
                )

                result_data = json.dumps({
                    'recommendation_type': 'manual_verification',
                    'severity': finding.severity,
                    'title': finding.title,
                    'category': finding.category,
                    'recommendation': recommendation_text,
                })

                confidence = 0.9 if finding.severity == 'critical' else 0.8

                self._create_analysis_result(
                    finding_id=finding.id,
                    scan_id=scan_id,
                    analysis_type='recommendation',
                    result=result_data,
                    confidence_score=confidence,
                    reasoning=(
                        f"{finding.severity.capitalize()} severity finding in "
                        f"category '{finding.category}' warrants manual review."
                    ),
                )
                recommendations_generated += 1

            # Recon categories → specific next-step recommendation
            elif finding.category in RECON_RECOMMENDATIONS:
                recommendation_text = RECON_RECOMMENDATIONS[finding.category]

                result_data = json.dumps({
                    'recommendation_type': 'follow_up_testing',
                    'category': finding.category,
                    'title': finding.title,
                    'recommendation': recommendation_text,
                })

                self._create_analysis_result(
                    finding_id=finding.id,
                    scan_id=scan_id,
                    analysis_type='recommendation',
                    result=result_data,
                    confidence_score=0.7,
                    reasoning=(
                        f"Recon finding in category '{finding.category}' "
                        f"suggests follow-up testing paths."
                    ),
                )
                recommendations_generated += 1

        db.session.commit()
        return {'recommendations_generated': recommendations_generated}

    # ── Helper ───────────────────────────────────────────────────────────

    def _create_analysis_result(self, finding_id, scan_id, analysis_type,
                                result, confidence_score=None, reasoning=None):
        """Create an AIAnalysisResult record."""
        analysis = AIAnalysisResult(
            finding_id=finding_id,
            scan_id=scan_id,
            analysis_type=analysis_type,
            result=result,
            confidence_score=confidence_score,
            reasoning=reasoning,
        )
        db.session.add(analysis)
        return analysis

    # ── Query helpers ────────────────────────────────────────────────────

    def get_analysis_results(self, scan_id, analysis_type=None):
        """Get AI analysis results for a scan, optionally filtered by type."""
        query = AIAnalysisResult.query.filter_by(scan_id=scan_id)
        if analysis_type:
            query = query.filter_by(analysis_type=analysis_type)
        return query.order_by(AIAnalysisResult.created_at.desc()).all()

    def review_finding(self, finding_id, analysis_type, accept):
        """Accept or reject an AI suggestion for a finding.

        Args:
            finding_id: The finding ID.
            analysis_type: The analysis type to review.
            accept: True to accept, False to reject.

        Returns dict with success status.
        """
        finding = db.session.get(Finding, finding_id)
        if not finding:
            return {'success': False, 'errors': ['Finding not found']}

        analysis = AIAnalysisResult.query.filter_by(
            finding_id=finding_id, analysis_type=analysis_type,
            is_accepted=None,
        ).first()
        if not analysis:
            return {'success': False, 'errors': ['No pending analysis found for this finding and type']}

        analysis.is_accepted = accept

        # Apply the suggestion if accepted
        if accept:
            result_data = json.loads(analysis.result)

            if analysis_type == 'deduplication':
                finding.is_duplicate = True
                finding.duplicate_of_id = result_data.get('original_finding_id')

            elif analysis_type == 'severity_suggestion':
                suggested = result_data.get('suggested_severity')
                suggested_cvss = result_data.get('suggested_cvss')
                if suggested:
                    finding.severity = suggested
                if suggested_cvss is not None:
                    finding.cvss_score = suggested_cvss

            elif analysis_type == 'false_positive':
                finding.is_false_positive = True

            # 'recommendation' type: no automatic change, just mark accepted

        db.session.commit()
        return {'success': True}
