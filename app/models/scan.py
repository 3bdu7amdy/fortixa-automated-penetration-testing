"""Scan model - a single execution of tools against a target."""
from datetime import datetime, timezone
from app.extensions import db
from app.models.base import BaseModel


class Scan(BaseModel):
    """Scan model.

    A scan groups multiple ScanJobs together. Each scan targets
    one target with a specific configuration.
    """
    __tablename__ = 'scans'

    target_id = db.Column(db.Integer, db.ForeignKey('targets.id'), nullable=True, index=True)
    manual_target = db.Column(db.String(255), nullable=True)  # For ad-hoc targets without DB record
    manual_target_type = db.Column(db.String(20), nullable=True)  # domain, ip, url, cidr
    initiated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending', index=True)
    scan_type = db.Column(db.String(30), nullable=False)  # recon, vuln, full
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    total_jobs = db.Column(db.Integer, nullable=False, default=0)
    completed_jobs = db.Column(db.Integer, nullable=False, default=0)
    failed_jobs = db.Column(db.Integer, nullable=False, default=0)
    config_id = db.Column(db.Integer, db.ForeignKey('configurations.id'), nullable=True)

    # ── Pipeline mode fields ───────────────────────────────────────
    # When True, this scan is part of a multi-phase pipeline (1→2→3a→3b→4)
    pipeline_mode = db.Column(db.Boolean, nullable=False, default=False, index=True)
    # Current phase: 1, 2, 3, 4 (3a & 3b share phase 3)
    current_phase = db.Column(db.Integer, nullable=False, default=0)
    # If this is a sub-scan, the ID of the parent pipeline scan
    pipeline_scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=True)

    @property
    def target_value(self):
        """Get the target value string (from DB target or manual input)."""
        if self.target_id:
            return self.target.value if self.target else 'unknown'
        return self.manual_target or 'unknown'

    @property
    def target_type_value(self):
        """Get the target type (from DB target or manual input)."""
        if self.target_id and self.target:
            return self.target.type
        return self.manual_target_type or 'url'

    # Relationships
    jobs = db.relationship('ScanJob', backref='scan', lazy='dynamic')
    findings = db.relationship('Finding', backref='scan', lazy='dynamic')
    reports = db.relationship('Report', backref='scan', lazy='dynamic')

    def update_progress(self):
        """Update scan progress based on job statuses."""
        from app.models.scan_job import ScanJob
        self.total_jobs = self.jobs.count()
        self.completed_jobs = self.jobs.filter_by(status='completed').count()
        self.failed_jobs = self.jobs.filter(ScanJob.status.in_(['failed', 'timeout'])).count()

        running = self.jobs.filter_by(status='running').count()
        queued = self.jobs.filter_by(status='queued').count()

        # Transition: pending → running (when first job starts or completes)
        if self.status == 'pending' and (running > 0 or self.completed_jobs > 0 or self.failed_jobs > 0):
            self.status = 'running'
            self.started_at = datetime.now(timezone.utc).replace(tzinfo=None)

        # Transition: running → completed/failed (when no more running or queued jobs)
        # NOTE: For pipeline scans, don't auto-complete here. The pipeline
        # service is responsible for marking the scan as completed when the
        # final phase finishes. Auto-completing early would prevent later
        # phases from being enqueued.
        if self.status == 'running' and running == 0 and queued == 0:
            if getattr(self, 'pipeline_mode', False):
                # Pipeline scans are advanced by pipeline_service.advance_pipeline()
                # which will either enqueue the next phase's jobs or mark the
                # scan as completed when phase 4 is done.
                pass
            else:
                if self.failed_jobs > 0 and self.completed_jobs == 0:
                    self.status = 'failed'
                else:
                    self.status = 'completed'
                self.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)

        self.save()

    @property
    def progress_percentage(self):
        """Calculate scan progress as a percentage."""
        if self.total_jobs == 0:
            return 0
        return int((self.completed_jobs + self.failed_jobs) / self.total_jobs * 100)

    # ── Pipeline / Tab helper methods ────────────────────────────────

    def get_subdomains(self):
        """Return all subdomain findings for this scan (deduped by title)."""
        from app.models.finding import Finding
        rows = Finding.query.filter_by(
            scan_id=self.id, vuln_category='Subdomain', is_duplicate=False
        ).filter(
            db.or_(Finding.is_false_positive == False,
                   Finding.is_false_positive.is_(None))
        ).all()
        seen = set()
        out = []
        for r in rows:
            # Extract the subdomain from the title (e.g. "Subdomain discovered: x.example.com")
            sub = r.description.replace('Subfinder discovered subdomain:', '').strip() if r.description else ''
            if not sub:
                sub = r.title.replace('Subdomain discovered:', '').strip()
            if sub and sub not in seen:
                seen.add(sub)
                out.append({
                    'subdomain': sub,
                    'title': getattr(r, '_http_title', None),
                    'status_code': getattr(r, '_http_status', None),
                    'source': r.tool_name,
                })
        return out

    def get_urls(self):
        """Return all URL findings for this scan (deduped)."""
        from app.models.finding import Finding
        rows = Finding.query.filter_by(
            scan_id=self.id, vuln_category='URL', is_duplicate=False
        ).filter(
            db.or_(Finding.is_false_positive == False,
                   Finding.is_false_positive.is_(None))
        ).all()
        seen = set()
        out = []
        for r in rows:
            url = r.url or r.title
            if url and url not in seen:
                seen.add(url)
                has_params = '?' in url and '=' in url
                out.append({
                    'url': url,
                    'has_parameters': has_params,
                    'source': r.tool_name,
                })
        return out

    def get_vulnerabilities_grouped(self):
        """Return vulnerabilities grouped by vuln_category.

        Deduplicates findings by (title, normalized_url) so the same finding
        from the same URL doesn't appear multiple times. URL normalization
        strips trailing slashes, default ports (:80/:443), and lowercases
        the scheme+host so that ``https://x.com`` and ``https://x.com/``
        and ``https://x.com:443`` are treated as the same URL.

        Returns:
            Dict: {vuln_category: [{finding}, ...], ...}
            Only includes actual vulnerabilities (not recon categories).
        """
        from app.models.finding import Finding
        from app.utils.vuln_categories import is_vulnerability_category

        rows = Finding.query.filter_by(
            scan_id=self.id, is_duplicate=False
        ).filter(
            db.or_(Finding.is_false_positive == False,
                   Finding.is_false_positive.is_(None))
        ).order_by(Finding.severity).all()

        def _norm_url(u):
            if not u:
                return ''
            u = str(u).strip()
            if '://' not in u:
                return u  # not a URL, return as-is
            scheme, rest = u.split('://', 1)
            scheme = scheme.lower()
            if '/' in rest:
                host_part, path_part = rest.split('/', 1)
            else:
                host_part = rest
                path_part = ''
            if host_part.endswith(':80'):
                host_part = host_part[:-3]
            elif host_part.endswith(':443'):
                host_part = host_part[:-4]
            host_part = host_part.lower()
            path_part = path_part.rstrip('/')
            if path_part:
                return f'{scheme}://{host_part}/{path_part}'
            return f'{scheme}://{host_part}'

        grouped = {}
        seen_keys = set()  # For deduplication

        for r in rows:
            cat = r.vuln_category or 'Other'
            if not is_vulnerability_category(cat):
                continue

            # Create a unique key for deduplication (title + normalized url)
            dedup_key = (r.title, _norm_url(r.url))
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            grouped.setdefault(cat, []).append({
                'id': r.id,
                'title': r.title,
                'severity': r.severity,
                'tool_name': r.tool_name,
                'url': r.url,
                'description': r.description,
                'evidence': r.evidence,
                'remediation': r.remediation,
                'cvss_score': r.cvss_score,
                'cve_id': r.cve_id,
            })
        return grouped

    def get_overview_stats(self):
        """Return an overview stats dict for the Overview tab."""
        from app.models.finding import Finding
        from app.utils.vuln_categories import is_vulnerability_category

        all_findings = Finding.query.filter_by(scan_id=self.id, is_duplicate=False).filter(
            db.or_(Finding.is_false_positive == False,
                   Finding.is_false_positive.is_(None))
        ).all()

        subdomains_count = 0
        urls_count = 0
        vuln_count = 0
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

        seen_subs = set()
        seen_urls = set()

        for f in all_findings:
            cat = f.vuln_category or 'Other'
            if cat == 'Subdomain':
                sub = (f.description or '').replace('Subfinder discovered subdomain:', '').strip()
                if sub and sub not in seen_subs:
                    seen_subs.add(sub)
                    subdomains_count += 1
            elif cat == 'URL':
                url = f.url or f.title
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    urls_count += 1
            elif is_vulnerability_category(cat):
                vuln_count += 1
                sev = (f.severity or 'info').lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1
                else:
                    severity_counts['info'] += 1

        return {
            'subdomains_count': subdomains_count,
            'urls_count': urls_count,
            'vulnerabilities_count': vuln_count,
            'total_findings': len(all_findings),
            'severity_counts': severity_counts,
        }

    def __repr__(self):
        return f'<Scan {self.name} [{self.status}]>'
