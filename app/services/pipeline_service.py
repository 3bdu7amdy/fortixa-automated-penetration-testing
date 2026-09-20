"""Pipeline Service - orchestrates multi-phase pentest scans.

Implements the workflow:
    Phase 1: assetfinder + subfinder + amass  → subdomains.txt (anew merge)
    Phase 2: httpx                              → live_hosts.txt
    Phase 3a: waybackurls + gau + katana        → all_urls.txt → params_urls.txt
    Phase 3b: host-based checks (parallel with 3a)
    Phase 4: injection scanners on params_urls.txt

The pipeline runs as a series of sub-scans. After each phase completes the
worker triggers `advance_pipeline()` which inspects the produced text files
and enqueues the next phase's jobs.
"""
import json
import logging
import os
import shutil
import threading
from datetime import datetime, timezone

from app.extensions import db
from app.models.scan import Scan
from app.models.scan_job import ScanJob
from app.models.finding import Finding
from app.plugins.registry import tool_registry

logger = logging.getLogger(__name__)


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ── Tool groupings per phase (simplified to most important tools) ─────────
# Phase 1: Subdomain discovery (only subfinder - the most reliable)
PHASE1_TOOLS = ['subfinder']
# Phase 2: HTTP probing (only httpx)
PHASE2_TOOLS = ['httpx']
# Phase 3a: URL gathering (only waybackurls - the most comprehensive)
PHASE3A_TOOLS = ['waybackurls']
# Phase 3b: Host-based checks - 8 most important categories
PHASE3B_TOOLS = [
    'ssl_issues',           # SSL/TLS analysis (testssl)
    'waf_detection',        # WAF detection (wafw00f)
    'subdomain_takeover',   # Subdomain takeover (subzy)
    'security_headers',     # Security headers (nuclei)
    'clickjacking',         # Clickjacking (nuclei)
    'cves',                 # Known CVEs (nuclei)
    'admin_panels',         # Admin panels exposure (nuclei)
    'default_credentials',  # Default credentials (nuclei)
]
# Phase 4: Injection scans - 7 most important injection categories
PHASE4_TOOLS = [
    'xss',               # XSS (dalfox)
    'sqli',              # SQL Injection (sqlmap)
    'ssti',              # Server-Side Template Injection (tplmap)
    'command_injection', # OS Command Injection (commix)
    'lfi',               # Local File Inclusion / Path Traversal (dotdotpwn)
    'ssrf_nuclei',       # SSRF (nuclei)
    'open_redirect',     # Open Redirect (openredirex)
]


class PipelineService:
    """Manages multi-phase pipeline scans."""

    # ── Phase orchestration ────────────────────────────────────────

    def start_pipeline(self, scan_id, config_id=None):
        """Kick off Phase 1 for a pipeline scan.

        Creates ScanJobs for each Phase-1 tool, all targeting the root
        domain.  Each tool writes its raw output to a per-tool file under
        ``output/<target>/phase1_subdomains/``.

        Args:
            scan_id: The scan ID.
            config_id: Optional config ID. If provided, only tools enabled
                       in this config will run in each phase.
        """
        scan = db.session.get(Scan, scan_id)
        if scan is None:
            logger.error("Pipeline start: scan %s not found", scan_id)
            return {'success': False, 'errors': ['Scan not found']}

        target_value = scan.target_value
        output_base = self._phase_dir(scan_id, 1)

        # Mark the scan as pipeline mode + phase 1
        scan.pipeline_mode = True
        scan.current_phase = 1
        scan.status = 'running'
        scan.started_at = _utcnow()
        scan.save()

        # Determine which tools to run in this phase
        phase1_tools = self._filter_tools_by_config(PHASE1_TOOLS, config_id)

        created_jobs = []
        for tool_name in phase1_tools:
            binary = tool_registry.get_tool_binary(tool_name)
            if not shutil.which(binary):
                logger.warning("Pipeline P1: %s not installed, skipping", tool_name)
                continue
            tool_options = {
                'flags': self._default_flags(tool_name),
                'timeout': 600,
                'phase': 1,
                'output_filename': f'{tool_name}.txt',
            }
            job = ScanJob(
                scan_id=scan.id,
                tool_name=tool_name,
                command=f"{binary} {target_value}",
                timeout_seconds=600,
                output_dir=output_base,
                tool_options=json.dumps(tool_options),
            )
            job.save()
            created_jobs.append(job.id)

        scan.total_jobs = scan.jobs.count()
        scan.save()

        if not created_jobs:
            scan.status = 'failed'
            scan.completed_at = _utcnow()
            scan.save()
            return {'success': False, 'errors': ['No Phase-1 tools available']}

        # Enqueue all created jobs (the worker will pick them up)
        from app.engine.task_queue import TaskQueue
        queue = TaskQueue()
        for jid in created_jobs:
            queue.enqueue(jid)

        logger.info("Pipeline started for scan %s (Phase 1, %d jobs, config=%s)",
                    scan_id, len(created_jobs), config_id)
        return {'success': True, 'phase': 1, 'jobs': created_jobs}

    def _filter_tools_by_config(self, phase_tools, config_id):
        """Filter a list of phase tools by what's enabled in the config.

        If config_id is None or no config is found, returns the full list.
        """
        if not config_id:
            return list(phase_tools)

        from app.models.configuration import Configuration
        config = db.session.get(Configuration, config_id)
        if not config:
            return list(phase_tools)

        enabled = set(config.get_enabled_tools())
        # Also include tools whose binary is enabled (e.g. 'xss' → 'dalfox')
        # by checking both the vuln_key and the binary name
        for tool_name in list(enabled):
            binary = tool_registry.get_tool_binary(tool_name)
            enabled.add(binary)

        filtered = [t for t in phase_tools if t in enabled]
        # If filter is too aggressive (config doesn't include any Phase 1 tools),
        # fall back to the full list so the pipeline can still proceed
        if not filtered:
            return list(phase_tools)
        return filtered

    def advance_pipeline(self, scan_id):
        """Inspect the current phase and enqueue the next one if ready.

        Called by the worker after each job completes (only for pipeline scans).
        Uses an in-memory lock to prevent concurrent advances from multiple
        worker threads (which would create duplicate phase jobs).
        """
        scan = db.session.get(Scan, scan_id)
        if scan is None or not scan.pipeline_mode:
            return None

        # ── Phase-completion lock ────────────────────────────────────
        # Use a per-scan lock to prevent two worker threads from advancing
        # the same scan at the same time (which would create duplicate jobs).
        lock = self._get_scan_lock(scan_id)
        if not lock.acquire(blocking=False):
            # Another thread is already advancing this scan
            return None
        try:
            # Re-fetch scan under lock to get fresh state
            db.session.expire(scan)
            scan = db.session.get(Scan, scan_id)
            if scan is None or scan.status in ('completed', 'failed', 'cancelled'):
                return None

            # Don't advance until all current-phase jobs are finished
            running = scan.jobs.filter(ScanJob.status.in_(['queued', 'running'])).count()
            if running > 0:
                return None

            phase = scan.current_phase

            if phase == 1:
                return self._advance_to_phase2(scan)
            elif phase == 2:
                return self._advance_to_phase3(scan)
            elif phase == 3:
                return self._advance_to_phase4(scan)
            elif phase == 4:
                # Pipeline complete
                scan.status = 'completed'
                scan.completed_at = _utcnow()
                scan.save()
                logger.info("Pipeline scan %s completed", scan_id)
                return {'phase': 'done'}
            return None
        finally:
            lock.release()

    def _get_scan_lock(self, scan_id):
        """Return (or create) a threading.Lock for a given scan ID."""
        if not hasattr(self, '_scan_locks'):
            self._scan_locks = {}
        if scan_id not in self._scan_locks:
            self._scan_locks[scan_id] = threading.Lock()
        return self._scan_locks[scan_id]

    # ── Phase transitions ──────────────────────────────────────────

    def _advance_to_phase2(self, scan):
        """Merge Phase-1 outputs → subdomains.txt, then enqueue httpx."""
        phase1_dir = self._phase_dir(scan.id, 1)
        subdomains_file = os.path.join(phase1_dir, 'subdomains.txt')
        # Merge all Phase-1 tool outputs (subfinder.txt, assetfinder.txt, amass.txt)
        phase1_output_files = [f'{t}.txt' for t in PHASE1_TOOLS]
        self._merge_unique(phase1_dir, phase1_output_files, subdomains_file)

        if not os.path.exists(subdomains_file) or os.path.getsize(subdomains_file) == 0:
            scan.status = 'failed'
            scan.completed_at = _utcnow()
            scan.save()
            logger.warning("Pipeline P1 produced no subdomains for scan %s", scan.id)
            return {'phase': 'failed', 'reason': 'no subdomains'}

        phase2_dir = self._phase_dir(scan.id, 2)
        tool_options = {
            'flags': ['-l', subdomains_file, '-status-code', '-title', '-tech-detect',
                      '-o', os.path.join(phase2_dir, 'live_hosts.txt')],
            'timeout': 600,
            'phase': 2,
            'input_file': subdomains_file,
            'output_filename': 'live_hosts.txt',
        }
        job = ScanJob(
            scan_id=scan.id,
            tool_name='httpx',
            command=f"httpx -l {subdomains_file}",
            timeout_seconds=600,
            output_dir=phase2_dir,
            tool_options=json.dumps(tool_options),
        )
        job.save()

        scan.current_phase = 2
        scan.total_jobs = scan.jobs.count()
        scan.save()

        from app.engine.task_queue import TaskQueue
        TaskQueue().enqueue(job.id)

        logger.info("Pipeline scan %s advanced to Phase 2 (httpx)", scan.id)
        return {'phase': 2}

    def _advance_to_phase3(self, scan):
        """Parse httpx output → live_hosts.txt, then enqueue Phase 3a + 3b in parallel."""
        phase2_dir = self._phase_dir(scan.id, 2)
        live_file = os.path.join(phase2_dir, 'live_hosts.txt')

        # If httpx didn't write its file, try to derive from its stdout
        if not os.path.exists(live_file):
            httpx_job = scan.jobs.filter_by(tool_name='httpx').first()
            if httpx_job and httpx_job.stdout_path and os.path.exists(httpx_job.stdout_path):
                with open(httpx_job.stdout_path) as f:
                    lines = [l.strip() for l in f if l.strip()]
                with open(live_file, 'w') as f:
                    f.write('\n'.join(lines))

        # Fallback: if httpx didn't run or failed, use subdomains.txt as live_hosts
        if not os.path.exists(live_file) or os.path.getsize(live_file) == 0:
            phase1_dir = self._phase_dir(scan.id, 1)
            subdomains_file = os.path.join(phase1_dir, 'subdomains.txt')
            if os.path.exists(subdomains_file):
                with open(subdomains_file) as f:
                    subs = [l.strip() for l in f if l.strip()]
                # Convert bare subdomains to https:// URLs
                hosts = [f"https://{s}" for s in subs]
                with open(live_file, 'w') as f:
                    f.write('\n'.join(hosts))
                logger.info("Pipeline scan %s: using subdomains.txt as live_hosts fallback", scan.id)

        # Deduplicate live_hosts.txt (httpx may output the same host twice if
        # subdomains.txt had duplicates that slipped through)
        if os.path.exists(live_file):
            seen = set()
            deduped = []
            with open(live_file) as f:
                for line in f:
                    line = line.strip()
                    if line and line not in seen:
                        seen.add(line)
                        deduped.append(line)
            with open(live_file, 'w') as f:
                f.write('\n'.join(deduped))

        if not os.path.exists(live_file) or os.path.getsize(live_file) == 0:
            scan.status = 'failed'
            scan.completed_at = _utcnow()
            scan.save()
            return {'phase': 'failed', 'reason': 'no live hosts'}

        phase3a_dir = self._phase_dir(scan.id, '3a')
        phase3b_dir = self._phase_dir(scan.id, '3b')

        created_jobs = []

        # Filter tools by config if applicable
        phase3a_tools = self._filter_tools_by_config(PHASE3A_TOOLS, scan.config_id)
        phase3b_tools = self._filter_tools_by_config(PHASE3B_TOOLS, scan.config_id)

        # Phase 3a: URL gathering - one job per tool, each reading live_hosts.txt
        for tool_name in phase3a_tools:
            binary = tool_registry.get_tool_binary(tool_name)
            if not shutil.which(binary):
                continue
            tool_options = {
                'flags': self._default_flags(tool_name),
                'timeout': 600,
                'phase': '3a',
                'input_file': live_file,
                'output_filename': f'{tool_name}.txt',
            }
            job = ScanJob(
                scan_id=scan.id,
                tool_name=tool_name,
                command=f"{binary} (live_hosts)",
                timeout_seconds=600,
                output_dir=phase3a_dir,
                tool_options=json.dumps(tool_options),
            )
            job.save()
            created_jobs.append(job.id)

        # Phase 3b: host-based checks - one job per tool
        for tool_name in phase3b_tools:
            binary = tool_registry.get_tool_binary(tool_name)
            if not shutil.which(binary):
                continue
            tool_options = {
                'flags': self._default_flags(tool_name),
                'timeout': 600,
                'phase': '3b',
                'input_file': live_file,
                'output_filename': f'{tool_name}.txt',
            }
            job = ScanJob(
                scan_id=scan.id,
                tool_name=tool_name,
                command=f"{binary} (live_hosts)",
                timeout_seconds=600,
                output_dir=phase3b_dir,
                tool_options=json.dumps(tool_options),
            )
            job.save()
            created_jobs.append(job.id)

        scan.current_phase = 3
        scan.total_jobs = scan.jobs.count()
        scan.save()

        # If no Phase-3 tools are available, advance to Phase 4 immediately
        if not created_jobs:
            logger.info("Pipeline scan %s: no Phase-3 jobs, advancing to Phase 4", scan.id)
            return self._advance_to_phase4(scan)

        from app.engine.task_queue import TaskQueue
        queue = TaskQueue()
        for jid in created_jobs:
            queue.enqueue(jid)

        logger.info("Pipeline scan %s advanced to Phase 3 (%d jobs)",
                    scan.id, len(created_jobs))
        return {'phase': 3}

    def _advance_to_phase4(self, scan):
        """Merge Phase-3a outputs → all_urls.txt → filter params_urls.txt,
        then enqueue injection scanners on params_urls.txt."""
        phase3a_dir = self._phase_dir(scan.id, '3a')
        all_urls_file = os.path.join(phase3a_dir, 'all_urls.txt')
        params_file = os.path.join(phase3a_dir, 'params_urls.txt')

        # Merge + dedupe all Phase-3a tool outputs
        phase3a_output_files = [f'{t}.txt' for t in PHASE3A_TOOLS]
        self._merge_unique(phase3a_dir,
                           phase3a_output_files,
                           all_urls_file)

        # Filter only URLs containing parameters (?...=...)
        self._filter_parameterized(all_urls_file, params_file)

        if not os.path.exists(params_file) or os.path.getsize(params_file) == 0:
            logger.info("Pipeline scan %s: no parameterized URLs - skipping Phase 4",
                        scan.id)
            scan.status = 'completed'
            scan.completed_at = _utcnow()
            scan.current_phase = 4
            scan.save()
            return {'phase': 'skipped', 'reason': 'no parameterized URLs'}

        phase4_dir = self._phase_dir(scan.id, 4)
        created_jobs = []

        phase4_tools = self._filter_tools_by_config(PHASE4_TOOLS, scan.config_id)
        for tool_name in phase4_tools:
            binary = tool_registry.get_tool_binary(tool_name)
            if not shutil.which(binary):
                continue
            tool_options = {
                'flags': self._default_flags(tool_name),
                'timeout': 1200,
                'phase': 4,
                'input_file': params_file,
                'output_filename': f'{tool_name}.txt',
            }
            job = ScanJob(
                scan_id=scan.id,
                tool_name=tool_name,
                command=f"{binary} (params_urls)",
                timeout_seconds=1200,
                output_dir=phase4_dir,
                tool_options=json.dumps(tool_options),
            )
            job.save()
            created_jobs.append(job.id)

        scan.current_phase = 4
        scan.total_jobs = scan.jobs.count()
        scan.save()

        # If no Phase-4 tools are available (or no parameterized URLs), mark
        # the pipeline as completed immediately - there's nothing more to run.
        if not created_jobs:
            scan.status = 'completed'
            scan.completed_at = _utcnow()
            scan.save()
            logger.info("Pipeline scan %s completed (no Phase-4 jobs to run)", scan.id)
            return {'phase': 'done', 'reason': 'no phase-4 jobs'}

        from app.engine.task_queue import TaskQueue
        queue = TaskQueue()
        for jid in created_jobs:
            queue.enqueue(jid)

        logger.info("Pipeline scan %s advanced to Phase 4 (%d jobs)",
                    scan.id, len(created_jobs))
        return {'phase': 4}

    # ── File helpers ───────────────────────────────────────────────

    def _phase_dir(self, scan_id, phase):
        """Return (and create) the output directory for a phase."""
        scan = db.session.get(Scan, scan_id)
        target = scan.target_value if scan else 'unknown'
        safe_target = ''.join(c if c.isalnum() or c in '-.' else '_' for c in str(target))
        names = {1: 'phase1_subdomains', 2: 'phase2_httpx',
                 '3a': 'phase3a_urls', '3b': 'phase3b_host_checks',
                 4: 'phase4_injection'}
        dirname = names.get(phase, f'phase{phase}')
        path = os.path.abspath(os.path.join('output', safe_target, dirname))
        os.makedirs(path, exist_ok=True)
        return path

    def _merge_unique(self, directory, filenames, output_file):
        """Concatenate files and dedupe lines (anew-style)."""
        seen = set()
        out_lines = []
        for fname in filenames:
            fpath = os.path.join(directory, fname)
            if not os.path.exists(fpath):
                continue
            try:
                with open(fpath, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line and line not in seen:
                            seen.add(line)
                            out_lines.append(line)
            except OSError as exc:
                logger.warning("Failed reading %s: %s", fpath, exc)
        try:
            with open(output_file, 'w') as f:
                f.write('\n'.join(out_lines))
                if out_lines:
                    f.write('\n')
        except OSError as exc:
            logger.error("Failed writing merged file %s: %s", output_file, exc)

    def _filter_parameterized(self, input_file, output_file):
        """Keep only lines containing both '?' and '=' (URL parameters)."""
        if not os.path.exists(input_file):
            return
        out_lines = []
        try:
            with open(input_file, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and '?' in line and '=' in line:
                        out_lines.append(line)
            with open(output_file, 'w') as f:
                f.write('\n'.join(out_lines))
                if out_lines:
                    f.write('\n')
        except OSError as exc:
            logger.error("Failed filtering %s: %s", input_file, exc)

    def _default_flags(self, tool_name):
        """Sensible default flags per tool for pipeline use."""
        defaults = {
            'assetfinder': ['--subs-only'],
            'subfinder': ['-all', '-recursive'],
            'amass': ['enum'],
            'httpx': ['-status-code', '-title', '-tech-detect'],
            'waybackurls': [],
            'gau': [],
            'katana': ['-jc', '-d', '5'],
            'sqlmap': ['--batch', '--random-agent'],
        }
        return defaults.get(tool_name, [])


# Module-level singleton
pipeline_service = PipelineService()
