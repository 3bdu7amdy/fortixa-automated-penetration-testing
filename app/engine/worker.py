"""Background worker that executes scan jobs from the task queue."""
import json
import logging
import os
import shutil
import threading
import time
from datetime import datetime, timezone

from flask import has_app_context

from app.engine.task_queue import TaskQueue
from app.extensions import db
from app.models.scan import Scan
from app.models.scan_job import ScanJob
from app.models.finding import Finding
from app.models.tool_output import ToolOutput
from app.models.execution_log import ExecutionLog
from app.services.scan_service import ScanService
from app.plugins.registry import tool_registry

logger = logging.getLogger(__name__)


def _utcnow():
    """Return current UTC time as a naive datetime (SQLite-compatible)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Worker:
    """Background worker that polls the task queue and executes scan jobs.

    Runs in a daemon thread. Uses Flask app context for all DB operations.
    Supports graceful shutdown and concurrent job execution up to
    MAX_CONCURRENT_JOBS.
    """

    POLL_INTERVAL = 5          # seconds between queue polls
    MAX_CONCURRENT_JOBS = 2    # maximum parallel job threads
    # Only retry on timeout (-1). All other exit codes are considered final.
    # Security tools return various exit codes (1, 2, 244) for different
    # reasons and retrying doesn't help - it just wastes time.
    RETRYABLE_EXIT_CODES = [-1]
    NON_RETRYABLE_PATTERNS = [
        'command not found',
        'no such file',
        'permission denied',
    ]

    def __init__(self, app):
        """Initialise the worker.

        Args:
            app: Flask application instance (used for app context).
        """
        self.app = app
        self._queue = TaskQueue()
        self._running = False
        self._thread = None
        self._lock = threading.Lock()
        self._running_jobs: dict = {}   # {job_id: thread}
        self._stop_event = threading.Event()

    # ── Public API ─────────────────────────────────────────────────────

    def start(self):
        """Start the worker in a daemon thread."""
        if self._running:
            logger.warning("Worker is already running.")
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info("Worker started.")

    def stop(self, graceful=True):
        """Stop the worker.

        Args:
            graceful: If True, wait for running jobs to finish.
                     If False, set stop event and return immediately.
        """
        if not self._running:
            return
        self._running = False
        self._stop_event.set()
        logger.info("Worker stop requested (graceful=%s).", graceful)

        if graceful and self._thread is not None:
            # Wait for the main loop to exit
            self._thread.join(timeout=60)
            # Wait for any still-running job threads
            for job_id, t in list(self._running_jobs.items()):
                t.join(timeout=30)
                logger.info("Job thread %s joined.", job_id)
        logger.info("Worker stopped.")

    def get_status(self):
        """Return a dict describing current worker state."""
        with self._lock:
            running_job_ids = list(self._running_jobs.keys())
        with self.app.app_context():
            queued_count = self._queue.get_queued_count()
        return {
            'is_running': self._running,
            'running_jobs': running_job_ids,
            'running_count': len(running_job_ids),
            'queued_count': queued_count,
            'max_concurrent_jobs': self.MAX_CONCURRENT_JOBS,
            'poll_interval': self.POLL_INTERVAL,
        }

    # ── Internal ───────────────────────────────────────────────────────

    def _run_loop(self):
        """Main loop: poll the queue and start jobs when capacity allows."""
        logger.info("Worker loop started.")
        while not self._stop_event.is_set():
            try:
                with self.app.app_context():
                    self._poll_and_dispatch()
            except Exception as exc:
                logger.error("Error in worker loop: %s", exc, exc_info=True)

            self._stop_event.wait(self.POLL_INTERVAL)

        logger.info("Worker loop exited.")

    def _poll_and_dispatch(self):
        """Check for queued jobs and start them if capacity allows."""
        # Clean up finished job threads
        with self._lock:
            finished = [
                jid for jid, t in self._running_jobs.items() if not t.is_alive()
            ]
            for jid in finished:
                del self._running_jobs[jid]

        # Check capacity
        with self._lock:
            current_count = len(self._running_jobs)

        while current_count < self.MAX_CONCURRENT_JOBS:
            job = self._queue.dequeue()
            if job is None:
                break

            # Re-check capacity under lock
            with self._lock:
                if len(self._running_jobs) >= self.MAX_CONCURRENT_JOBS:
                    break

            self._start_job(job)
            with self._lock:
                current_count = len(self._running_jobs)

    def _start_job(self, job):
        """Start a job in a new thread.

        Args:
            job: ScanJob instance to execute.
        """
        self._queue.mark_running(job.id)

        t = threading.Thread(
            target=self._execute_job,
            args=(job.id,),
            daemon=True,
            name=f"worker-job-{job.id}",
        )
        with self._lock:
            self._running_jobs[job.id] = t
        t.start()
        logger.info("Job %d (%s) started in thread %s.", job.id, job.tool_name, t.name)

    def _resolve_runner(self, vuln_key):
        """Resolve a vuln key (e.g. 'xss', 'sqli') to a runner instance.

        Steps:
        1. Try a direct lookup in TOOL_RUNNERS (for recon tools where
           key == binary name).
        2. Resolve the binary name via tool_registry.get_tool_binary()
           and look that up in TOOL_RUNNERS.
        3. Return None if no runner is found.

        Args:
            vuln_key: The tool_name stored in the ScanJob (may be a vuln
                      name or a recon tool name).

        Returns:
            A BaseToolRunner instance, or None.
        """
        tool_runners = ScanService.TOOL_RUNNERS

        # 1. Direct lookup (recon tools: subfinder, httpx, etc.)
        runner_cls = tool_runners.get(vuln_key)
        if runner_cls is not None:
            return runner_cls() if callable(runner_cls) else runner_cls

        # 2. Resolve via registry (vuln tools: xss→dalfox, sqli→sqlmap, etc.)
        binary = tool_registry.get_tool_binary(vuln_key)
        runner_cls = tool_runners.get(binary)
        if runner_cls is not None:
            return runner_cls() if callable(runner_cls) else runner_cls

        return None

    def _get_tool_options(self, job):
        """Extract stored tool options from the job's tool_options field.

        The scan_service stores a JSON string of tool options in the
        tool_options column at job creation time.

        Args:
            job: ScanJob instance.

        Returns:
            Dict of tool options, or empty dict.
        """
        return job.get_tool_options()

    def _execute_job(self, job_id):
        """Execute a single scan job.

        Steps:
        1. Look up the tool runner.
        2. Run the tool.
        3. Store findings and tool output in the DB.
        4. Update scan progress.
        5. Handle retries on failure.

        Args:
            job_id: Primary key of the ScanJob to execute.
        """
        # If there's already an active app context (e.g. in tests calling
        # this method directly), reuse it.  Otherwise push a fresh one
        # (normal case when called from a daemon thread).
        if has_app_context():
            self._do_execute_job(job_id)
        else:
            with self.app.app_context():
                self._do_execute_job(job_id)

    def _do_execute_job(self, job_id):
        """Internal implementation of job execution (must run inside app context)."""
        job = db.session.get(ScanJob, job_id)
        if job is None:
            logger.error("Job %d not found during execution.", job_id)
            return

        scan = db.session.get(Scan, job.scan_id)
        if scan is None:
            logger.error("Scan for job %d not found.", job_id)
            return

        # Log execution start
        self._log(job_id, 'INFO', f'Starting execution of {job.tool_name}')

        # Check if scan was cancelled
        if scan.status == 'cancelled':
            self._queue.mark_failed(job_id, 'Scan was cancelled')
            self._log(job_id, 'WARNING', 'Skipped - scan was cancelled')
            return

        # Look up runner – resolve vuln key to actual tool binary runner
        runner = self._resolve_runner(job.tool_name)

        if runner is None:
            # Try a fallback: run the command directly as a subprocess
            binary = tool_registry.get_tool_binary(job.tool_name)
            msg = f"No runner registered for tool '{job.tool_name}' (binary: {binary})"
            logger.warning(msg)

            # Fallback to generic command execution
            from app.plugins.base import BaseToolRunner

            class GenericRunner(BaseToolRunner):
                tool_name = binary or job.tool_name

                def build_command(self, target, options):
                    if not self.validate_target(target):
                        raise ValueError(f"Invalid target: {target}")
                    # Build command from stored flags and target
                    flags = options.get('flags', [])
                    cmd = [self.tool_name] + flags + [target]
                    return cmd

                def parse_output(self, stdout, stderr, output_dir):
                    # Generic parsing – treat each line as an info finding
                    findings = []
                    output_files = []
                    for line in stdout.strip().splitlines():
                        line = line.strip()
                        if line:
                            findings.append({
                                'category': self.tool_name,
                                'severity': 'info',
                                'title': f'{self.tool_name} output',
                                'description': line,
                                'tool': self.tool_name,
                            })
                    return {
                        'findings': findings,
                        'output_files': output_files,
                        'stats': {},
                    }

            runner = GenericRunner()
            self._log(job_id, 'INFO', f'Using generic runner for {job.tool_name}')

        # Build target string from scan -> target or manual target
        target = None
        target_value = None
        if scan.target_id:
            from app.models.target import Target
            target = db.session.get(Target, scan.target_id)
            if target is None:
                msg = f"Target {scan.target_id} not found"
                self._queue.mark_failed(job_id, msg)
                self._log(job_id, 'ERROR', msg)
                scan.update_progress()
                return
            target_value = target.value
        elif scan.manual_target:
            target_value = scan.manual_target
        else:
            msg = "Scan has no target (neither target_id nor manual_target)"
            self._queue.mark_failed(job_id, msg)
            self._log(job_id, 'ERROR', msg)
            scan.update_progress()
            return

        # Get stored tool options
        tool_options = self._get_tool_options(job)

        # ── Pipeline mode: bypass the regular runner and run via flags ──
        if 'phase' in tool_options:
            result = self._execute_pipeline_job(job, scan, tool_options, job_id)
        else:
            # Check if the tool binary is still available before executing
            binary = tool_registry.get_tool_binary(job.tool_name)
            if not shutil.which(binary):
                msg = f"Tool binary '{binary}' is not installed on this system. Please install it to run this scan."
                self._queue.mark_failed(job_id, msg)
                self._log(job_id, 'ERROR', msg)
                scan.update_progress()
                return

            # Execute the tool
            output_dir = job.output_dir or os.path.join(
                'output', str(target_value), job.tool_name
            )
            options = {
                'timeout': job.timeout_seconds,
                'output_dir': output_dir,
            }
            # Merge stored tool options (includes auth_cookie if provided)
            options.update(tool_options)

            # Extract auth cookie for tools that support it
            auth_cookie = tool_options.get('auth_cookie')

            self._log(job_id, 'INFO', f'Running {job.tool_name} against {target_value}'
                      + (f' (with auth cookie)' if auth_cookie else ''))

            try:
                # Check if the runner supports stdin (e.g., waybackurls)
                stdin_input = None
                if hasattr(runner, 'get_stdin_input'):
                    stdin_input = runner.get_stdin_input(target_value)

                if stdin_input is not None:
                    # Use the base runner's run method but with stdin
                    result = self._run_with_stdin(runner, target_value, options, output_dir, stdin_input)
                else:
                    result = runner.run(
                        target=target_value,
                        options=options,
                        output_dir=output_dir,
                    )
            except Exception as exc:
                result = {
                    'exit_code': -1,
                    'error': str(exc),
                    'findings': [],
                    'output_files': [],
                    'stats': {},
                }
                self._log(job_id, 'ERROR', f'Runner exception: {exc}')

        # Store result
        exit_code = result.get('exit_code', -1)
        error = result.get('error')

        # Update job paths (only if they are real strings, not mock objects)
        stdout_path = result.get('stdout_path')
        stderr_path = result.get('stderr_path')
        if stdout_path and isinstance(stdout_path, str):
            job.stdout_path = stdout_path
        if stderr_path and isinstance(stderr_path, str):
            job.stderr_path = stderr_path
        db.session.commit()

        # Check for timeout
        if error and 'Timeout' in str(error):
            self._log(job_id, 'WARNING', f'Timeout after {job.timeout_seconds}s')
            if self._is_retryable(job, result):
                requeued = self._queue.increment_retry(job_id)
                if requeued:
                    self._log(job_id, 'INFO', f'Retry after timeout {job.retry_count}/{job.max_retries}.')
                else:
                    # Max retries exceeded – increment_retry already marked as failed
                    self._log(job_id, 'WARNING', 'Timeout retries exhausted.')
            else:
                self._queue.mark_timeout(job_id)
                self._log(job_id, 'WARNING', 'Timeout is non-retryable; marking as timeout.')
            scan.update_progress()
            return

        # Store findings (with DB-level deduplication)
        findings_data = result.get('findings', [])

        # Helper: normalize URL for dedup (must match the logic in
        # scan.py get_vulnerabilities_grouped and worker _norm_url)
        def _db_norm_url(u):
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

        # Pre-load existing (title, normalized_url) pairs for this scan to
        # avoid inserting duplicates that may have come from a different job
        # in the same scan (e.g. nuclei ran on the same host in two phases).
        existing_pairs = set()
        try:
            existing_findings = Finding.query.filter_by(
                scan_id=scan.id, is_duplicate=False
            ).with_entities(Finding.title, Finding.url).all()
            for t, u in existing_findings:
                existing_pairs.add((t or '', _db_norm_url(u)))
        except Exception:
            pass

        # Track pairs we're saving in THIS batch too (in case the same
        # (title, url) appears multiple times in findings_data).
        batch_pairs = set()

        saved_count = 0
        skipped_dup_count = 0
        for fdata in findings_data:
            # Map raw_data field → raw_output (DB column)
            raw_output = fdata.pop('raw_data', None) or fdata.pop('raw_output', None)
            # Convert dicts/lists to JSON string for DB storage
            if isinstance(raw_output, (dict, list)):
                raw_output = json.dumps(raw_output)
            elif raw_output is not None:
                raw_output = str(raw_output)
            # Remove 'tool' field (not a DB column for Finding)
            fdata.pop('tool', None)

            # Resolve unified vuln_category from tool_name + finding category
            from app.utils.vuln_categories import get_vuln_category
            fdata_category = fdata.get('category', job.tool_name)
            # Prefer explicit category from the runner; fall back to tool_name
            vuln_cat = get_vuln_category(fdata_category) or get_vuln_category(job.tool_name)

            finding_title = fdata.get('title', f'{job.tool_name} finding')
            finding_url = fdata.get('url')
            norm_url = _db_norm_url(finding_url)
            dedup_key = (finding_title, norm_url)

            # Skip if we've already saved an identical finding for this scan
            if dedup_key in existing_pairs or dedup_key in batch_pairs:
                skipped_dup_count += 1
                continue
            batch_pairs.add(dedup_key)

            finding = Finding(
                scan_id=scan.id,
                scan_job_id=job.id,
                target_id=target.id if target else None,
                project_id=target.project_id if target else None,
                title=finding_title,
                description=fdata.get('description'),
                severity=fdata.get('severity', 'info'),
                category=fdata.get('category', job.tool_name),
                tool_name=job.tool_name,
                vuln_category=vuln_cat,
                url=finding_url,
                parameter=fdata.get('parameter'),
                payload=fdata.get('payload'),
                evidence=fdata.get('evidence'),
                remediation=fdata.get('remediation'),
                confidence=fdata.get('confidence', 'tentative'),
                raw_output=raw_output,
                cvss_score=fdata.get('cvss_score'),
                cve_id=fdata.get('cve_id'),
            )
            db.session.add(finding)
            saved_count += 1

        if skipped_dup_count > 0:
            self._log(job_id, 'INFO',
                      f'Skipped {skipped_dup_count} duplicate finding(s) at DB save time.')

        # Store tool output references
        output_files = result.get('output_files', [])
        for fpath in output_files:
            if isinstance(fpath, str) and os.path.exists(fpath):
                file_size = os.path.getsize(fpath)
            else:
                file_size = None
            tool_output = ToolOutput(
                scan_job_id=job.id,
                output_type='raw',
                file_path=str(fpath) if fpath else '',
                file_size=file_size,
            )
            db.session.add(tool_output)

        # Also record stdout/stderr paths as tool outputs
        if stdout_path and isinstance(stdout_path, str):
            existing = ToolOutput.query.filter_by(
                scan_job_id=job.id,
                file_path=stdout_path
            ).first()
            if not existing:
                stdout_size = None
                if os.path.exists(stdout_path):
                    stdout_size = os.path.getsize(stdout_path)
                db.session.add(ToolOutput(
                    scan_job_id=job.id,
                    output_type='stdout',
                    file_path=stdout_path,
                    file_size=stdout_size,
                ))
        if stderr_path and isinstance(stderr_path, str):
            existing = ToolOutput.query.filter_by(
                scan_job_id=job.id,
                file_path=stderr_path
            ).first()
            if not existing:
                stderr_size = None
                if os.path.exists(stderr_path):
                    stderr_size = os.path.getsize(stderr_path)
                db.session.add(ToolOutput(
                    scan_job_id=job.id,
                    output_type='stderr',
                    file_path=stderr_path,
                    file_size=stderr_size,
                ))

        db.session.commit()

        # Handle success / failure
        # IMPORTANT: Security tools return non-zero exit codes for various
        # reasons that are NOT failures:
        # - nuclei returns 1 when scan completes (with or without findings)
        # - sqlmap returns 1 when injection is found
        # - testssl returns 244+ for various completion states
        # - wafw00f returns 2 when WAF is detected
        # - dalfox returns 1 when XSS is found
        # - commix returns 1 when injection is found
        #
        # The ONLY real failure is a timeout (exit code -1) or when the
        # tool binary is not found. Everything else means the tool ran
        # and completed its scan - 0 findings is NORMAL (target not vulnerable).
        is_real_error = (exit_code == -1 or  # timeout
                         (error and any(kw in str(error).lower() for kw in
                                        ['not found', 'not installed', 'no such file',
                                         'permission denied', 'timeout'])))

        if is_real_error:
            # Real error: tool didn't run properly
            error_msg = error or f'Exit code {exit_code}'
            self._queue.mark_failed(job_id, error_msg)
            self._log(job_id, 'WARNING',
                      f'Tool failed to run (exit={exit_code}). Error: {error_msg}')
        else:
            # Tool completed successfully (any exit code is fine).
            # 0 findings is normal - means target is not vulnerable to this check.
            self._queue.mark_completed(job_id, exit_code=exit_code)
            status_msg = f'Completed (exit={exit_code}). {len(findings_data)} findings.'
            if len(findings_data) == 0:
                status_msg += ' (no vulnerabilities found for this check - normal)'
            self._log(
                job_id, 'INFO',
                status_msg,
                details={'findings_count': len(findings_data), 'exit_code': exit_code},
            )

        # Update scan progress
        scan.update_progress()

        # ── Pipeline advancement ──────────────────────────────────
        # If this scan is a pipeline scan, try to advance to the next phase.
        # advance_pipeline() is a no-op if there are still running jobs.
        try:
            if getattr(scan, 'pipeline_mode', False):
                from app.services.pipeline_service import pipeline_service
                pipeline_service.advance_pipeline(scan.id)
        except Exception as exc:
            logger.error("Pipeline advancement failed for scan %s: %s",
                         scan.id, exc, exc_info=True)

    def _execute_pipeline_job(self, job, scan, tool_options, job_id):
        """Execute a pipeline job by running the binary directly with flags.

        Pipeline jobs don't use the regular tool runners (which assume a single
        target string). Instead, they build the command from the stored flags
        and either take the root domain (phase 1) or read from an input file
        (phases 2-4) and iterate over its lines.
        """
        import subprocess

        binary = tool_registry.get_tool_binary(job.tool_name)
        if not shutil.which(binary):
            # Try alternative names for testssl
            if binary == 'testssl':
                alt_names = ['testssl.sh', 'testssl']
                for alt in alt_names:
                    if shutil.which(alt):
                        binary = alt
                        break
                else:
                    return {
                        'exit_code': -1,
                        'error': f"Tool binary 'testssl' is not installed",
                        'findings': [], 'output_files': [], 'stats': {},
                    }
            else:
                return {
                    'exit_code': -1,
                    'error': f"Tool binary '{binary}' is not installed",
                    'findings': [], 'output_files': [], 'stats': {},
                }

        phase = tool_options.get('phase')
        flags = tool_options.get('flags', [])
        input_file = tool_options.get('input_file')
        output_filename = tool_options.get('output_filename', f'{job.tool_name}_output.txt')
        timeout = tool_options.get('timeout', job.timeout_seconds)

        # Resolve the output file path
        output_dir = job.output_dir or os.path.join('output', scan.target_value, f'phase{phase}')
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, output_filename)
        stdout_path = os.path.join(output_dir, f'{job.tool_name}_stdout.txt')
        stderr_path = os.path.join(output_dir, f'{job.tool_name}_stderr.txt')

        findings = []
        output_files = []
        exit_code = 0
        error = None

        # ── In-job dedup helpers (shared across all phases) ───────────
        # Prevents the same (title, normalized_url) from being added twice
        # within a single job. This catches duplicates caused by:
        #  - nuclei re-reading a stale output file across hosts
        #  - tools printing the same finding on multiple lines
        #  - phase 4 iterating over duplicate URLs
        job_seen_keys = set()

        def _norm_url(u):
            """Normalize a URL for dedup: strip trailing slash, default
            ports (:80/:443), and lowercase the scheme+host."""
            if not u:
                return ''
            u = str(u).strip()
            if '://' not in u:
                return u  # not a URL, return as-is
            scheme, rest = u.split('://', 1)
            scheme = scheme.lower()
            # Split host and path
            if '/' in rest:
                host_part, path_part = rest.split('/', 1)
            else:
                host_part = rest
                path_part = ''
            # Strip default ports from host
            if host_part.endswith(':80'):
                host_part = host_part[:-3]
            elif host_part.endswith(':443'):
                host_part = host_part[:-4]
            host_part = host_part.lower()
            # Strip trailing slash from path (but keep path content)
            path_part = path_part.rstrip('/')
            # Reassemble
            if path_part:
                return f'{scheme}://{host_part}/{path_part}'
            return f'{scheme}://{host_part}'

        def _add_finding_dedup(finding_dict):
            """Append finding to list only if (title, normalized_url)
            hasn't been seen yet in this job. Returns True if added."""
            key = (finding_dict.get('title', ''),
                   _norm_url(finding_dict.get('url')))
            if key in job_seen_keys:
                return False
            job_seen_keys.add(key)
            findings.append(finding_dict)
            return True

        try:
            if phase == 1:
                # Phase 1: target = root domain, build tool-specific command
                target_value = scan.manual_target or (scan.target.value if scan.target else '')
                if not target_value:
                    return {'exit_code': -1, 'error': 'No target',
                            'findings': [], 'output_files': [], 'stats': {}}

                # Build command with proper flags per tool
                if binary == 'subfinder':
                    # subfinder requires -d before the domain
                    cmd = [binary, '-d', target_value] + flags
                    cmd.extend(['-o', output_file])
                elif binary == 'assetfinder':
                    # assetfinder takes domain as positional arg
                    cmd = [binary] + flags + [target_value]
                    cmd.extend(['-o', output_file])
                elif binary == 'amass':
                    # amass requires 'enum -d' before the domain
                    cmd = [binary, 'enum', '-d', target_value] + flags
                    cmd.extend(['-o', output_file])
                else:
                    cmd = [binary] + flags + [target_value]

                self._log(job_id, 'INFO', f'P1: {" ".join(cmd)}')
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                exit_code = result.returncode

                with open(stdout_path, 'w') as f: f.write(result.stdout)
                with open(stderr_path, 'w') as f: f.write(result.stderr)

                # Read subdomains (from output file or stdout)
                subdomains = []
                if os.path.exists(output_file):
                    with open(output_file) as f:
                        subdomains = [l.strip() for l in f if l.strip()]
                else:
                    subdomains = [l.strip() for l in result.stdout.splitlines() if l.strip()]
                    # Save to output_file for downstream phases
                    with open(output_file, 'w') as f:
                        f.write('\n'.join(subdomains))

                if os.path.exists(output_file):
                    output_files.append(output_file)

                for sub in subdomains:
                    _add_finding_dedup({
                        'category': 'subdomain',
                        'severity': 'info',
                        'title': f'Subdomain discovered: {sub}',
                        'description': f'{job.tool_name} discovered subdomain: {sub}',
                        'raw_data': sub,
                    })

            elif phase == 2:
                # Phase 2: httpx reads input file via -l flag
                if not input_file or not os.path.exists(input_file):
                    return {'exit_code': -1, 'error': f'Input file {input_file} not found',
                            'findings': [], 'output_files': [], 'stats': {}}

                # Read subdomains from input file
                with open(input_file) as f:
                    subdomains = [l.strip() for l in f if l.strip()]

                # Build httpx command
                clean_flags = [f for f in flags if f != '-l' and f != input_file]
                cmd = [binary, '-l', input_file] + clean_flags
                if '-o' not in clean_flags:
                    cmd.extend(['-o', output_file])

                self._log(job_id, 'INFO', f'P2: {" ".join(cmd)}')
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                exit_code = result.returncode

                with open(stdout_path, 'w') as f: f.write(result.stdout)
                with open(stderr_path, 'w') as f: f.write(result.stderr)

                # Parse httpx output
                # CRITICAL: Only accept lines that start with http:// or https://
                # AND contain a valid domain (not error messages)
                live_hosts = []
                if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                    with open(output_file) as f:
                        for line in f:
                            line = line.strip()
                            # Must start with http:// or https://
                            if line and (line.startswith('http://') or line.startswith('https://')):
                                # Must contain a dot (valid domain check)
                                # Extract just the URL part (before any spaces)
                                url_part = line.split()[0] if ' ' in line else line
                                # Remove protocol for domain check
                                domain_part = url_part.replace('https://', '').replace('http://', '')
                                domain_part = domain_part.split('/')[0].split(':')[0]
                                if '.' in domain_part:
                                    live_hosts.append(url_part)

                # If output file empty/invalid, check stdout
                if not live_hosts:
                    for line in result.stdout.splitlines():
                        line = line.strip()
                        if line and (line.startswith('http://') or line.startswith('https://')):
                            url_part = line.split()[0] if ' ' in line else line
                            domain_part = url_part.replace('https://', '').replace('http://', '')
                            domain_part = domain_part.split('/')[0].split(':')[0]
                            if '.' in domain_part:
                                live_hosts.append(url_part)

                # If STILL no hosts, use subdomains directly (httpx might be broken)
                if not live_hosts and subdomains:
                    self._log(job_id, 'WARNING',
                              f'httpx returned 0 valid hosts. Using {len(subdomains)} subdomains as fallback.')
                    # Create live_hosts.txt with the subdomains (with https:// prefix)
                    for sub in subdomains:
                        live_hosts.append(f'https://{sub}')

                # Write live_hosts.txt with ONLY valid hosts
                with open(output_file, 'w') as f:
                    f.write('\n'.join(live_hosts))

                # Log errors if any
                if result.returncode != 0 and result.stderr:
                    stderr_short = result.stderr.strip()[:300]
                    self._log(job_id, 'WARNING', f'httpx stderr: {stderr_short}')

                output_files.append(output_file)

                for host in live_hosts:
                    _add_finding_dedup({
                        'category': 'live_host',
                        'severity': 'info',
                        'title': f'Live host: {host}',
                        'description': host,
                        'url': host,
                        'raw_data': host,
                    })

            elif phase == '3a':
                # Phase 3a: URL gathering - iterate over hosts in input file
                if not input_file or not os.path.exists(input_file):
                    return {'exit_code': -1, 'error': f'Input file {input_file} not found',
                            'findings': [], 'output_files': [], 'stats': {}}

                with open(input_file) as f:
                    # Strip httpx formatting like [STATUS] from each line
                    hosts = []
                    for line in f:
                        line = line.strip()
                        if not line: continue
                        # httpx output: "https://example.com [200] [Title] [nginx]"
                        # Extract just the URL (first token before space)
                        url_match = line.split()[0] if line.split() else line
                        hosts.append(url_match)

                all_urls = []
                for host in hosts:
                    try:
                        # Extract the bare domain from the httpx output line
                        bare_host = host.split()[0] if ' ' in host else host

                        # For waybackurls: it needs the root domain (e.g., example.com)
                        domain_for_tool = bare_host
                        if domain_for_tool.startswith('https://'):
                            domain_for_tool = domain_for_tool[8:]
                        elif domain_for_tool.startswith('http://'):
                            domain_for_tool = domain_for_tool[7:]
                        # Strip trailing slash and any path
                        domain_for_tool = domain_for_tool.split('/')[0].rstrip('/')
                        # Strip port if present
                        domain_for_tool = domain_for_tool.split(':')[0]

                        if binary == 'waybackurls':
                            # waybackurls takes the domain as a positional argument
                            cmd = [binary, domain_for_tool]
                            self._log(job_id, 'INFO',
                                      f'P3a: waybackurls {domain_for_tool}')
                        elif binary == 'gau':
                            cmd = [binary, domain_for_tool]
                            self._log(job_id, 'INFO',
                                      f'P3a: gau {domain_for_tool}')
                        elif binary == 'katana':
                            cmd = [binary, '-u', bare_host] + flags
                            self._log(job_id, 'INFO',
                                      f'P3a: katana -u {bare_host}')
                        else:
                            cmd = [binary] + flags + [bare_host]

                        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

                        # Log if there was an error
                        if r.returncode != 0 and r.stderr:
                            self._log(job_id, 'WARNING',
                                      f'{binary} returned {r.returncode} on {domain_for_tool}: {r.stderr.strip()[:200]}')

                        # waybackurls outputs URLs to STDOUT (one per line)
                        # Some versions also output to STDERR
                        urls = [u.strip() for u in r.stdout.splitlines() if u.strip()]
                        # Also check stderr for URLs (waybackurls sometimes outputs there)
                        stderr_urls = [u.strip() for u in r.stderr.splitlines()
                                       if u.strip() and u.strip().startswith('http')]
                        urls.extend(stderr_urls)

                        all_urls.extend(urls)
                        self._log(job_id, 'INFO',
                                  f'{binary} found {len(urls)} URLs for {domain_for_tool}')

                        for u in urls:
                            _add_finding_dedup({
                                'category': 'url',
                                'severity': 'info',
                                'title': f'URL: {u}',
                                'description': f'{binary} found URL: {u}',
                                'url': u,
                                'raw_data': u,
                            })
                    except subprocess.TimeoutExpired:
                        self._log(job_id, 'WARNING', f'{binary} timeout on {host}')
                    except Exception as e:
                        self._log(job_id, 'WARNING', f'{binary} error on {host}: {e}')

                # Dedupe URLs before saving
                seen = set()
                deduped = []
                for u in all_urls:
                    if u not in seen:
                        seen.add(u)
                        deduped.append(u)
                all_urls = deduped

                # Save all URLs to tool-specific output file
                with open(output_file, 'w') as f:
                    f.write('\n'.join(all_urls))
                output_files.append(output_file)

                with open(stdout_path, 'w') as f:
                    f.write(f'{binary} gathered {len(all_urls)} URLs')
                with open(stderr_path, 'w') as f:
                    f.write('')

            elif phase == '3b':
                # Phase 3b: host-based checks on live_hosts
                if not input_file or not os.path.exists(input_file):
                    return {'exit_code': -1, 'error': f'Input file {input_file} not found',
                            'findings': [], 'output_files': [], 'stats': {}}

                with open(input_file) as f:
                    hosts = []
                    for line in f:
                        line = line.strip()
                        if not line: continue
                        url_match = line.split()[0] if line.split() else line
                        hosts.append(url_match)

                # For nuclei-based tools, use -tags flag for tag-based filtering
                nuclei_template_map = {
                    'ssrf_nuclei': 'ssrf',
                    'clickjacking': 'clickjacking',
                    'security_headers': 'misconfig',
                    'default_credentials': 'default-logins',
                    'admin_panels': 'exposed-panels',
                    'cves': 'cves',
                    'open_redirect': 'redirect',
                    'sensitive_exposure': 'exposure',
                }

                # In-job dedup helpers (_norm_url, _add_finding_dedup) are
                # defined at the top of _execute_pipeline_job and shared
                # across all phases.

                for host in hosts:
                    try:
                        # Strip any trailing whitespace/quotes from host
                        host = host.strip().strip('"').strip("'")
                        if not host:
                            continue

                        if binary == 'nuclei':
                            # CRITICAL: Clear the output file BEFORE running nuclei
                            # on this host. Nuclei's -o flag overwrites the file
                            # when it HAS findings, but if it has NO findings for
                            # the current host, the file retains the previous
                            # host's findings, which we would then re-parse and
                            # re-add as duplicates.
                            try:
                                if os.path.exists(output_file):
                                    os.remove(output_file)
                            except OSError:
                                pass
                            # Build nuclei command with JSON output for proper parsing
                            # Use -j (short flag) for compatibility across nuclei versions
                            template = nuclei_template_map.get(job.tool_name)
                            cmd = [binary, '-u', host, '-silent', '-j',
                                   '-o', output_file]
                            if template:
                                cmd.extend(['-tags', template])
                            # Add rate limit to avoid being blocked
                            cmd.extend(['-rl', '50'])
                        elif binary == 'testssl':
                            # testssl needs the hostname without protocol
                            # Use --ssl-native for compatibility and -E for protocols only
                            # Avoid --warnings which can cause exit code issues
                            testssl_target = host
                            if testssl_target.startswith('https://'):
                                testssl_target = testssl_target[8:]
                            elif testssl_target.startswith('http://'):
                                testssl_target = testssl_target[7:]
                            testssl_target = testssl_target.rstrip('/')
                            # testssl.sh uses --quiet to suppress banner
                            cmd = [binary, '--quiet', testssl_target]
                        elif binary == 'wafw00f':
                            cmd = [binary, '-a', host]
                        elif binary == 'subzy':
                            # subzy needs --target (single) or --targets (file)
                            cmd = [binary, 'run', '--target', host,
                                   '--hide_fails', '--timeout', '10']
                        elif binary == 'tplmap':
                            # tplmap needs -u for URL
                            cmd = [binary, '-u', host, '--level', '1']
                        elif binary in ('openredirex', 'oralyzer'):
                            # oralyzer/openredirex need -u for URL
                            cmd = [binary, '-u', host]
                        elif binary == 'dalfox':
                            cmd = [binary, 'url', host, '--skip-bav', '--skip-mining-dom']
                        elif binary == 'sqlmap':
                            cmd = [binary, '-u', host, '--batch', '--random-agent',
                                   '--level', '1', '--risk', '1']
                        elif binary == 'commix':
                            cmd = [binary, '--url=' + host, '--batch', '--level=1']
                        elif binary == 'dotdotpwn':
                            # dotdotpwn needs -m module + -u url
                            cmd = [binary, '-m', 'http', '-u', host]
                        else:
                            cmd = [binary] + flags + [host]

                        self._log(job_id, 'INFO',
                                  f'P3b: {" ".join(str(c) for c in cmd[:8])}')
                        r = subprocess.run(cmd, capture_output=True,
                                           text=True, timeout=timeout)

                        # Log stderr if there was an error (for debugging)
                        if r.returncode != 0 and r.stderr:
                            stderr_short = r.stderr.strip()[:300]
                            self._log(job_id, 'WARNING',
                                      f'{binary} returned {r.returncode} on {host}: {stderr_short}')

                        # Save raw output for inspection (truncated to 1MB)
                        try:
                            MAX_OUT = 1024 * 1024  # 1MB
                            stdout_data = (r.stdout or '')[:MAX_OUT]
                            stderr_data = (r.stderr or '')[:MAX_OUT]
                            if len(r.stdout or '') > MAX_OUT:
                                stdout_data += '\n... [truncated]'
                            if len(r.stderr or '') > MAX_OUT:
                                stderr_data += '\n... [truncated]'
                            with open(stdout_path, 'a') as f:
                                f.write(f'=== {host} ===\n')
                                f.write(stdout_data)
                                f.write('\n--- STDERR ---\n')
                                f.write(stderr_data)
                                f.write('\n')
                        except Exception:
                            pass

                        # ── Parse nuclei JSON output ────────────────────
                        # nuclei writes JSON to output_file with -o flag,
                        # but also prints to stdout in some versions.
                        # Check both sources.
                        if binary == 'nuclei':
                            nuclei_findings_raw = []
                            # Try output file first
                            if os.path.exists(output_file):
                                with open(output_file) as f:
                                    nuclei_findings_raw = f.readlines()
                            # Also check stdout (nuclei may print to stdout)
                            if not nuclei_findings_raw and r.stdout:
                                nuclei_findings_raw = r.stdout.splitlines()

                            for raw_line in nuclei_findings_raw:
                                line = raw_line.strip()
                                if not line:
                                    continue
                                try:
                                    data = json.loads(line)
                                    sev = (data.get('info', {}).get('severity', 'info')
                                           or 'info').lower()
                                    sev_map = {'critical': 'critical',
                                               'high': 'high',
                                               'medium': 'medium',
                                               'low': 'low',
                                               'info': 'info'}
                                    _add_finding_dedup({
                                        'category': job.tool_name,
                                        'severity': sev_map.get(sev, 'medium'),
                                        'title': data.get('info', {}).get('name',
                                                 'Nuclei finding'),
                                        'description': data.get('info', {}).get('description',
                                                 data.get('matched-at', host)),
                                        'url': data.get('matched-at', host) or host,
                                        'raw_data': line,
                                    })
                                except json.JSONDecodeError:
                                    # Not JSON - check if it's a text finding
                                    # nuclei text output format:
                                    # [template-id] [type] [severity] URL
                                    if line and not line.startswith('[') and 'http' in line:
                                        _add_finding_dedup({
                                            'category': job.tool_name,
                                            'severity': 'medium',
                                            'title': f'{job.tool_name}: {line[:100]}',
                                            'description': line,
                                            'url': host,
                                            'raw_data': line,
                                        })
                        # ── Parse testssl output (look for vulnerabilities) ──
                        elif binary == 'testssl' and r.stdout:
                            for line in r.stdout.splitlines():
                                line = line.strip()
                                # testssl marks issues with severity tags
                                if any(kw in line.upper() for kw in
                                       ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW',
                                        'VULNERABLE', 'NOT OK', 'WARN']):
                                    _add_finding_dedup({
                                        'category': job.tool_name,
                                        'severity': 'medium',
                                        'title': f'SSL issue: {line[:100]}',
                                        'description': line,
                                        'url': host,
                                        'raw_data': line,
                                    })
                        # ── Parse wafw00f output (consolidated, deduped) ──
                        elif binary == 'wafw00f' and r.stdout:
                            import re
                            for line in r.stdout.splitlines():
                                # Skip info/header lines
                                if any(kw in line.lower() for kw in
                                       ['wafw00f', 'generic detection', 'no waf']):
                                    continue
                                # Clean ANSI codes
                                clean_line = re.sub(r'\x1b\[[0-9;]*m', '', line).strip()
                                if not clean_line:
                                    continue
                                # Only capture actual WAF detection
                                if 'is behind' in clean_line.lower():
                                    _add_finding_dedup({
                                        'category': job.tool_name,
                                        'severity': 'info',
                                        'title': f'WAF detected: {clean_line[:100]}',
                                        'description': clean_line,
                                        'url': host,
                                        'raw_data': clean_line,
                                    })
                        # ── Parse subzy output ──
                        elif binary == 'subzy' and r.stdout:
                            for line in r.stdout.splitlines():
                                line_lower = line.lower()
                                # Skip info/status messages
                                if any(kw in line_lower for kw in
                                       ['loaded', 'fingerprints', 'checking',
                                        'concurrent', 'timeout', 'https by default',
                                        'verify_ssl', 'hide_fails', 'http request',
                                        'show only', 'yes ]', 'no ]']):
                                    continue
                                # Only capture actual vulnerabilities
                                if 'vulnerable' in line_lower or 'takeover' in line_lower:
                                    _add_finding_dedup({
                                        'category': job.tool_name,
                                        'severity': 'high',
                                        'title': f'Subdomain takeover: {line[:100]}',
                                        'description': line,
                                        'url': host,
                                        'raw_data': line,
                                    })
                        # ── Parse injection tools output ──
                        elif binary in ('dalfox', 'sqlmap', 'commix', 'tplmap',
                                        'dotdotpwn', 'openredirex', 'oralyzer'):
                            for line in r.stdout.splitlines():
                                line_lower = line.lower()
                                if any(kw in line_lower for kw in
                                       ['vulnerab', 'inject', 'exploit', 'payload',
                                        'found', 'confirmed', 'detected',
                                        'sql injection', 'xss', 'ssti',
                                        'command injection', 'open redirect',
                                        'lfi', 'path traversal']):
                                    _add_finding_dedup({
                                        'category': job.tool_name,
                                        'severity': 'high',
                                        'title': f'{job.tool_name}: {line[:100]}',
                                        'description': line,
                                        'url': host,
                                        'raw_data': line,
                                    })
                    except subprocess.TimeoutExpired:
                        self._log(job_id, 'WARNING',
                                  f'{binary} timeout on {host}')
                    except FileNotFoundError as e:
                        self._log(job_id, 'ERROR',
                                  f'{binary} not found: {e}')
                    except Exception as e:
                        self._log(job_id, 'WARNING',
                                  f'{binary} error on {host}: {e}')

                if os.path.exists(output_file):
                    output_files.append(output_file)

            elif phase == 4:
                # Phase 4: injection scans on parameterized URLs
                if not input_file or not os.path.exists(input_file):
                    return {'exit_code': -1, 'error': f'Input file {input_file} not found',
                            'findings': [], 'output_files': [], 'stats': {}}

                with open(input_file) as f:
                    urls = [l.strip() for l in f if l.strip()]

                # Nuclei template for Phase 4 (ssrf_nuclei)
                nuclei_template_map_p4 = {
                    'ssrf_nuclei': 'ssrf',
                }

                for url in urls:
                    try:
                        url = url.strip().strip('"').strip("'")
                        if not url:
                            continue

                        # Build command per tool
                        if binary == 'dalfox':
                            cmd = [binary, 'url', url, '--skip-bav',
                                   '--skip-mining-dom', '--skip-grep']
                        elif binary == 'sqlmap':
                            cmd = [binary, '-u', url, '--batch', '--random-agent',
                                   '--level', '1', '--risk', '1']
                        elif binary == 'tplmap':
                            cmd = [binary, '-u', url, '--level', '1']
                        elif binary == 'commix':
                            cmd = [binary, '--url=' + url, '--batch', '--level=1']
                        elif binary == 'dotdotpwn':
                            cmd = [binary, '-m', 'http', '-u', url,
                                   '-f', '/etc/passwd']
                        elif binary == 'nuclei':
                            # ssrf_nuclei uses nuclei in Phase 4
                            # CRITICAL: Clear output file before each run to
                            # avoid re-parsing stale findings from previous URL.
                            try:
                                if os.path.exists(output_file):
                                    os.remove(output_file)
                            except OSError:
                                pass
                            template = nuclei_template_map_p4.get(job.tool_name, 'ssrf')
                            cmd = [binary, '-u', url, '-silent', '-j',
                                   '-t', template, '-o', output_file, '-rl', '50']
                        elif binary in ('openredirex', 'oralyzer'):
                            cmd = [binary, '-u', url]
                        else:
                            cmd = [binary] + flags + [url]

                        self._log(job_id, 'INFO',
                                  f'P4: {" ".join(str(c) for c in cmd[:8])}')
                        r = subprocess.run(cmd, capture_output=True,
                                           text=True, timeout=timeout)

                        # Log stderr if there was an error
                        if r.returncode != 0 and r.stderr:
                            stderr_short = r.stderr.strip()[:300]
                            self._log(job_id, 'WARNING',
                                      f'{binary} returned {r.returncode} on {url}: {stderr_short}')

                        # Save raw output (truncated to 1MB)
                        try:
                            MAX_OUT = 1024 * 1024  # 1MB
                            stdout_data = (r.stdout or '')[:MAX_OUT]
                            stderr_data = (r.stderr or '')[:MAX_OUT]
                            if len(r.stdout or '') > MAX_OUT:
                                stdout_data += '\n... [truncated]'
                            if len(r.stderr or '') > MAX_OUT:
                                stderr_data += '\n... [truncated]'
                            with open(stdout_path, 'a') as f:
                                f.write(f'=== {url} ===\n')
                                f.write(stdout_data)
                                f.write('\n--- STDERR ---\n')
                                f.write(stderr_data)
                                f.write('\n')
                        except Exception:
                            pass

                        # ── Parse nuclei JSON output ──
                        # Check both output file and stdout
                        if binary == 'nuclei':
                            nuclei_findings_raw = []
                            if os.path.exists(output_file):
                                with open(output_file) as f:
                                    nuclei_findings_raw = f.readlines()
                            if not nuclei_findings_raw and r.stdout:
                                nuclei_findings_raw = r.stdout.splitlines()

                            for raw_line in nuclei_findings_raw:
                                line = raw_line.strip()
                                if not line:
                                    continue
                                try:
                                    data = json.loads(line)
                                    sev = (data.get('info', {}).get('severity', 'info')
                                           or 'info').lower()
                                    sev_map = {'critical': 'critical',
                                               'high': 'high',
                                               'medium': 'medium',
                                               'low': 'low',
                                               'info': 'info'}
                                    _add_finding_dedup({
                                        'category': job.tool_name,
                                        'severity': sev_map.get(sev, 'medium'),
                                        'title': data.get('info', {}).get('name',
                                                 'Nuclei finding'),
                                        'description': data.get('info', {}).get('description',
                                                 data.get('matched-at', url)),
                                        'url': data.get('matched-at', url) or url,
                                        'raw_data': line,
                                    })
                                except json.JSONDecodeError:
                                    pass
                        # ── Parse other injection tools ──
                        elif binary in ('dalfox', 'sqlmap', 'commix', 'tplmap',
                                        'dotdotpwn', 'openredirex', 'oralyzer'):
                            for line in r.stdout.splitlines():
                                line_lower = line.lower()
                                if any(kw in line_lower for kw in
                                       ['vulnerab', 'inject', 'exploit', 'payload',
                                        'found', 'confirmed', 'detected',
                                        'sql injection', 'xss', 'ssti',
                                        'command injection', 'open redirect',
                                        'lfi', 'path traversal', 'is vulnerable']):
                                    _add_finding_dedup({
                                        'category': job.tool_name,
                                        'severity': 'high',
                                        'title': f'{job.tool_name}: {line[:100]}',
                                        'description': line,
                                        'url': url,
                                        'raw_data': line,
                                    })
                    except subprocess.TimeoutExpired:
                        self._log(job_id, 'WARNING',
                                  f'{binary} timeout on {url}')
                    except FileNotFoundError as e:
                        self._log(job_id, 'ERROR',
                                  f'{binary} not found: {e}')
                    except Exception as e:
                        self._log(job_id, 'WARNING',
                                  f'{binary} error on {url}: {e}')

                if os.path.exists(output_file):
                    output_files.append(output_file)

        except subprocess.TimeoutExpired:
            error = f'Timeout after {timeout} seconds'
            exit_code = -1
        except Exception as exc:
            error = str(exc)
            exit_code = -1
            self._log(job_id, 'ERROR', f'Pipeline execution error: {exc}')

        return {
            'exit_code': exit_code,
            'error': error,
            'findings': findings,
            'output_files': output_files,
            'stats': {'total_findings': len(findings)},
            'stdout_path': stdout_path,
            'stderr_path': stderr_path,
        }

    def _run_with_stdin(self, runner, target, options, output_dir, stdin_input):
        """Execute a tool that requires stdin input.

        Similar to BaseToolRunner.run() but passes stdin to subprocess.

        Args:
            runner: The tool runner instance.
            target: Target string.
            options: Tool options dict.
            output_dir: Directory for output files.
            stdin_input: String to pass as stdin.

        Returns:
            Result dict from the runner.
        """
        import subprocess

        os.makedirs(output_dir, exist_ok=True)

        command = runner.build_command(target, options)
        logger.info(f"[{runner.tool_name}] Running command: {' '.join(command)} (with stdin)")

        timeout = options.get('timeout', runner.default_timeout)

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=stdin_input,
            )

            # Save raw output
            stdout_path = os.path.join(output_dir, f'{runner.tool_name}_stdout.txt')
            stderr_path = os.path.join(output_dir, f'{runner.tool_name}_stderr.txt')
            with open(stdout_path, 'w') as f:
                f.write(result.stdout)
            with open(stderr_path, 'w') as f:
                f.write(result.stderr)

            # Parse output
            parsed = runner.parse_output(result.stdout, result.stderr, output_dir)
            parsed['exit_code'] = result.returncode
            parsed['stdout_path'] = stdout_path
            parsed['stderr_path'] = stderr_path

            return parsed

        except subprocess.TimeoutExpired:
            logger.error(f"[{runner.tool_name}] Timeout after {timeout}s")
            return {
                'exit_code': -1,
                'error': f'Timeout after {timeout} seconds',
                'findings': [],
                'output_files': [],
                'stats': {}
            }
        except Exception as e:
            logger.error(f"[{runner.tool_name}] Unexpected error: {str(e)}")
            return {
                'exit_code': -1,
                'error': str(e),
                'findings': [],
                'output_files': [],
                'stats': {}
            }

    def _handle_retry_or_fail(self, job_id, job, result):
        """Attempt retry if the failure is retryable.

        Args:
            job_id: The ScanJob primary key.
            job: ScanJob instance.
            result: Result dict from the tool runner.
        """
        if self._is_retryable(job, result):
            requeued = self._queue.increment_retry(job_id)
            if requeued:
                # Exponential backoff is implicit - the job goes back to
                # 'queued' and will be picked up on the next poll cycle.
                self._log(
                    job_id, 'INFO',
                    f'Retry {job.retry_count}/{job.max_retries} scheduled.',
                )
            # else: max retries exceeded - increment_retry already marked as failed
        else:
            self._log(job_id, 'WARNING', 'Failure is non-retryable; not retrying.')

    def _is_retryable(self, job, result):
        """Check if a failure is retryable.

        A failure is retryable if:
        - The exit code is in RETRYABLE_EXIT_CODES.
        - The error message does NOT contain any NON_RETRYABLE_PATTERNS.
        - The job has not exceeded max_retries.

        Args:
            job: ScanJob instance.
            result: Result dict from the tool runner.

        Returns:
            True if the failure should be retried.
        """
        exit_code = result.get('exit_code', -1)
        if exit_code not in self.RETRYABLE_EXIT_CODES:
            return False

        error = result.get('error', '')
        for pattern in self.NON_RETRYABLE_PATTERNS:
            if pattern.lower() in str(error).lower():
                return False

        if job.retry_count >= job.max_retries:
            return False

        return True

    def _log(self, job_id, level, message, details=None):
        """Write an ExecutionLog entry.

        Args:
            job_id: ScanJob primary key.
            level: Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
            message: Human-readable log message.
            details: Optional dict to store as JSON.
        """
        # Truncate message to prevent oversized log entries
        if message and len(message) > 500:
            message = message[:500] + '...'

        try:
            log_entry = ExecutionLog(
                scan_job_id=job_id,
                level=level,
                message=message,
                details=json.dumps(details) if details else None,
            )
            db.session.add(log_entry)
            db.session.commit()
        except Exception as exc:
            # Try to rollback the session so it doesn't stay in a broken state
            try:
                db.session.rollback()
            except Exception:
                pass
            logger.error("Failed to write ExecutionLog for job %d: %s", job_id, exc)
