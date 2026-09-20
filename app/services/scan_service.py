"""Scan service - handles scan configuration and execution business logic."""
import json
import logging
import shutil
from app.extensions import db
from app.models.scan import Scan
from app.models.scan_job import ScanJob
from app.models.target import Target
from app.models.configuration import Configuration
from app.plugins.registry import tool_registry
from app.plugins import TOOL_RUNNERS as PLUGIN_RUNNERS

logger = logging.getLogger(__name__)


def _is_binary_available(binary_name: str) -> bool:
    """Quick check if a binary is available on the system PATH."""
    return shutil.which(binary_name) is not None

# Nuclei template tags for vuln-specific scans.
# When a vuln key maps to the 'nuclei' binary, these templates are
# passed via the 'templates' option so that only relevant checks run.
# SIMPLIFIED: Only the templates for our 15 supported vulnerability categories.
NUCLEI_TEMPLATE_MAP = {
    'ssrf_nuclei': 'ssrf',
    'clickjacking': 'clickjacking',
    'security_headers': 'misconfiguration/security-misconfiguration',
    'default_credentials': 'default-login',
    'admin_panels': 'exposed-panels',
    'cves': 'cves',
}


class ScanService:
    """Handles all scan-related business logic."""

    # Use the plugin-level TOOL_RUNNERS registry (maps binary name → runner class)
    TOOL_RUNNERS = PLUGIN_RUNNERS

    def start_scan(self, user_id, config_id, scan_name, scan_type=None,
                   target_id=None, manual_target=None, manual_target_type=None,
                   auth_cookie=None):
        """Start a new scan for a target using a configuration.

        Targets can be resolved in two ways:
            1. ``target_id`` – look up an existing Target from the database.
            2. ``manual_target`` – an ad-hoc target value provided at
               scan-creation time (no DB record required).

        At least one of ``target_id`` or ``manual_target`` must be supplied.

        Args:
            user_id: The user initiating the scan.
            config_id: The configuration to use.
            scan_name: Human-readable scan name.
            scan_type: Override scan type; defaults to the config's type.
            target_id: Database ID of an existing Target.
            manual_target: Inline target value (e.g. a domain or URL).
            manual_target_type: Type hint for the manual target (e.g.
                'domain', 'url', 'ip').
        """
        # ── Resolve target ──────────────────────────────────────────────
        target = None
        target_value = None

        if target_id:
            target = db.session.get(Target, target_id)
            if not target:
                return {'success': False, 'errors': ['Target not found']}
            target_value = target.value
        elif manual_target:
            target_value = manual_target.strip()
            if not target_value:
                return {'success': False, 'errors': ['Manual target value is empty']}
        else:
            return {'success': False, 'errors': ['Either select a target or provide a manual target URL/domain']}

        # ── Resolve configuration ───────────────────────────────────────
        if not config_id:
            return {'success': False, 'errors': ['Please select a scan configuration']}

        config = db.session.get(Configuration, config_id)
        if not config:
            return {'success': False, 'errors': ['Configuration not found']}

        if not scan_name or len(scan_name.strip()) < 3:
            scan_name = f"Scan - {target_value}"

        if not scan_type:
            scan_type = config.config_type

        # Create scan (target_id may be None for manual targets)
        scan = Scan(
            target_id=target_id if target else None,
            manual_target=manual_target.strip() if manual_target else None,
            manual_target_type=manual_target_type if manual_target else None,
            initiated_by=user_id,
            name=scan_name.strip(),
            scan_type=scan_type,
            config_id=config_id,
            status='pending'
        )
        scan.save()

        # ── Create scan jobs for each enabled tool ─────────────────────
        enabled_tools = config.get_enabled_tools()
        output_dir = f"output/{target_value}"

        # Check tool availability and skip unavailable ones
        available_tools = []
        skipped_tools = []

        for tool_name in enabled_tools:
            binary = tool_registry.get_tool_binary(tool_name)
            if _is_binary_available(binary):
                available_tools.append(tool_name)
            else:
                skipped_tools.append({
                    'tool_name': tool_name,
                    'binary': binary,
                })
                logger.warning(
                    f"Tool '{tool_name}' (binary: {binary}) is not installed - skipping"
                )

        if not available_tools:
            missing_binaries = sorted(set(s['binary'] for s in skipped_tools))
            return {
                'success': False,
                'errors': [
                    f'None of the selected tools are installed on this system. '
                    f'Please install the following tools first: {", ".join(missing_binaries)}'
                ],
                'skipped_tools': skipped_tools,
            }

        for tool_name in available_tools:
            tool_opts = config.get_tool_options(tool_name)
            timeout = tool_opts.get('timeout', 600)
            flags = tool_opts.get('flags', [])

            # Resolve the actual binary name from the registry key
            binary = tool_registry.get_tool_binary(tool_name)
            command = f"{binary} {' '.join(flags)} {target_value}"

            # Build tool-specific options JSON for the worker to use
            tool_options = {
                'flags': flags,
                'timeout': timeout,
            }

            # Add nuclei template tag if this is a nuclei-based vuln scan
            if tool_name in NUCLEI_TEMPLATE_MAP:
                tool_options['templates'] = NUCLEI_TEMPLATE_MAP[tool_name]

            # Add specific options from the config
            for opt_key, opt_val in tool_opts.items():
                if opt_key not in ('enabled', 'flags', 'timeout'):
                    tool_options[opt_key] = opt_val

            # Pass auth cookie to the tool (for tools that support it)
            if auth_cookie:
                tool_options['auth_cookie'] = auth_cookie

            job = ScanJob(
                scan_id=scan.id,
                tool_name=tool_name,
                command=command,
                timeout_seconds=timeout,
                output_dir=f"{output_dir}/{tool_name}",
                tool_options=json.dumps(tool_options),
            )
            job.save()

        scan.total_jobs = len(available_tools)
        scan.save()

        result = {
            'success': True,
            'scan': scan,
            'available_count': len(available_tools),
            'skipped_count': len(skipped_tools),
            'skipped_tools': skipped_tools,
        }

        logger.info(
            f"Scan '{scan_name}' started for target {target_value} with "
            f"{len(available_tools)} tools ({len(skipped_tools)} skipped - not installed)"
        )
        return result

    def get_scan(self, scan_id, user_id):
        """Get scan details."""
        scan = db.session.get(Scan, scan_id)
        if not scan:
            return {'success': False, 'errors': ['Scan not found']}
        return {'success': True, 'scan': scan}

    def cancel_scan(self, scan_id, user_id):
        """Cancel a running scan."""
        scan = db.session.get(Scan, scan_id)
        if not scan:
            return {'success': False, 'errors': ['Scan not found']}

        scan.status = 'cancelled'
        scan.save()

        # Cancel queued jobs
        queued_jobs = ScanJob.query.filter_by(scan_id=scan_id, status='queued').all()
        for job in queued_jobs:
            job.status = 'skipped'
        db.session.commit()

        logger.info(f"Scan {scan_id} cancelled by user {user_id}")
        return {'success': True}

    def start_pipeline_scan(self, user_id, target_value, scan_name=None,
                            target_type='domain', config_id=None):
        """Start a multi-phase pipeline scan on a root domain.

        Phases:
            1. Subdomain discovery (assetfinder + subfinder + amass)
            2. HTTP probing (httpx)
            3. URL gathering + host checks (parallel)
            4. Injection scans on parameterized URLs

        Args:
            user_id: The user initiating the scan.
            target_value: Root domain (e.g. 'example.com').
            scan_name: Optional human-readable name.
            target_type: Type hint for the target (default 'domain').
            config_id: Optional configuration ID. If provided, only the tools
                       enabled in this config will run in their respective phases.

        Returns:
            dict with 'success', 'scan', or 'errors'.
        """
        if not target_value or not target_value.strip():
            return {'success': False, 'errors': ['Target is required']}

        target_value = target_value.strip()

        if not scan_name or len(scan_name.strip()) < 3:
            scan_name = f"Pipeline - {target_value}"

        # Create the scan record - link to config if provided
        scan = Scan(
            manual_target=target_value,
            manual_target_type=target_type,
            initiated_by=user_id,
            name=scan_name.strip(),
            scan_type='pipeline',
            status='pending',
            config_id=config_id,
            pipeline_mode=True,
            current_phase=0,
        )
        scan.save()

        # Kick off Phase 1 (pass config_id so only enabled tools run)
        from app.services.pipeline_service import pipeline_service
        result = pipeline_service.start_pipeline(scan.id, config_id=config_id)
        if not result['success']:
            scan.status = 'failed'
            scan.save()
            return result

        scan.status = 'running'
        scan.save()

        logger.info("Pipeline scan '%s' started for %s by user %s (config_id=%s)",
                    scan_name, target_value, user_id, config_id)
        return {'success': True, 'scan': scan}

    def should_use_pipeline(self, config, target_type):
        """Determine whether a scan should run in pipeline mode.

        Pipeline mode is recommended when the configuration contains tools
        from multiple phases (recon + vuln_scan), which means a phased
        workflow is needed.

        Note: This method only checks the *config*. The caller is responsible
        for verifying that the target type is compatible with the pipeline
        (Phase 1 requires a root domain).

        Args:
            config: Configuration instance.
            target_type: 'domain', 'ip', 'url', or 'cidr'.

        Returns:
            True if pipeline mode should be used.
        """
        enabled_tools = config.get_enabled_tools()
        if not enabled_tools:
            return False

        # Phase-1 / Phase-2 tools (subdomain discovery + http probing)
        recon_phase_tools = {'subfinder', 'httpx'}
        # Phase-3 tools (URL gathering + host checks)
        phase3_tools = {'waybackurls', 'nuclei', 'testssl', 'wafw00f', 'subzy',
                        'ssl_issues', 'waf_detection', 'subdomain_takeover',
                        'security_headers', 'clickjacking', 'cves',
                        'admin_panels', 'default_credentials', 'ssrf_nuclei'}
        # Phase-4 tools (injection)
        phase4_tools = {'xss', 'sqli', 'ssti', 'command_injection', 'lfi',
                        'open_redirect'}

        has_recon = any(t in recon_phase_tools for t in enabled_tools)
        has_phase3 = any(t in phase3_tools for t in enabled_tools)
        has_phase4 = any(t in phase4_tools for t in enabled_tools)

        # Use pipeline if config has tools from at least 2 different phases
        phases_present = sum([has_recon, has_phase3, has_phase4])
        return phases_present >= 2
