"""Tool Registry - tracks available security tools and their status.

SIMPLIFIED: Only 3 recon tools + 15 vulnerability scanners (18 total).
All other tools have been removed from the platform.
"""
import subprocess
import logging

logger = logging.getLogger(__name__)


class ToolRegistry:
    """Registry of supported security tools with installation checks.

    Maintains a catalogue of the 18 tools the platform can invoke, grouped by
    category, and provides helpers to check which ones are actually installed
    on the host system.
    """

    SUPPORTED_TOOLS = {
        # ── Recon (3 tools) ───────────────────────────────────────────
        'subfinder': {
            'category': 'recon',
            'description': 'Subdomain discovery tool',
            'version_flag': '-version',
            'input_type': 'Domain',
        },
        'httpx': {
            'category': 'recon',
            'description': 'Fast and multi-purpose HTTP toolkit',
            'version_flag': '-version',
            'input_type': 'URL',
        },
        'waybackurls': {
            'category': 'recon',
            'description': 'Fetch known URLs from Wayback Machine',
            'version_flag': '-version',
            'input_type': 'Domain',
        },

        # ── Vulnerability Scanning (15 tools) ─────────────────────────
        # Phase 3b - Host-based checks (8 tools)
        'ssl_issues': {
            'category': 'vuln_scan',
            'description': 'SSL/TLS security testing',
            'version_flag': '--version',
            'tool': 'testssl',
            'input_type': 'Domain',
        },
        'waf_detection': {
            'category': 'vuln_scan',
            'description': 'Web Application Firewall identification',
            'version_flag': '-V',
            'tool': 'wafw00f',
            'input_type': 'Domain',
        },
        'subdomain_takeover': {
            'category': 'vuln_scan',
            'description': 'Subdomain takeover vulnerability detection',
            'version_flag': '-version',
            'tool': 'subzy',
            'input_type': 'Subdomains',
        },
        'security_headers': {
            'category': 'vuln_scan',
            'description': 'Security Headers analysis via Nuclei',
            'version_flag': '-version',
            'tool': 'nuclei',
            'input_type': 'URL',
        },
        'clickjacking': {
            'category': 'vuln_scan',
            'description': 'Clickjacking / UI Redress detection via Nuclei',
            'version_flag': '-version',
            'tool': 'nuclei',
            'input_type': 'URL',
        },
        'cves': {
            'category': 'vuln_scan',
            'description': 'Known CVE vulnerability detection via Nuclei',
            'version_flag': '-version',
            'tool': 'nuclei',
            'input_type': 'URL',
        },
        'admin_panels': {
            'category': 'vuln_scan',
            'description': 'Admin Panel exposure detection via Nuclei',
            'version_flag': '-version',
            'tool': 'nuclei',
            'input_type': 'URL',
        },
        'default_credentials': {
            'category': 'vuln_scan',
            'description': 'Default Credentials detection via Nuclei',
            'version_flag': '-version',
            'tool': 'nuclei',
            'input_type': 'URL',
        },
        # Phase 4 - Injection scans (7 tools)
        'xss': {
            'category': 'vuln_scan',
            'description': 'Cross-Site Scripting detection and exploitation',
            'version_flag': 'version',
            'tool': 'dalfox',
            'input_type': 'URL with Parameters',
        },
        'sqli': {
            'category': 'vuln_scan',
            'description': 'SQL Injection detection and exploitation',
            'version_flag': '--version',
            'tool': 'sqlmap',
            'input_type': 'URL or Request Raw',
        },
        'ssti': {
            'category': 'vuln_scan',
            'description': 'Server-Side Template Injection detection',
            'version_flag': '-version',
            'tool': 'tplmap',
            'input_type': 'URL with Parameters',
        },
        'command_injection': {
            'category': 'vuln_scan',
            'description': 'OS Command Injection exploitation',
            'version_flag': '--version',
            'tool': 'commix',
            'input_type': 'URL with Parameters',
        },
        'lfi': {
            'category': 'vuln_scan',
            'description': 'Local File Inclusion / Path Traversal detection',
            'version_flag': '--help',
            'tool': 'dotdotpwn',
            'input_type': 'URL with Parameters',
        },
        'ssrf_nuclei': {
            'category': 'vuln_scan',
            'description': 'SSRF detection via Nuclei templates',
            'version_flag': '-version',
            'tool': 'nuclei',
            'input_type': 'URL',
        },
        'open_redirect': {
            'category': 'vuln_scan',
            'description': 'Open Redirect vulnerability detection',
            'version_flag': '-version',
            'tool': 'openredirex',
            'input_type': 'URLs',
        },
    }

    def __init__(self):
        # Cache: {tool_name: True/False} – populated by check_all_tools()
        self._cache: dict = {}

    # ── Public API ──────────────────────────────────────────────────────

    def get_tool_binary(self, vuln_key: str) -> str:
        """Return the actual binary name for a registry key.

        For recon tools the key *is* the binary, so the key
        itself is returned.  For vuln_scan entries the key is a
        vulnerability name and the real binary is stored in the
        ``tool`` field.

        Args:
            vuln_key: The dictionary key in SUPPORTED_TOOLS.

        Returns:
            The binary/executable name to invoke on the host.
        """
        tool_info = self.SUPPORTED_TOOLS.get(vuln_key, {})
        return tool_info.get('tool', vuln_key)

    def check_tool(self, tool_name: str) -> bool:
        """Check whether a single tool is installed on the host.

        Runs ``<binary> <version_flag>`` and returns *True* if the
        process exits cleanly (return-code 0).  A timeout of 5 seconds is
        used so a hung tool never blocks the registry.

        For vuln_scan entries the key is a vulnerability name; the
        actual binary to check is resolved via ``get_tool_binary``.
        """
        if tool_name not in self.SUPPORTED_TOOLS:
            logger.warning(f"Unknown tool: {tool_name}")
            return False

        tool_info = self.SUPPORTED_TOOLS[tool_name]
        binary = self.get_tool_binary(tool_name)
        cmd = [binary, tool_info['version_flag']]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
            installed = result.returncode == 0
            self._cache[tool_name] = installed
            return installed
        except FileNotFoundError:
            self._cache[tool_name] = False
            return False
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout checking tool: {tool_name}")
            self._cache[tool_name] = False
            return False
        except Exception as exc:
            logger.error(f"Error checking tool {tool_name}: {exc}")
            self._cache[tool_name] = False
            return False

    def check_all_tools(self) -> dict:
        """Check every supported tool and return the full status dict.

        Returns:
            Dictionary mapping tool_name -> bool (installed or not).
        """
        for tool_name in self.SUPPORTED_TOOLS:
            self.check_tool(tool_name)
        return dict(self._cache)

    def get_installed_tools(self) -> list:
        """Return a list of tool names that are installed."""
        if not self._cache:
            self.check_all_tools()
        return [name for name, installed in self._cache.items() if installed]

    def get_tools_by_category(self, category: str) -> dict:
        """Return SUPPORTED_TOOLS entries filtered by *category*.

        Args:
            category: One of 'recon', 'vuln_scan'.

        Returns:
            Dict of {tool_name: tool_info} for tools in that category.
        """
        return {
            name: info
            for name, info in self.SUPPORTED_TOOLS.items()
            if info['category'] == category
        }

    def is_tool_available(self, tool_name: str) -> bool:
        """Quick boolean check – returns cached value if present, else checks."""
        if tool_name in self._cache:
            return self._cache[tool_name]
        return self.check_tool(tool_name)

    def get_tool_info(self, tool_name: str) -> dict:
        """Return the metadata dict for a single tool, or empty dict."""
        return self.SUPPORTED_TOOLS.get(tool_name, {})

    def get_categories(self) -> list:
        """Return the distinct categories across all supported tools."""
        return sorted({info['category'] for info in self.SUPPORTED_TOOLS.values()})


# ── Module-level singleton ─────────────────────────────────────────────
tool_registry = ToolRegistry()
