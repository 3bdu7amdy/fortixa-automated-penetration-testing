"""Vulnerability category mapping - groups tools by vulnerability type.

SIMPLIFIED: Only 15 vulnerability categories + 3 recon categories.
"""

# Mapping: tool_name or vuln_key → unified vuln_category label
VULN_CATEGORY_MAP = {
    # ── Recon categories (3) ─────────────────────────────────────
    'subfinder': 'Subdomain',
    'httpx': 'Live Host',
    'waybackurls': 'URL',
    'subdomain': 'Subdomain',
    'live_host': 'Live Host',
    'url': 'URL',

    # ── Vulnerability categories (15) ────────────────────────────
    # Phase 3b - Host-based checks (8)
    'ssl_issues': 'SSL/TLS Issues',
    'testssl': 'SSL/TLS Issues',
    'waf_detection': 'WAF Detection',
    'wafw00f': 'WAF Detection',
    'subdomain_takeover': 'Subdomain Takeover',
    'subzy': 'Subdomain Takeover',
    'security_headers': 'Security Headers',
    'clickjacking': 'Clickjacking',
    'cves': 'Known CVEs',
    'admin_panels': 'Admin Panel Exposure',
    'default_credentials': 'Default Credentials',

    # Phase 4 - Injection scans (7) - actually 4 unique + 3 same as above
    # Wait, let me count properly:
    # ssl_issues, waf_detection, subdomain_takeover, security_headers,
    # clickjacking, cves, admin_panels, default_credentials = 8 (Phase 3b)
    # xss, sqli, ssti, command_injection, lfi, ssrf_nuclei, open_redirect = 7 (Phase 4)
    # Total vuln categories = 15 ✅
    'xss': 'XSS',
    'dalfox': 'XSS',
    'sqli': 'SQL Injection',
    'sqlmap': 'SQL Injection',
    'ssti': 'SSTI',
    'tplmap': 'SSTI',
    'command_injection': 'Command Injection',
    'commix': 'Command Injection',
    'lfi': 'LFI / Path Traversal',
    'dotdotpwn': 'LFI / Path Traversal',
    'ssrf_nuclei': 'SSRF',
    'open_redirect': 'Open Redirect',
    'openredirex': 'Open Redirect',
    'oralyzer': 'Open Redirect',

    # ── Nuclei generic (when no specific mapping) ────────────────
    'nuclei': 'Nuclei Findings',
}


def get_vuln_category(tool_name):
    """Resolve a tool name or vuln key to a unified vuln_category label.

    Args:
        tool_name: The tool_name stored on the Finding (may be a vuln key
                   like 'xss' or a binary name like 'dalfox').

    Returns:
        A human-readable category label (e.g. 'XSS', 'SQL Injection'),
        or the original tool_name if no mapping exists.
    """
    if not tool_name:
        return 'Other'
    return VULN_CATEGORY_MAP.get(tool_name, tool_name)


def is_recon_category(category):
    """Check if a vuln_category represents recon output (not a vulnerability)."""
    return category in ('Subdomain', 'Live Host', 'URL')


def is_vulnerability_category(category):
    """Check if a vuln_category represents an actual vulnerability."""
    return not is_recon_category(category)
