"""Configuration model - scan configurations and tool settings."""
import json
from app.extensions import db
from app.models.base import BaseModel


class Configuration(BaseModel):
    """Configuration model.

    Stores scan configurations - which tools to use, what parameters,
    and what thresholds. Tool settings are stored as JSON for flexibility.
    """
    __tablename__ = 'configurations'

    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=True, index=True)
    name = db.Column(db.String(120), nullable=False)
    config_type = db.Column(db.String(30), nullable=False, index=True)  # recon, vuln_scan, full, custom
    tool_settings = db.Column(db.Text, nullable=False)  # JSON string
    is_default = db.Column(db.Boolean, nullable=False, default=False)

    def get_tool_settings(self):
        """Parse the JSON tool_settings string into a Python dict."""
        try:
            return json.loads(self.tool_settings)
        except (json.JSONDecodeError, TypeError):
            return {}

    def set_tool_settings(self, settings_dict):
        """Serialize a Python dict into the JSON tool_settings string."""
        self.tool_settings = json.dumps(settings_dict, indent=2)

    def get_enabled_tools(self):
        """Return a list of tool names that are enabled in this config."""
        settings = self.get_tool_settings()
        return [name for name, opts in settings.items() if opts.get('enabled', False)]

    def get_tool_options(self, tool_name):
        """Return the options dict for a specific tool."""
        settings = self.get_tool_settings()
        return settings.get(tool_name, {})

    @staticmethod
    def create_default_configs():
        """Create the built-in default configurations.

        Simplified to use only the most important tools that are widely
        installed and produce reliable results:
          - Recon: subfinder + httpx + waybackurls
          - Vulns: 15 high-value categories (XSS, SQLi, SSTi, CMDi, LFI,
                   SSRF, Open Redirect, SSL, WAF, Subdomain Takeover,
                   Security Headers, Clickjacking, CVEs, Admin Panels,
                   Default Credentials)
        """
        defaults = {
            'Quick Recon': {
                'config_type': 'recon',
                'tool_settings': {
                    'subfinder': {'enabled': True, 'flags': ['-all', '-recursive'], 'timeout': 300},
                    'httpx': {'enabled': True, 'flags': ['-status-code', '-title', '-tech-detect'], 'timeout': 300}
                }
            },
            'Full Recon': {
                'config_type': 'recon',
                'tool_settings': {
                    'subfinder': {'enabled': True, 'flags': ['-all', '-recursive'], 'timeout': 300},
                    'httpx': {'enabled': True, 'flags': ['-status-code', '-title', '-tech-detect'], 'timeout': 300},
                    'waybackurls': {'enabled': True, 'flags': [], 'timeout': 300}
                }
            },
            'Vulnerability Scan': {
                'config_type': 'vuln_scan',
                'tool_settings': {
                    # Phase 3b - host-based checks
                    'ssl_issues': {'enabled': True, 'flags': [], 'timeout': 600},
                    'waf_detection': {'enabled': True, 'flags': [], 'timeout': 120},
                    'subdomain_takeover': {'enabled': True, 'flags': [], 'timeout': 300},
                    'security_headers': {'enabled': True, 'flags': [], 'timeout': 300},
                    'clickjacking': {'enabled': True, 'flags': [], 'timeout': 300},
                    'cves': {'enabled': True, 'flags': [], 'timeout': 1800},
                    'admin_panels': {'enabled': True, 'flags': [], 'timeout': 300},
                    'default_credentials': {'enabled': True, 'flags': [], 'timeout': 300},
                    # Phase 4 - injection scans
                    'xss': {'enabled': True, 'flags': [], 'timeout': 600},
                    'sqli': {'enabled': True, 'flags': ['--batch', '--random-agent'], 'timeout': 1800},
                    'ssti': {'enabled': True, 'flags': [], 'timeout': 600},
                    'command_injection': {'enabled': True, 'flags': [], 'timeout': 600},
                    'lfi': {'enabled': True, 'flags': [], 'timeout': 600},
                    'ssrf_nuclei': {'enabled': True, 'flags': [], 'timeout': 600},
                    'open_redirect': {'enabled': True, 'flags': [], 'timeout': 300},
                }
            },
            'Full Pentest': {
                'config_type': 'full',
                'tool_settings': {
                    # Phase 1: Subdomain discovery
                    'subfinder': {'enabled': True, 'flags': ['-all', '-recursive'], 'timeout': 300},
                    # Phase 2: HTTP probing
                    'httpx': {'enabled': True, 'flags': ['-status-code', '-title', '-tech-detect'], 'timeout': 300},
                    # Phase 3a: URL gathering
                    'waybackurls': {'enabled': True, 'flags': [], 'timeout': 300},
                    # Phase 3b: Host-based checks (8 tools)
                    'ssl_issues': {'enabled': True, 'flags': [], 'timeout': 600},
                    'waf_detection': {'enabled': True, 'flags': [], 'timeout': 120},
                    'subdomain_takeover': {'enabled': True, 'flags': [], 'timeout': 300},
                    'security_headers': {'enabled': True, 'flags': [], 'timeout': 300},
                    'clickjacking': {'enabled': True, 'flags': [], 'timeout': 300},
                    'cves': {'enabled': True, 'flags': [], 'timeout': 1800},
                    'admin_panels': {'enabled': True, 'flags': [], 'timeout': 300},
                    'default_credentials': {'enabled': True, 'flags': [], 'timeout': 300},
                    # Phase 4: Injection scans (7 tools)
                    'xss': {'enabled': True, 'flags': [], 'timeout': 600},
                    'sqli': {'enabled': True, 'flags': ['--batch', '--random-agent'], 'timeout': 1800},
                    'ssti': {'enabled': True, 'flags': [], 'timeout': 600},
                    'command_injection': {'enabled': True, 'flags': [], 'timeout': 600},
                    'lfi': {'enabled': True, 'flags': [], 'timeout': 600},
                    'ssrf_nuclei': {'enabled': True, 'flags': [], 'timeout': 600},
                    'open_redirect': {'enabled': True, 'flags': [], 'timeout': 300},
                }
            }
        }
        for name, config in defaults.items():
            existing = Configuration.query.filter_by(name=name, is_default=True).first()
            if not existing:
                cfg = Configuration(
                    name=name,
                    config_type=config['config_type'],
                    tool_settings=json.dumps(config['tool_settings'], indent=2),
                    is_default=True,
                    project_id=None
                )
                cfg.save()

    def __repr__(self):
        return f'<Configuration {self.name} [{self.config_type}]>'
