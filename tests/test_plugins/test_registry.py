"""Tests for ToolRegistry."""
import pytest
from unittest.mock import patch, MagicMock
from app.plugins.registry import ToolRegistry, tool_registry


class TestToolRegistry:
    """Test suite for the ToolRegistry class."""

    def test_supported_tools_populated(self):
        """SUPPORTED_TOOLS dict should contain expected tools (simplified set)."""
        assert 'subfinder' in ToolRegistry.SUPPORTED_TOOLS
        assert 'httpx' in ToolRegistry.SUPPORTED_TOOLS
        assert 'waybackurls' in ToolRegistry.SUPPORTED_TOOLS
        assert 'xss' in ToolRegistry.SUPPORTED_TOOLS  # vuln_scan entry
        assert 'sqli' in ToolRegistry.SUPPORTED_TOOLS
        # Simplified registry has exactly 18 tools (3 recon + 15 vuln_scan)
        assert len(ToolRegistry.SUPPORTED_TOOLS) == 18

    def test_each_tool_has_required_keys(self):
        """Every tool entry must have category, description, and version_flag."""
        for name, info in ToolRegistry.SUPPORTED_TOOLS.items():
            assert 'category' in info, f"{name} missing 'category'"
            assert 'description' in info, f"{name} missing 'description'"
            assert 'version_flag' in info, f"{name} missing 'version_flag'"

    def test_categories_are_valid(self):
        """All categories should be one of recon, vuln_scan."""
        valid = {'recon', 'vuln_scan'}
        for name, info in ToolRegistry.SUPPORTED_TOOLS.items():
            assert info['category'] in valid, f"{name} has invalid category: {info['category']}"

    def test_get_tools_by_category_recon(self):
        """get_tools_by_category('recon') should return only recon tools."""
        registry = ToolRegistry()
        recon = registry.get_tools_by_category('recon')
        assert len(recon) == 3  # subfinder, httpx, waybackurls
        for name, info in recon.items():
            assert info['category'] == 'recon'

    def test_get_tools_by_category_vuln_scan(self):
        """get_tools_by_category('vuln_scan') should return only vuln_scan tools."""
        registry = ToolRegistry()
        vuln = registry.get_tools_by_category('vuln_scan')
        assert len(vuln) == 15  # 15 vulnerability categories
        for name, info in vuln.items():
            assert info['category'] == 'vuln_scan'

    def test_get_tools_by_category_utility_removed(self):
        """get_tools_by_category('utility') should return empty (utility removed)."""
        registry = ToolRegistry()
        util = registry.get_tools_by_category('utility')
        assert len(util) == 0

    def test_get_tools_by_category_empty_for_invalid(self):
        """get_tools_by_category with invalid category returns empty dict."""
        registry = ToolRegistry()
        assert registry.get_tools_by_category('nonexistent') == {}

    @patch('app.plugins.registry.subprocess.run')
    def test_check_tool_installed(self, mock_run):
        """check_tool returns True when tool exits with code 0."""
        mock_run.return_value = MagicMock(returncode=0)
        registry = ToolRegistry()
        assert registry.check_tool('subfinder') is True

    @patch('app.plugins.registry.subprocess.run')
    def test_check_tool_not_installed(self, mock_run):
        """check_tool returns False when FileNotFoundError is raised."""
        mock_run.side_effect = FileNotFoundError
        registry = ToolRegistry()
        assert registry.check_tool('subfinder') is False

    @patch('app.plugins.registry.subprocess.run')
    def test_check_tool_non_zero_exit(self, mock_run):
        """check_tool returns False when tool exits with non-zero code."""
        mock_run.return_value = MagicMock(returncode=1)
        registry = ToolRegistry()
        assert registry.check_tool('subfinder') is False

    @patch('app.plugins.registry.subprocess.run')
    def test_check_tool_timeout(self, mock_run):
        """check_tool returns False on timeout."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd='subfinder', timeout=5)
        registry = ToolRegistry()
        assert registry.check_tool('subfinder') is False

    def test_check_tool_unknown(self):
        """check_tool returns False for unknown tool names."""
        registry = ToolRegistry()
        assert registry.check_tool('nonexistent_tool_xyz') is False

    @patch('app.plugins.registry.subprocess.run')
    def test_check_all_tools(self, mock_run):
        """check_all_tools checks every tool and returns status dict."""
        mock_run.return_value = MagicMock(returncode=0)
        registry = ToolRegistry()
        status = registry.check_all_tools()
        assert isinstance(status, dict)
        assert len(status) == len(ToolRegistry.SUPPORTED_TOOLS)

    @patch('app.plugins.registry.subprocess.run')
    def test_get_installed_tools(self, mock_run):
        """get_installed_tools returns only tools with True status."""
        # Make all tools "installed"
        mock_run.return_value = MagicMock(returncode=0)
        registry = ToolRegistry()
        registry.check_all_tools()
        installed = registry.get_installed_tools()
        assert isinstance(installed, list)
        assert len(installed) == len(ToolRegistry.SUPPORTED_TOOLS)

    @patch('app.plugins.registry.subprocess.run')
    def test_get_installed_tools_none(self, mock_run):
        """get_installed_tools returns empty list when no tools installed."""
        mock_run.side_effect = FileNotFoundError
        registry = ToolRegistry()
        registry.check_all_tools()
        installed = registry.get_installed_tools()
        assert installed == []

    @patch('app.plugins.registry.subprocess.run')
    def test_is_tool_available_cached(self, mock_run):
        """is_tool_available uses cache on second call."""
        mock_run.return_value = MagicMock(returncode=0)
        registry = ToolRegistry()
        assert registry.is_tool_available('subfinder') is True
        # Second call should use cache, not subprocess
        assert registry.is_tool_available('subfinder') is True
        # subprocess.run should only have been called once
        assert mock_run.call_count == 1

    @patch('app.plugins.registry.subprocess.run')
    def test_is_tool_available_not_installed(self, mock_run):
        """is_tool_available returns False when tool not installed."""
        mock_run.side_effect = FileNotFoundError
        registry = ToolRegistry()
        assert registry.is_tool_available('subfinder') is False

    def test_get_categories(self):
        """get_categories returns the distinct categories."""
        registry = ToolRegistry()
        cats = registry.get_categories()
        assert 'recon' in cats
        assert 'vuln_scan' in cats

    def test_get_tool_info(self):
        """get_tool_info returns metadata for a known tool."""
        registry = ToolRegistry()
        # 'xss' is a vuln_scan entry that maps to dalfox binary
        info = registry.get_tool_info('xss')
        assert info['category'] == 'vuln_scan'
        assert 'description' in info
        assert 'version_flag' in info

    def test_get_tool_info_unknown(self):
        """get_tool_info returns empty dict for unknown tool."""
        registry = ToolRegistry()
        assert registry.get_tool_info('no_such_tool') == {}

    def test_global_registry_instance(self):
        """Module-level tool_registry should be a ToolRegistry instance."""
        from app.plugins.registry import tool_registry as tr
        assert isinstance(tr, ToolRegistry)
