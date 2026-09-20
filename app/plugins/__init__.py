"""Plugins package - security tool runners."""
from app.plugins.base import BaseToolRunner
from app.plugins.recon import RECON_RUNNERS
from app.plugins.vuln import VULN_RUNNERS

# Unified mapping: tool name -> runner class
TOOL_RUNNERS = {}
TOOL_RUNNERS.update(RECON_RUNNERS)
TOOL_RUNNERS.update(VULN_RUNNERS)

__all__ = ['BaseToolRunner', 'TOOL_RUNNERS', 'RECON_RUNNERS', 'VULN_RUNNERS']
