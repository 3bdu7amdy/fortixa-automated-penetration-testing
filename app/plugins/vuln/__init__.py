"""Vulnerability scanner tool runner plugins."""
from app.plugins.vuln.dalfox import DalfoxRunner
from app.plugins.vuln.nuclei import NucleiRunner
from app.plugins.vuln.sqlmap import SqlmapRunner
from app.plugins.vuln.xsstrike import XSStrikeRunner
from app.plugins.vuln.ghauri import GhauriRunner
from app.plugins.vuln.nosqli import NosqliRunner
from app.plugins.vuln.ssrfmap import SSRFMapRunner
from app.plugins.vuln.tplmap import TplmapRunner
from app.plugins.vuln.commix import CommixRunner
from app.plugins.vuln.testssl import TestsslRunner
from app.plugins.vuln.wafw00f import Wafw00fRunner
from app.plugins.vuln.subzy import SubzyRunner
from app.plugins.vuln.dnsx import DnsxRunner

VULN_RUNNERS = {
    'dalfox': DalfoxRunner,
    'nuclei': NucleiRunner,
    'sqlmap': SqlmapRunner,
    'xsstrike': XSStrikeRunner,
    'ghauri': GhauriRunner,
    'nosqli': NosqliRunner,
    'ssrfmap': SSRFMapRunner,
    'tplmap': TplmapRunner,
    'commix': CommixRunner,
    'testssl': TestsslRunner,
    'wafw00f': Wafw00fRunner,
    'subzy': SubzyRunner,
    'dnsx': DnsxRunner,
}

__all__ = [
    'DalfoxRunner',
    'NucleiRunner',
    'SqlmapRunner',
    'XSStrikeRunner',
    'GhauriRunner',
    'NosqliRunner',
    'SSRFMapRunner',
    'TplmapRunner',
    'CommixRunner',
    'TestsslRunner',
    'Wafw00fRunner',
    'SubzyRunner',
    'DnsxRunner',
    'VULN_RUNNERS',
]
