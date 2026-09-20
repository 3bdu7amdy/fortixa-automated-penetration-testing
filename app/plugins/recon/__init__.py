"""Reconnaissance tool runner plugins."""
from app.plugins.recon.subfinder import SubfinderRunner
from app.plugins.recon.httpx import HttpxRunner
from app.plugins.recon.assetfinder import AssetfinderRunner
from app.plugins.recon.amass import AmassRunner
from app.plugins.recon.waybackurls import WaybackurlsRunner
from app.plugins.recon.gau import GauRunner
from app.plugins.recon.katana import KatanaRunner

RECON_RUNNERS = {
    'subfinder': SubfinderRunner,
    'httpx': HttpxRunner,
    'assetfinder': AssetfinderRunner,
    'amass': AmassRunner,
    'waybackurls': WaybackurlsRunner,
    'gau': GauRunner,
    'katana': KatanaRunner,
}

__all__ = [
    'SubfinderRunner',
    'HttpxRunner',
    'AssetfinderRunner',
    'AmassRunner',
    'WaybackurlsRunner',
    'GauRunner',
    'KatanaRunner',
    'RECON_RUNNERS',
]
