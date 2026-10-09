"""CISA Known Exploited Vulnerabilities catalogue (FR-8)."""
import httpx
from langsmith import traceable

from app.config import HTTP_TIMEOUT
from app.tools import cache

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _fetch() -> list[str]:
    r = httpx.get(URL, timeout=HTTP_TIMEOUT, follow_redirects=True)
    r.raise_for_status()
    return [v["cveID"] for v in r.json()["vulnerabilities"]]


@traceable(name="cisa_kev", run_type="tool")
def kev_set() -> set[str]:
    """All KEV CVE ids; empty when the feed is unreachable and was never cached."""
    try:
        return set(cache.cached("kev", "catalog", _fetch))
    except (httpx.HTTPError, cache.OfflineMiss, ValueError, KeyError):
        return set()
