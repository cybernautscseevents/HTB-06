"""EPSS exploit probability (FR-8). https://api.first.org/data/v1/epss"""
import httpx
from langsmith import traceable

from app.config import HTTP_TIMEOUT
from app.tools import cache

URL = "https://api.first.org/data/v1/epss"
CHUNK = 80


def _fetch(cves: list[str]) -> dict[str, float]:
    r = httpx.get(URL, params={"cve": ",".join(cves)}, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    return {row["cve"]: float(row["epss"]) for row in r.json().get("data", [])}


@traceable(name="epss_scores", run_type="tool")
def epss_scores(cves: list[str]) -> dict[str, float]:
    """{cve: probability}. CVEs unknown to EPSS, or unreachable offline, are simply absent."""
    cves = sorted(set(cves))
    out: dict[str, float] = {}
    for i in range(0, len(cves), CHUNK):
        chunk = cves[i:i + CHUNK]
        try:
            out.update(cache.cached("epss", ",".join(chunk), lambda chunk=chunk: _fetch(chunk)))
        except (httpx.HTTPError, cache.OfflineMiss, ValueError, KeyError):
            continue
    return out
