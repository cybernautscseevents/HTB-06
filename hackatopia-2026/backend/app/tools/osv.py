"""OSV.dev client (FR-5, FR-6). Every response goes through the disk cache."""
import httpx
from langsmith import traceable

from app.config import HTTP_TIMEOUT
from app.tools import cache
from app.tools.cvss import base_score
from app.tools.versions import newer_than, normalize

OSV = "https://api.osv.dev/v1"
BATCH_SIZE = 500


def _query_chunk(pairs: list[tuple[str, str]]) -> list[list[str]]:
    body = {"queries": [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in pairs]}
    r = httpx.post(f"{OSV}/querybatch", json=body, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    return [[v["id"] for v in res.get("vulns", [])] for res in r.json()["results"]]


@traceable(name="osv_query_batch", run_type="tool")
def query_batch(components: list[dict]) -> dict[tuple[str, str], list[str]]:
    """{(name, version): [vuln ids]} for all components, one request per 500 (FR-5)."""
    pairs = sorted({(c["name"], c["version"]) for c in components})
    out: dict[tuple[str, str], list[str]] = {}
    for i in range(0, len(pairs), BATCH_SIZE):
        chunk = pairs[i:i + BATCH_SIZE]
        key = "|".join(f"{n}=={v}" for n, v in chunk)
        ids = cache.cached("osv_batch", key, lambda chunk=chunk: _query_chunk(chunk))
        out.update(dict(zip(chunk, ids)))
    return out


def query_one(name: str, version: str) -> list[str]:
    return query_batch([{"name": name, "version": version}]).get((name, version), [])


def get_vuln(vuln_id: str) -> dict:
    def fetch():
        r = httpx.get(f"{OSV}/vulns/{vuln_id}", timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        return r.json()

    return cache.cached("osv_vuln", vuln_id, fetch)


def fixed_versions(record: dict, package: str) -> list[str]:
    target = normalize(package)
    fixed = []
    for aff in record.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") != "PyPI" or normalize(pkg.get("name", "")) != target:
            continue
        for rng in aff.get("ranges", []):
            if rng.get("type") != "ECOSYSTEM":
                continue
            fixed += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    return fixed


def cve_of(ids: list[str]) -> str | None:
    return next((i for i in sorted(ids) if i.startswith("CVE-")), None)


def to_finding(record: dict, component: dict) -> dict:
    """OSV record -> schemas.Finding dict (EPSS and KEV are filled in later)."""
    ids = [record["id"], *record.get("aliases", [])]
    vectors = [s.get("score", "") for s in record.get("severity", [])]
    for aff in record.get("affected", []):
        vectors += [s.get("score", "") for s in aff.get("severity", [])]
    label = (record.get("database_specific") or {}).get("severity")
    return {
        "id": record["id"],
        "cve": cve_of(ids),
        "aliases": sorted(set(record.get("aliases", []))),
        "package": component["name"],
        "version": component["version"],
        "summary": record.get("summary") or (record.get("details") or "")[:200],
        "cvss": base_score(vectors, label),
        "epss": 0.0,
        "kev": False,
        "fixed_in": newer_than(fixed_versions(record, component["name"]), component["version"]),
        "direct": component["direct"],
    }


def dedupe(findings: list[dict]) -> list[dict]:
    """Merge findings of the same package whose id/alias sets overlap (FR-6).

    A GHSA and a PYSEC record for one CVE become a single finding: GHSA id preferred,
    highest CVSS, union of aliases and fixed versions.
    """
    groups: list[dict] = []  # {"ids": set, "items": [finding]}
    for f in findings:
        ids = {f["id"], *f["aliases"]}
        merged = {"ids": ids, "items": [f]}
        rest = []
        for g in groups:
            if g["items"][0]["package"] == f["package"] and g["ids"] & merged["ids"]:
                merged["ids"] |= g["ids"]
                merged["items"] += g["items"]
            else:
                rest.append(g)
        groups = rest + [merged]

    out = []
    for g in groups:
        items = sorted(g["items"], key=lambda f: (not f["id"].startswith("GHSA-"), f["id"]))
        primary = dict(items[0])
        primary["aliases"] = sorted(g["ids"] - {primary["id"]})
        primary["cve"] = cve_of(list(g["ids"]))
        primary["cvss"] = max(f["cvss"] for f in items)
        primary["summary"] = next((f["summary"] for f in items if f["summary"]), "")
        primary["fixed_in"] = newer_than([v for f in items for v in f["fixed_in"]], primary["version"])
        out.append(primary)
    return out
