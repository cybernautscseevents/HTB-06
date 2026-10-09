"""Agent 2: Vuln Intel (no LLM). FR-5..FR-9."""
from concurrent.futures import ThreadPoolExecutor

from app import config, stubs
from app.events import emit
from app.state import AuditState
from app.tools import ast_scanner, epss, kev, osv, packages


def vuln_intel_node(state: AuditState) -> dict:
    if config.STUBS["vuln_intel"]:
        findings = sorted(stubs.FINDINGS, key=lambda f: -f["cvss"])[: config.MAX_FANOUT]
        return {"findings": findings}

    # Packages installed from a repository or URL are not PyPI releases: looking them up by name
    # would match an unrelated PyPI project, so they are listed in the SBOM but not checked here.
    components = [c for c in state.get("components", []) if c.get("source", "pypi") == "pypi"]
    by_key = {(c["name"], c["version"]): c for c in components}
    hits = osv.query_batch(components)                                   # FR-5: one batch request
    pairs = [(by_key[key], vid) for key, ids in hits.items() for vid in ids]
    emit("vuln_intel", "running", f"Fetching {len(pairs)} advisories")

    with ThreadPoolExecutor(max_workers=8) as pool:
        records = list(pool.map(lambda p: osv.get_vuln(p[1]), pairs))
    findings = [osv.to_finding(rec, comp) for (comp, _), rec in zip(pairs, records)
                if not rec.get("withdrawn")]
    findings = osv.dedupe(findings)                                      # FR-6

    def cves(f: dict) -> list[str]:
        return [i for i in [f["id"], *f["aliases"]] if i.startswith("CVE-")]

    scores = epss.epss_scores([c for f in findings for c in cves(f)])     # FR-8
    exploited = kev.kev_set()
    for f in findings:
        f["epss"] = max((scores.get(c, 0.0) for c in cves(f)), default=0.0)
        f["kev"] = any(c in exploited for c in cves(f))

    # Packages the application imports go first, so a cap can never hide a reachable finding
    # behind higher-CVSS alerts in packages that are never used.
    used = imported_packages(state.get("repo_dir"), state.get("venv_dir"), {f["package"] for f in findings})
    findings.sort(key=lambda f: (f["package"] not in used, -f["cvss"], f["package"], f["id"]))
    return {"findings": findings[: config.MAX_FINDINGS]}                  # NFR-6


def imported_packages(repo_dir: str | None, venv_dir: str | None, names: set[str]) -> set[str]:
    if not repo_dir:
        return set(names)
    roots = ast_scanner.imported_roots(repo_dir)
    return {n for n in names if roots & set(packages.import_names(venv_dir, n))}


def describe(_state: dict, update: dict) -> tuple[str, str]:
    findings = update["findings"]
    affected = len({f["package"] for f in findings})
    kev_count = sum(f["kev"] for f in findings)
    return "done", f"{len(findings)} vulnerabilities in {affected} packages ({kev_count} in CISA KEV)"
