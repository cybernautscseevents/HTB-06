"""Agent 3: Risk Analysis. Decides how reachable each vulnerability is, then scores and ranks.

One agent, two steps in the graph:
  1. worker_node  - one worker per finding, fanned out in parallel with Send(). Finds the vulnerable
                    function (curated map, else the LLM with its answer validated in code), scans the
                    application source and assigns L0 / L1 / L2 with evidence. FR-10..FR-15.
  2. rank_node    - runs once all workers have reported. Computes the risk score, ranks, and writes
                    explanations for the top findings. FR-16..FR-18.

A worker receives the Send payload {"finding", "repo_dir", "venv_dir", "allow_llm"} and returns
{"reach_results": [one Reachability dict]}, which the operator.add reducer merges.
"""
import json
import re
from functools import lru_cache

from app import config, db, stubs
from app.state import AuditState
from app.tools import ast_scanner, callgraph, llm, osv, packages
from app.tools.versions import normalize


# --- Step 1: reachability worker (one per finding, in parallel) ----------------------------------------

@lru_cache(maxsize=1)
def _curated() -> dict:
    return json.loads((config.DATA_DIR / "curated_vuln_functions.json").read_text(encoding="utf-8"))


def curated_functions(finding: dict) -> list[str]:
    by_id = _curated().get(normalize(finding["package"]), {})
    for vid in [finding["id"], *finding["aliases"]]:
        if vid in by_id:
            return by_id[vid]
    return []


def vulnerable_functions(finding: dict, venv_dir: str | None, allow_llm: bool = True) -> tuple[list[str], str]:
    """(function names, source). Curated map first, else LLM extraction validated in code (FR-11, FR-12)."""
    curated = curated_functions(finding)
    if curated:
        return curated, "curated"
    if not allow_llm:
        return [], "none"
    try:
        record = osv.get_vuln(finding["id"])
        advisory = f"{record.get('summary', '')}\n\n{record.get('details', '')}"
    except Exception:  # noqa: BLE001 - offline miss or network error: use what is in state
        advisory = finding["summary"]
    candidates = llm.extract_functions(finding["id"], finding["package"], advisory)
    return packages.validate_functions(venv_dir, finding["package"], candidates), "llm"


def analyse(finding: dict, repo_dir: str | None, venv_dir: str | None, allow_llm: bool = True) -> dict:
    result = {"finding_id": finding["id"], "level": "L1", "functions": [], "evidence": [], "note": None,
              "path": []}
    if not repo_dir:
        result["note"] = "source unavailable; assumed imported"
        return result

    roots = list(packages.import_names(venv_dir, finding["package"]))
    if not ast_scanner.scan(repo_dir, roots, [])["imports"]:
        # Never imported: L0 whatever the vulnerable function is, so no LLM call is spent on it.
        result.update(level="L0", note="not imported")
        return result
    functions, _source = vulnerable_functions(finding, venv_dir, allow_llm)
    scan = ast_scanner.scan(repo_dir, roots, functions)
    result["functions"] = functions

    if scan["calls"]:                                    # vulnerable function called directly
        result.update(level="L2", evidence=scan["calls"])
        return result

    # Indirect: the application calls a public function of the package whose own code reaches
    # the vulnerable function (static call graph of the installed package).
    entries = callgraph.entry_points(venv_dir, finding["package"], functions) if functions else {}
    indirect = ast_scanner.scan(repo_dir, roots, callgraph.entry_names(entries))["calls"] if entries else []
    if indirect:
        called = indirect[0]["call"]
        path = callgraph.path_for(entries, called) or []
        if not path or path[0].split(".")[-1] != called.split(".")[-1] or len(called.split(".")) > 2:
            path = [called, *path]                       # show what the application wrote first
        result.update(level="L2", evidence=indirect, path=path,
                      note=f"reached indirectly through {called}")
    elif scan["safe_calls"]:                             # FR-15: called, but only in a known-safe way
        result.update(level="L1", evidence=scan["safe_calls"],
                      note="downgraded: " + "; ".join(scan["safe_notes"]))
    else:                                                # imported, vulnerable function not called
        result.update(level="L1", evidence=scan["imports"],
                      note=None if functions else "no vulnerable function identified")
    return result


def worker_node(payload: dict) -> dict:
    finding = payload["finding"]
    if config.STUBS["risk_analysis"]:
        return {"reach_results": [stubs.REACH.get(finding["id"], {
            "finding_id": finding["id"], "level": "L0", "functions": [], "evidence": [], "note": None})]}
    try:
        result = analyse(finding, payload.get("repo_dir"), payload.get("venv_dir"),
                         payload.get("allow_llm", True))
    except Exception as e:  # noqa: BLE001 - one bad worker must not sink the audit
        result = {"finding_id": finding["id"], "level": "L1", "functions": [], "evidence": [],
                  "note": f"analysis failed, assumed imported: {str(e)[:120]}"}
    return {"reach_results": [result]}


def worker_id(payload: dict) -> str:
    return payload["finding"]["id"]


def describe_worker(payload: dict, update: dict) -> tuple[str, str]:
    r = update["reach_results"][0]
    detail = f"{payload['finding']['package']}: {r['level']}"
    if r["evidence"]:
        detail += f" at {r['evidence'][0]['file']}:{r['evidence'][0]['line']}"
    return "done", detail


# --- Step 2: score and rank (once, after every worker) -----------------------------------------------------

ID_PATTERN = re.compile(r"\b(?:CVE-\d{4}-\d+|GHSA(?:-[0-9a-z]{4}){3}|PYSEC-\d{4}-\d+)\b", re.I)


def compute_score(finding: dict, reach: dict) -> tuple[float, dict]:
    rw = config.REACH_WEIGHT[reach["level"]]
    kev = config.KEV_BOOST if finding["kev"] else 1.0
    direct = config.DIRECT_BOOST if finding["direct"] else 1.0
    epss_factor = 1 + finding["epss"]
    score = finding["cvss"] * rw * epss_factor * kev * direct
    breakdown = {"cvss": finding["cvss"], "reach_weight": rw, "epss_factor": epss_factor,
                 "kev_boost": kev, "direct_boost": direct}
    return round(score, 3), breakdown


def template_explanation(s: dict) -> str:
    f, r = s["finding"], s["reach"]
    vuln = f["cve"] or f["id"]
    if r["level"] == "L2":
        e = r["evidence"][0]
        where = f"and the vulnerable code is called at {e['file']}:{e['line']}"
    elif r["level"] == "L1":
        where = "and the package is imported, though no call to the vulnerable function was found"
    else:
        where = "but the package is never imported by the application"
    fix = f"Upgrade to {f['fixed_in'][0]} or later." if f["fixed_in"] else "No fixed version is published yet."
    return f"{f['package']} {f['version']} is affected by {vuln} (CVSS {f['cvss']:.1f}), {where}. {fix}"


def _facts(s: dict) -> dict:
    f, r = s["finding"], s["reach"]
    return {
        "finding_id": f["id"], "package": f["package"], "version": f["version"], "cve": f["cve"],
        "summary": f["summary"], "cvss": f["cvss"], "epss": round(f["epss"], 3), "in_cisa_kev": f["kev"],
        "direct_dependency": f["direct"], "fixed_in": f["fixed_in"][:1],
        "reachability": {"L0": "package never imported", "L1": "package imported, vulnerable function not called",
                         "L2": "vulnerable function called"}[r["level"]],
        "vulnerable_functions": r["functions"],
        "evidence": [f"{e['file']}:{e['line']}" for e in r["evidence"][:2]],
    }


def _grounded(text: str, s: dict) -> bool:
    """Reject LLM text that cites a vulnerability id the finding does not carry (FR-18)."""
    known = {i.upper() for i in [s["finding"]["id"], *s["finding"]["aliases"]]}
    return bool(text) and len(text) <= 600 and all(m.upper() in known for m in ID_PATTERN.findall(text))


def rank_node(state: AuditState) -> dict:
    reach_by_id = {r["finding_id"]: r for r in state.get("reach_results", [])}
    scored = []
    for f in state.get("findings", []):
        reach = reach_by_id.get(f["id"]) or {"finding_id": f["id"], "level": "L1", "functions": [],
                                              "evidence": [], "note": "not analysed; assumed imported"}
        score, breakdown = compute_score(f, reach)
        scored.append({"finding": f, "reach": reach, "score": score,
                       "breakdown": breakdown, "rank": 0, "explanation": None})
    scored.sort(key=lambda s: (-s["score"], -s["finding"]["cvss"], s["finding"]["id"]))
    for i, s in enumerate(scored, start=1):
        s["rank"] = i

    top = scored[: config.TOP_EXPLAIN]
    written = llm.explain_findings([_facts(s) for s in top]) if top else {}
    for s in top:
        text = written.get(s["finding"]["id"], "")
        s["explanation"] = text if _grounded(text, s) else template_explanation(s)   # NFR-3 fallback
    return {"scored": scored, "since_last": since_last(state.get("repo_url", ""), scored)}


def since_last(repo_url: str, scored: list[dict]) -> dict | None:
    """Per-repository memory: which findings are new or gone since the last audit of this repo."""
    try:
        previous = db.kv_get("memory", "last_audit", repo_url)
    except Exception:  # noqa: BLE001 - memory is a convenience, never a reason to fail an audit
        return None
    if not previous:
        return None
    now, before = {s["finding"]["id"] for s in scored}, set(previous["finding_ids"])
    return {"previous_run_id": previous["run_id"], "previous_at": previous.get("at", 0.0),
            "new": sorted(now - before), "resolved": sorted(before - now), "unchanged": len(now & before)}


def describe_ranking(_state: dict, update: dict) -> tuple[str, str]:
    scored = update["scored"]
    if not scored:
        return "done", "no vulnerabilities to rank"
    levels = [s["reach"]["level"] for s in scored]
    top = scored[0]["finding"]
    since = update.get("since_last")
    delta = f"; {len(since['new'])} new, {len(since['resolved'])} resolved since last audit" if since else ""
    return "done", (f"L2: {levels.count('L2')}, L1: {levels.count('L1')}, L0: {levels.count('L0')}; "
                    f"top risk {top['package']} {top['cve'] or top['id']}{delta}")
