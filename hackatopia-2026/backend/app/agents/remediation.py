"""Agent 4: Remediation. Proposes a fix and verifies it before anyone sees it.

One agent, two steps in the graph, with a loop between them:
  1. propose_node - chooses the smallest safe version per package, patches the manifest (and the
                    files it includes), builds the diff and the PR text. FR-19..FR-21.
  2. verify_node  - the critic. Re-queries OSV at the proposed versions and runs
                    `pip install --dry-run`. A failure goes back to step 1 with the rejected
                    versions; after MAX_VERIFIER_RETRIES the run ends without a pull request. FR-22, FR-23.

Versions, CVE lists and the manifest patch are computed in code; the LLM only words the PR.
"""
import difflib
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from langsmith import traceable
from packaging.requirements import InvalidRequirement, Requirement

from app import config, stubs
from app.agents.risk_analysis import ID_PATTERN
from app.state import AuditState
from app.tools import cache, llm, osv
from app.tools.syft import MANIFEST, flat_manifest, flatten, manifest_files, parse_manifest, venv_python
from app.tools.textio import read_source, to_source
from app.tools.versions import highest, is_major_bump, newer_than, normalize, parse

LEVEL_ORDER = {"L0": 0, "L1": 1, "L2": 2}


def _eligible(s: dict) -> bool:
    """FR-20: patch only reachable (L1/L2) or actively exploited (KEV) findings."""
    return s["reach"]["level"] in ("L1", "L2") or s["finding"]["kev"]


def _forced_bad(package: str) -> str | None:
    """Demo hook (AC-3): FORCE_BAD_VERSION=pkg==ver is proposed on the first attempt only."""
    name, _, version = config.FORCE_BAD_VERSION.partition("==")
    version = version.strip()
    return version if parse(version) and normalize(name) == normalize(package) else None


def choose_version(package: str, current: str, items: list[dict], bad: list[dict],
                   same_major: bool = False) -> str | None:
    """Highest of the per-vulnerability minimal fixes (FR-19), skipping versions the verifier rejected.

    With same_major=True only fixes that stay on the current major version are considered.
    """
    def allowed(v: str) -> bool:
        return not (same_major and is_major_bump(current, v))

    minimal = [s["finding"]["fixed_in"][0] for s in items if _eligible(s) and s["finding"]["fixed_in"]]
    target = highest([v for v in minimal if allowed(v)])
    if not target:
        return None
    rejected = {b["version"]: b for b in bad if normalize(b["package"]) == normalize(package)}
    pool = newer_than([v for s in items for v in s["finding"]["fixed_in"]]
                      + [b["suggest"] for b in rejected.values() if b.get("suggest")], current)
    pool = [v for v in pool if allowed(v)]
    floor = parse(target)
    for b in rejected.values():  # never go back below something already proven insufficient
        for v in (b["version"], b.get("suggest")):
            if v and parse(v) and parse(v) > floor:
                floor = parse(v)
    for candidate in pool:
        if parse(candidate) >= floor and candidate not in rejected:
            return candidate
    return None


def plan(scored: list[dict], bad: list[dict], first_attempt: bool) -> dict:
    by_pkg: dict[str, list[dict]] = {}
    for s in scored:
        by_pkg.setdefault(s["finding"]["package"], []).append(s)

    changes, manual, closed_ids = [], [], set()
    for package, items in sorted(by_pkg.items()):
        if not any(_eligible(s) for s in items):
            continue
        current = items[0]["finding"]["version"]

        def change_for(version: str) -> tuple[dict, list[dict]]:
            # A finding is closed when its minimal fix is at or below the chosen version.
            closed = [s for s in items if s["finding"]["fixed_in"]
                      and parse(s["finding"]["fixed_in"][0]) <= parse(version)]
            return {"package": package, "old": current, "new": version,
                    "cves_closed": sorted({s["finding"]["cve"] or s["finding"]["id"] for s in closed})}, closed

        new = choose_version(package, current, items, bad)
        if first_attempt and _forced_bad(package):
            new = _forced_bad(package)
        if new and is_major_bump(current, new):                           # FR-21
            full, _ = change_for(new)
            # Still take the best fix available without leaving the current major version.
            new = choose_version(package, current, items, bad, same_major=True)
            partial = set(change_for(new)[0]["cves_closed"]) if new else set()
            full["cves_closed"] = [c for c in full["cves_closed"] if c not in partial]
            manual.append(full)
        if not new:
            # Every candidate was rejected by the verifier: surface it instead of dropping it.
            rejected = [b["version"] for b in bad if normalize(b["package"]) == normalize(package)]
            if rejected and package not in {c["package"] for c in manual}:
                manual.append({"package": package, "old": current, "new": rejected[-1], "cves_closed": []})
            continue
        change, closed = change_for(new)
        changes.append(change)
        closed_ids |= {s["finding"]["id"] for s in closed}
    manual_pkgs = {c["package"] for c in manual}
    not_patched = [s["finding"]["id"] for s in scored
                   if s["finding"]["id"] not in closed_ids and s["finding"]["package"] not in manual_pkgs]
    return {"changes": changes, "manual_review": manual, "not_patched": not_patched}


def patch_manifests(files: dict[str, str], changes: list[dict]) -> dict[str, str]:
    """Apply the changes across requirements.txt and the files it includes. Each pin is rewritten
    in the file it lives in; packages pinned nowhere (transitive) are appended to the root file.
    Returns only the files that changed."""
    def names(text: str) -> set[str]:
        return {normalize(r.name) for r in parse_manifest(text)}

    pinned_somewhere = set().union(*(names(t) for t in files.values())) if files else set()
    primary = next(iter(files), MANIFEST)         # where pins for transitive packages are added
    out = {}
    for rel, text in files.items():
        here = names(text)
        mine = [c for c in changes if normalize(c["package"]) in here]
        if rel == primary:
            mine += [c for c in changes if normalize(c["package"]) not in pinned_somewhere]
        if mine:
            new = patch_manifest(text, mine)
            if new != text:
                out[rel] = new
    return out


def patch_manifest(text: str, changes: list[dict]) -> str:
    """Rewrite pins in one requirements file; packages not pinned in it get an explicit pin appended."""
    targets = {normalize(c["package"]): c for c in changes}
    done, out = set(), []
    for raw in text.splitlines():
        body, sep, comment = raw.partition(" #")
        try:
            req = Requirement(body.strip()) if body.strip() and not body.lstrip().startswith(("#", "-")) else None
        except InvalidRequirement:
            req = None
        change = targets.get(normalize(req.name)) if req else None
        if not change:
            out.append(raw)
            continue
        extras = f"[{','.join(sorted(req.extras))}]" if req.extras else ""
        marker = f"; {req.marker}" if req.marker else ""
        padding = body[len(body.rstrip()):] if sep else ""
        out.append(f"{req.name}{extras}=={change['new']}{marker}{padding}{sep}{comment}")
        done.add(normalize(req.name))
    for name, change in targets.items():
        if name not in done:
            out.append(f"{change['package']}=={change['new']}  # transitive dependency pinned by security audit")
    return "\n".join(out) + "\n"


def unified_diff(old: str, new: str, path: str = MANIFEST) -> str:
    return "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                        fromfile=f"a/{path}", tofile=f"b/{path}"))


def _evidence_cell(package: str, scored: list[dict]) -> str:
    items = [s for s in scored if s["finding"]["package"] == package]
    best = max(items, key=lambda s: LEVEL_ORDER[s["reach"]["level"]])
    level, evidence = best["reach"]["level"], best["reach"]["evidence"]
    return f"{level} `{evidence[0]['file']}:{evidence[0]['line']}`" if evidence else level


def pr_text(result: dict, scored: list[dict], manifest: str = MANIFEST) -> tuple[str, str]:
    changes = result["changes"]
    if len(changes) == 1:
        c = changes[0]
        title = f"fix(deps): bump {c['package']} from {c['old']} to {c['new']}"
    else:
        title = f"fix(deps): security updates for {len(changes)} packages"
    closed = sorted({cve for c in changes for cve in c["cves_closed"]})
    summary = (f"Updates {len(changes)} package(s) in `{manifest}` to close {len(closed)} known "
               f"vulnerabilit{'y' if len(closed) == 1 else 'ies'} that are reachable from this application "
               "or actively exploited.")

    # LLM call site 3: wording only. Rejected unless every id it cites is one this PR closes.
    draft = llm.draft_pr_text({"changes": changes, "manifest": manifest}) if changes else None
    if draft and 0 < len(draft.title) <= 72 and "\n" not in draft.title and draft.summary.strip():
        cited = {m.upper() for m in ID_PATTERN.findall(f"{draft.title} {draft.summary}")}
        if cited <= {c.upper() for c in closed}:
            title, summary = draft.title.strip(), draft.summary.strip()

    by_id = {s["finding"]["id"]: s for s in scored}
    lines = ["## Security dependency updates", "", summary, "",
             "| Package | Old | New | CVEs closed | Reachability evidence |", "|---|---|---|---|---|"]
    lines += [f"| {c['package']} | {c['old']} | {c['new']} | {', '.join(c['cves_closed']) or 'n/a'} | "
              f"{_evidence_cell(c['package'], scored)} |" for c in changes]
    if result["manual_review"]:
        lines += ["", "### Manual review (major version bumps, not included)"]
        lines += [f"- {c['package']} {c['old']} -> {c['new']} ({', '.join(c['cves_closed']) or 'n/a'})"
                  for c in result["manual_review"]]
    if result["not_patched"]:
        lines += ["", "### Not patched"]
        for fid in result["not_patched"]:
            s = by_id[fid]
            f = s["finding"]
            why = ("not reachable (L0)" if s["reach"]["level"] == "L0" and not f["kev"]
                   else "no fixed version available" if not f["fixed_in"] else "not closed by the chosen version")
            lines.append(f"- {f['package']} {f['version']}: {f['cve'] or f['id']}, {why}")
    lines += ["", "_Generated by Agentic SBOM Risk Auditor._"]
    return title, "\n".join(lines)


def propose_node(state: AuditState) -> dict:
    if config.STUBS["remediation"]:
        stub_manifest = "pyyaml==5.4\nrequests==2.25.0\n"
        return {"patched_manifest": stub_manifest, "patched_manifests": {MANIFEST: stub_manifest},
                "flat_manifest": stub_manifest, "remediation": {
            "changes": [{"package": "pyyaml", "old": "5.3", "new": "5.4", "cves_closed": ["CVE-2020-14343"]}],
            "manual_review": [],
            "not_patched": ["GHSA-pillow-fake"],
            "diff": stubs.DIFF,
            "pr_title": "fix(deps): bump pyyaml to 5.4 (CVE-2020-14343)",
            "pr_body": "| package | old | new | CVEs | reachability |\n|---|---|---|---|---|\n"
                       "| pyyaml | 5.3 | 5.4 | CVE-2020-14343 | L2 app/config_loader.py:12 |",
        }}

    scored = state.get("scored", [])
    result = plan(scored, state.get("bad_versions", []), first_attempt=state.get("verifier_attempts", 0) == 0)

    # requirements.txt and whatever it includes with -r: a pin is patched in the file it lives in.
    repo_dir = state.get("repo_dir")
    originals = manifest_files(repo_dir) if repo_dir else {}
    if repo_dir and not originals and result["changes"]:
        # The audit ran from a shipped SBOM and the repository has no requirements file to edit.
        result = {**result, "manual_review": [*result["manual_review"], *result["changes"]], "changes": []}
    changed = patch_manifests(originals, result["changes"]) if result["changes"] else {}
    patched = {**originals, **changed}
    primary = next(iter(originals), MANIFEST)
    title, body = pr_text(result, scored, ", ".join(changed) or primary)

    def on_disk(rel: str, text: str) -> str:
        """Keep each file's own line endings, so the commit only touches the lines it means to."""
        return to_source(text, read_source(Path(repo_dir) / rel)[1])

    return {
        "patched_manifest": on_disk(primary, patched[primary]) if primary in patched else "",
        "patched_manifests": {rel: on_disk(rel, text) for rel, text in changed.items()},
        "flat_manifest": flatten(patched),            # what the verifier asks pip to resolve
        "remediation": {**result, "pr_title": title, "pr_body": body,
                        "diff": "".join(unified_diff(originals[rel], changed[rel], rel) for rel in changed)},
    }


def route_after_proposal(state: AuditState) -> str:
    """A proposal with upgrades is verified; with none there is nothing to verify."""
    return "remediation_verify" if state["remediation"]["changes"] else "code_fix"


def _summary(remediation: dict) -> str:
    text = ", ".join(f"{c['package']} {c['old']} -> {c['new']}" for c in remediation["changes"]) or "nothing to patch"
    if remediation["manual_review"]:
        text += f"; {len(remediation['manual_review'])} for manual review"
    return text


def describe_proposal(state: dict, update: dict) -> tuple[str, str]:
    """With upgrades the agent is not finished yet (verification follows), so it stays `running`."""
    r = update["remediation"]
    detail = _summary(r)
    if state.get("verifier_attempts", 0):
        detail = f"retry {state['verifier_attempts']}: {detail}"
    return ("running", f"proposed {detail}; verifying") if r["changes"] else ("done", detail)



# --- Step 2: verify the proposal (the critic) ---------------------------------------------------------

@traceable(name="recheck_osv_at_new_versions", run_type="tool")
def check_vulnerabilities(changes: list[dict]) -> tuple[list[dict], list[str]]:
    """Returns (bad_versions, notes)."""
    bad, notes = [], []
    for c in changes:
        try:
            records = [osv.get_vuln(vid) for vid in osv.query_one(c["package"], c["new"])]
        except Exception as e:  # noqa: BLE001 - offline cache miss or network failure
            notes.append(f"warning: could not re-check {c['package']} {c['new']} against OSV ({type(e).__name__})")
            continue
        remaining, fixes, seen = [], [], set()
        for rec in sorted(records, key=lambda r: (not r["id"].startswith("GHSA-"), r["id"])):
            ids = {rec["id"], *rec.get("aliases", [])}
            if rec.get("withdrawn") or ids & seen:      # one advisory, several databases
                continue
            seen |= ids
            newer = newer_than(osv.fixed_versions(rec, c["package"]), c["new"])
            reachable_fix = [v for v in newer if not is_major_bump(c["old"], v)]
            if reachable_fix:               # still vulnerable and a better version exists
                remaining.append(rec["id"])
                fixes.append(reachable_fix[0])
            elif newer:                     # FR-21: major bumps are never automatic
                notes.append(f"note: {c['package']} {c['new']} still has {rec['id']}; "
                             f"the fix ({newer[0]}) is a major upgrade left for manual review")
            else:
                notes.append(f"note: {c['package']} {c['new']} still has {rec['id']}, which has no fixed release")
        if remaining:
            suggest = highest(fixes)
            reason = f"{c['package']} {c['new']} is still affected by {', '.join(sorted(remaining))}"
            bad.append({"package": c["package"], "version": c["new"], "reason": reason, "suggest": suggest})
            notes.append(f"FAIL: {reason}; fixed in {suggest}")
    return bad, notes


def _pip_python(venv_dir: str | None) -> str | None:
    candidates = [str(venv_python(venv_dir))] if venv_dir else []
    for py in [*candidates, sys.executable]:
        if not Path(py).exists():
            continue
        try:
            r = subprocess.run([py, "-m", "pip", "--version"], capture_output=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if r.returncode == 0:
            return py
    return None


@traceable(name="pip_dry_run", run_type="tool")
def dry_run(manifest_text: str, venv_dir: str | None) -> dict:
    """{"ok": bool | None, "output": str}. ok=None means the check could not be run."""
    def run() -> dict:
        py = _pip_python(venv_dir)
        if not py:
            return {"ok": None, "output": "no Python with pip available"}
        fd, path = tempfile.mkstemp(suffix=".txt", prefix="requirements-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(manifest_text)
            r = subprocess.run(
                [py, "-m", "pip", "install", "--dry-run", "--ignore-installed", "--no-input",
                 "--disable-pip-version-check", "-r", path],
                capture_output=True, text=True, timeout=config.DRY_RUN_TIMEOUT,
                encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            return {"ok": None, "output": "pip dry-run timed out"}
        finally:
            os.unlink(path)
        if r.returncode != 0 and "no such option: --dry-run" in r.stderr:
            return {"ok": None, "output": "pip is older than 22.2 (no --dry-run)"}
        lines = (r.stderr or r.stdout).strip().splitlines()
        errors = [ln.strip() for ln in lines if ln.lstrip().lower().startswith("error")]
        return {"ok": r.returncode == 0, "output": "\n".join(errors[:4] or lines[-4:])}

    key = hashlib.sha256(manifest_text.encode()).hexdigest()
    hit = cache.get("dryrun", key)
    if hit is not None:
        return hit
    if config.OFFLINE:
        return {"ok": None, "output": "offline and not cached"}
    result = run()
    if result["ok"] is not None:  # a skipped check must not stick in the cache
        cache.put("dryrun", key, result)
    return result


def check_resolution(original: str, patched: str, changes: list[dict],
                     venv_dir: str | None) -> tuple[list[dict], list[str]]:
    result = dry_run(patched, venv_dir)
    if result["ok"] is None:
        return [], [f"warning: dependency resolution check skipped ({result['output']})"]
    if result["ok"]:
        return [], ["pip install --dry-run resolved the patched manifest"]
    # Baseline: a manifest that never resolved on this interpreter says nothing about the patch.
    if original and dry_run(original, venv_dir)["ok"] is False:
        return [], ["warning: the original manifest does not resolve on this Python either, so the "
                    f"resolution check is inconclusive: {result['output'][-300:]}"]
    # Find the culprit: pins that cannot be installed on their own, else whatever pip names.
    output = result["output"].lower()
    blamed = [c for c in changes if dry_run(f"{c['package']}=={c['new']}\n", venv_dir)["ok"] is False]
    blamed = blamed or [c for c in changes if c["package"].lower() in output] or changes
    bad = [{"package": c["package"], "version": c["new"], "suggest": None,
            "reason": "patched manifest does not resolve"} for c in blamed]
    return bad, [f"FAIL: pip install --dry-run could not resolve the manifest: {result['output'][-400:]}"]


def _original_manifest(repo_dir: str | None) -> str:
    """The manifest as pip sees it: the root file with its -r includes inlined."""
    return flat_manifest(repo_dir) if repo_dir and Path(repo_dir).is_dir() else ""


def verify_node(state: AuditState) -> dict:
    attempt = state.get("verifier_attempts", 0) + 1
    if config.STUBS["remediation"]:
        return {"verifier_attempts": attempt, "verification": {"ok": True, "notes": [], "attempt": attempt}}

    changes = state["remediation"]["changes"]
    bad, notes = check_vulnerabilities(changes)
    if not bad:  # only resolve a manifest whose versions are already known to be clean
        bad, more = check_resolution(_original_manifest(state.get("repo_dir")),
                                     state.get("flat_manifest") or state.get("patched_manifest") or "",
                                     changes, state.get("venv_dir"))
        notes += more
    return {
        "verifier_attempts": attempt,
        "bad_versions": [*state.get("bad_versions", []), *bad],
        "verification": {"ok": not bad, "notes": notes, "attempt": attempt},
    }


def route_after_verification(state: AuditState) -> str:
    if state["verification"]["ok"]:
        return "code_fix"
    if state["verifier_attempts"] > config.MAX_VERIFIER_RETRIES:
        return "give_up"
    return "remediation"


def describe_verification(state: dict, update: dict) -> tuple[str, str]:
    v = update["verification"]
    if v["ok"]:
        caveats = sum(not n.startswith("pip install") for n in v["notes"])
        detail = f"{_summary(state['remediation'])}; verified on attempt {v['attempt']}"
        return "done", detail + (f" ({caveats} notes for the reviewer)" if caveats else "")
    failures = "; ".join(n[6:] for n in v["notes"] if n.startswith("FAIL: "))[:300]
    status = "failed" if v["attempt"] > config.MAX_VERIFIER_RETRIES else "retry"
    return status, f"attempt {v['attempt']}: {failures}"
