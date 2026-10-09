"""End-to-end run of the real agents against a local fake repo, with the network faked out."""
import pytest
from langgraph.types import Command

from app import config
from app.graph import graph

YAML_REC = {
    "id": "GHSA-8q59-q68h-6hv4", "aliases": ["CVE-2020-14343"], "summary": "Code execution in yaml.load",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [{"package": {"name": "PyYAML", "ecosystem": "PyPI"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}]}],
}
YAML_PYSEC = {**YAML_REC, "id": "PYSEC-2021-142"}
PILLOW_REC = {
    "id": "GHSA-pillow", "aliases": ["CVE-2020-35653"], "summary": "Buffer over-read",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
    "affected": [{"package": {"name": "pillow", "ecosystem": "PyPI"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "8.1.0"}]}]}],
}
RECORDS = {r["id"]: r for r in (YAML_REC, YAML_PYSEC, PILLOW_REC)}
VULNS = {("pyyaml", "5.3"): ["GHSA-8q59-q68h-6hv4", "PYSEC-2021-142"],
         ("pyyaml", "5.3.1"): ["GHSA-8q59-q68h-6hv4"],
         ("pillow", "8.0.0"): ["GHSA-pillow"]}


@pytest.fixture
def world(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "requirements.txt").write_bytes(b"PyYAML==5.3\nrequests==2.25.0\n")
    (repo / "app" / "config_loader.py").write_bytes(b"import yaml\n\n\ndef load(f):\n    return yaml.load(f)\n")
    components = [
        {"name": "pyyaml", "version": "5.3", "direct": True, "parents": []},
        {"name": "pillow", "version": "8.0.0", "direct": False, "parents": ["reportlab"]},
        {"name": "requests", "version": "2.25.0", "direct": True, "parents": []},
    ]
    monkeypatch.setattr(config, "STUBS", {k: False for k in config.STUBS})
    monkeypatch.setattr("app.tools.syft.components_for", lambda url, progress=None, token="": {
        "components": components, "source": "test", "repo_dir": str(repo), "venv_dir": None, "installed": False})
    monkeypatch.setattr("app.tools.osv.query_batch", lambda comps: {
        (c["name"], c["version"]): VULNS.get((c["name"], c["version"]), []) for c in comps})
    monkeypatch.setattr("app.tools.osv.get_vuln", lambda vid: RECORDS[vid])
    monkeypatch.setattr("app.tools.epss.epss_scores", lambda cves: {"CVE-2020-14343": 0.6})
    monkeypatch.setattr("app.tools.kev.kev_set", lambda: set())
    monkeypatch.setattr("app.agents.remediation.dry_run", lambda text, venv: {"ok": True, "output": ""})
    opened = []
    monkeypatch.setattr("app.tools.github.create_branch_commit_pr",
                        lambda url, files, title, body, token: opened.append(files) or "https://github.com/o/r/pull/7")
    return opened


def run(thread):
    cfg = {"configurable": {"thread_id": thread}}
    graph.invoke({"repo_url": "https://github.com/o/r", "reach_results": [], "verifier_attempts": 0,
                  "bad_versions": []}, cfg)
    return cfg, graph.get_state(cfg).values


def test_reachable_finding_outranks_higher_cvss_and_pr_opens(world):
    cfg, state = run("real-approve")
    top, second = state["scored"]
    assert len(state["findings"]) == 2                                   # GHSA + PYSEC merged (FR-6)
    assert top["finding"]["package"] == "pyyaml" and top["reach"]["level"] == "L2"   # AC-1
    assert top["reach"]["evidence"] == [{"file": "app/config_loader.py", "line": 5,
                                         "snippet": "return yaml.load(f)", "call": "yaml.load"}]       # AC-2
    assert second["finding"]["cvss"] > top["finding"]["cvss"] and second["reach"]["level"] == "L0"
    assert top["explanation"]

    r = state["remediation"]
    assert r["changes"] == [{"package": "pyyaml", "old": "5.3", "new": "5.4", "cves_closed": ["CVE-2020-14343"]}]
    assert r["not_patched"] == ["GHSA-pillow"]                           # FR-20
    assert "+PyYAML==5.4" in r["diff"] and "app/config_loader.py:5" in r["pr_body"]
    assert state["verification"]["ok"] and world == []                   # FR-24: nothing written yet

    out = graph.invoke(Command(resume={"approved": True}), cfg)
    assert out["pr_url"] == "https://github.com/o/r/pull/7"
    assert world[0]["requirements.txt"] == "PyYAML==5.4\nrequests==2.25.0\n"
    # the vulnerable call is rewritten too, and committed in the same pull request
    assert "return yaml.safe_load(f)" in world[0]["app/config_loader.py"]
    fix = out["code_fixes"][0]
    assert fix["file"] == "app/config_loader.py" and fix["changes"][0]["function"] == "load"
    assert fix["changes"][0]["issues"][0]["kind"] == "vulnerable" and "+    return yaml.safe_load(f)" in fix["diff"]
    assert "### Code changes" in out["remediation"]["pr_body"]


def test_critic_loop_recovers_from_forced_bad_version(world, monkeypatch):
    monkeypatch.setattr(config, "FORCE_BAD_VERSION", "pyyaml==5.3.1")
    _, state = run("real-critic")                                        # AC-3
    assert state["verifier_attempts"] == 2
    assert state["bad_versions"][0]["version"] == "5.3.1" and state["bad_versions"][0]["suggest"] == "5.4"
    assert state["verification"]["ok"] and state["remediation"]["changes"][0]["new"] == "5.4"


def test_unresolvable_fix_ends_in_report_without_pr(world, monkeypatch):
    # the original manifest resolves, the patched one does not
    monkeypatch.setattr("app.agents.remediation.dry_run",
                        lambda text, venv: {"ok": "5.3" in text, "output": "conflict"})
    _, state = run("real-unresolvable")
    r = state["remediation"]
    assert r["changes"] == [] and [c["package"] for c in r["manual_review"]] == ["pyyaml"]
    # the pin cannot be bumped, but the unsafe call can still be rewritten, so a PR is still offered
    assert state["code_fixes"] and state.get("pr_url") is None and world == []
    assert r["pr_title"] == "fix: replace deprecated and vulnerable API calls"


def test_crlf_files_keep_their_line_endings(world, tmp_path):
    repo = tmp_path / "repo"
    (repo / "requirements.txt").write_bytes(b"PyYAML==5.3\r\nrequests==2.25.0\r\n")
    (repo / "app" / "config_loader.py").write_bytes(b"import yaml\r\n\r\n\r\ndef load(f):\r\n    return yaml.load(f)\r\n")
    _, state = run("real-crlf")
    assert state["patched_manifest"] == "PyYAML==5.4\r\nrequests==2.25.0\r\n"
    assert state["patched_files"]["app/config_loader.py"].endswith("    return yaml.safe_load(f)\r\n")
    assert "\r" not in state["remediation"]["diff"]


def test_nothing_to_patch_and_nothing_to_rewrite_ends_in_a_report(world, tmp_path):
    (tmp_path / "repo" / "app" / "config_loader.py").write_bytes(b"import json\n")   # nothing imports yaml now
    _, state = run("real-clean")
    assert state["remediation"]["changes"] == [] and state["code_fixes"] == []
    assert state["status"] == "completed" and world == []


def test_verifier_stops_after_max_retries():
    from app.agents.remediation import route_after_verification as route_after_verifier

    failed = {"verification": {"ok": False}}
    assert route_after_verifier({**failed, "verifier_attempts": config.MAX_VERIFIER_RETRIES}) == "remediation"
    assert route_after_verifier({**failed, "verifier_attempts": config.MAX_VERIFIER_RETRIES + 1}) == "give_up"   # FR-23


def test_reject_writes_nothing(world):
    cfg, _ = run("real-reject")
    out = graph.invoke(Command(resume={"approved": False}), cfg)
    assert out["status"] == "rejected" and world == []                   # AC-4


def test_already_broken_manifest_does_not_block_the_fix(world, monkeypatch):
    monkeypatch.setattr("app.agents.remediation.dry_run", lambda text, venv: {"ok": False, "output": "no wheel"})
    _, state = run("real-baseline")
    v = state["verification"]
    assert v["ok"] and v["attempt"] == 1 and any("inconclusive" in n for n in v["notes"])
    assert state["remediation"]["changes"][0]["new"] == "5.4"


def test_cap_never_hides_findings_in_imported_packages(world, monkeypatch):
    # Only one LLM slot and pillow (never imported) has the higher CVSS: pyyaml must still be analysed first.
    monkeypatch.setattr(config, "MAX_FANOUT", 1)
    _, state = run("real-cap")
    assert [f["package"] for f in state["findings"]] == ["pyyaml", "pillow"]
    assert state["scored"][0]["reach"]["level"] == "L2" and len(state["scored"]) == 2
