from app.agents.remediation import patch_manifest, plan, unified_diff
from app.tools import osv


def scored(package, version, fixed_in, level="L2", fid=None, kev=False):
    fid = fid or f"GHSA-{package}-{fixed_in[0] if fixed_in else 'nofix'}"
    return {
        "finding": {"id": fid, "cve": None, "aliases": [], "package": package, "version": version,
                    "fixed_in": fixed_in, "kev": kev},
        "reach": {"level": level, "evidence": []},
    }


def test_highest_of_minimal_fixes():
    items = [scored("jinja2", "2.10", ["2.10.1", "3.0.0"]), scored("jinja2", "2.10", ["2.11.3"])]
    r = plan(items, [], first_attempt=True)
    assert [(c["package"], c["new"]) for c in r["changes"]] == [("jinja2", "2.11.3")]
    assert len(r["changes"][0]["cves_closed"]) == 2 and r["not_patched"] == []


def test_l0_is_reported_not_patched():
    r = plan([scored("pillow", "8.0.0", ["8.1.0"], level="L0", fid="A")], [], first_attempt=True)
    assert r["changes"] == [] and r["not_patched"] == ["A"]


def test_kev_is_patched_even_when_unreachable():
    r = plan([scored("pillow", "8.0.0", ["8.1.0"], level="L0", kev=True)], [], first_attempt=True)
    assert r["changes"][0]["new"] == "8.1.0"


def test_major_bump_goes_to_manual_review():
    r = plan([scored("django", "2.2", ["3.0.1"])], [], first_attempt=True)
    assert r["changes"] == [] and r["manual_review"][0]["new"] == "3.0.1"


def test_rejected_version_is_replaced_by_suggestion():
    bad = [{"package": "pyyaml", "version": "5.3.1", "reason": "", "suggest": "5.4"}]
    r = plan([scored("pyyaml", "5.3", ["5.3.1"])], bad, first_attempt=False)
    assert r["changes"][0]["new"] == "5.4"


def test_patch_manifest_keeps_extras_markers_comments_and_pins_transitives():
    text = "# deps\nPyYAML==5.3  # config\nrequests[socks]>=2.0 ; python_version > '3.6'\n-r other.txt\n"
    out = patch_manifest(text, [{"package": "pyyaml", "new": "5.4"}, {"package": "requests", "new": "2.31.0"},
                                {"package": "urllib3", "new": "1.26.18"}])
    lines = out.splitlines()
    assert lines[1] == "PyYAML==5.4  # config"
    assert lines[2] == 'requests[socks]==2.31.0; python_version > "3.6"'
    assert lines[3] == "-r other.txt"
    assert lines[4].startswith("urllib3==1.26.18")
    assert "-PyYAML==5.3" in unified_diff(text, out)


def test_osv_dedupe_merges_alias_overlap():
    base = {"package": "pyyaml", "version": "5.3", "summary": "", "epss": 0, "kev": False, "direct": True}
    merged = osv.dedupe([
        {**base, "id": "PYSEC-2021-142", "aliases": ["CVE-2020-14343"], "cvss": 9.8, "fixed_in": ["5.4"], "cve": "CVE-2020-14343"},
        {**base, "id": "GHSA-8q59-q68h-6hv4", "aliases": ["CVE-2020-14343"], "cvss": 7.5, "fixed_in": ["5.4"], "cve": "CVE-2020-14343"},
        {**base, "id": "GHSA-other", "aliases": [], "cvss": 5.0, "fixed_in": [], "cve": None},
    ])
    assert len(merged) == 2
    m = next(f for f in merged if f["cve"])
    assert m["id"] == "GHSA-8q59-q68h-6hv4" and m["cvss"] == 9.8
    assert m["aliases"] == ["CVE-2020-14343", "PYSEC-2021-142"]


def test_major_bump_still_takes_the_best_same_major_fix():
    items = [scored("jinja2", "2.11.2", ["2.11.3"], fid="A"), scored("jinja2", "2.11.2", ["3.1.6"], fid="B")]
    r = plan(items, [], first_attempt=True)
    assert [(c["new"], c["cves_closed"]) for c in r["changes"]] == [("2.11.3", ["A"])]
    assert [(c["new"], c["cves_closed"]) for c in r["manual_review"]] == [("3.1.6", ["B"])]
    assert r["not_patched"] == []


def test_pins_in_included_files_are_found_and_patched_where_they_live(tmp_path):
    from app.agents.remediation import patch_manifests
    from app.tools import syft

    (tmp_path / "requirements").mkdir()
    (tmp_path / "requirements.txt").write_bytes(b"# used by the host\n-r requirements/prod.txt\n")
    (tmp_path / "requirements" / "prod.txt").write_bytes(b"-r common.txt\ngunicorn==19.7.1\n")
    (tmp_path / "requirements" / "common.txt").write_bytes(b"Flask==0.12.2\nJinja2==2.9.6\n")

    files = syft.manifest_files(tmp_path)
    assert list(files) == ["requirements.txt", "requirements/prod.txt", "requirements/common.txt"]
    assert [r.name for r in syft.parse_manifest(syft.flatten(files))] == ["gunicorn", "Flask", "Jinja2"]
    assert "-r" not in syft.flatten(files)

    changed = patch_manifests(files, [{"package": "jinja2", "new": "2.11.3"}, {"package": "urllib3", "new": "1.26.18"}])
    assert changed["requirements/common.txt"] == "Flask==0.12.2\nJinja2==2.11.3\n"          # patched where it is pinned
    assert changed["requirements.txt"].splitlines()[-1].startswith("urllib3==1.26.18")     # transitive: root file
    assert "requirements/prod.txt" not in changed


def test_requirements_are_found_anywhere_in_the_repository(tmp_path):
    from app.agents.remediation import patch_manifests
    from app.tools import syft

    def repo(name, files):
        root = tmp_path / name
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_bytes(text.encode())
        return root

    # the root file wins when it exists
    assert syft.find_manifests(repo("a", {"requirements.txt": "x==1\n", "backend/requirements.txt": "y==1\n"})) == ["requirements.txt"]
    # no root file: every requirements.txt at the shallowest depth, never docs / tests / vendored ones
    mono = repo("b", {"backend/requirements.txt": "flask==1.0\n", "worker/requirements.txt": "celery==4.0\n",
                      "docs/requirements.txt": "sphinx==1\n", "backend/deep/requirements.txt": "z==1\n",
                      "node_modules/pkg/requirements.txt": "q==1\n"})
    assert syft.find_manifests(mono) == ["backend/requirements.txt", "worker/requirements.txt"]
    assert [r.name for r in syft.parse_manifest(syft.flat_manifest(mono))] == ["flask", "celery"]
    # no file with the exact name: the most likely differently named one
    assert syft.find_manifests(repo("c", {"requirements/dev.txt": "a==1\n", "requirements/base.txt": "b==1\n"})) == ["requirements/base.txt"]
    assert syft.find_manifests(repo("d", {"src/app/requirements-prod.txt": "a==1\n"})) == ["src/app/requirements-prod.txt"]
    assert syft.find_manifests(repo("e", {"README.md": "nothing here\n"})) == []

    # a pin is patched in the file it lives in; a transitive pin goes to the primary (first) manifest
    changed = patch_manifests(syft.manifest_files(mono), [{"package": "celery", "new": "5.3.0"}, {"package": "urllib3", "new": "2.0.7"}])
    assert changed["worker/requirements.txt"] == "celery==5.3.0\n"
    assert changed["backend/requirements.txt"].splitlines() == ["flask==1.0", "urllib3==2.0.7  # transitive dependency pinned by security audit"]
