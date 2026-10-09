import os
import time

from fastapi.testclient import TestClient

from app import auth, config, db, runs
from app.main import app
from app.tools import cache, deprecations, syft
from tests.test_api import sse, wait_for

REPO = "https://github.com/example/persist-demo"


def test_audit_waiting_for_approval_survives_a_restart(stubs):
    with TestClient(app) as client:
        run_id = client.post("/audit", json={"repo_url": REPO}).json()["run_id"]
        wait_for(client, run_id, {"awaiting_approval"})
        deadline = time.time() + 5                          # the snapshot is saved just after the pause
        while not runs.stored_snapshot(run_id) and time.time() < deadline:
            time.sleep(0.02)

        runs.RUNS.clear()                                   # what a backend restart does to memory
        snap = client.get(f"/audit/{run_id}").json()
        assert snap["status"] == "awaiting_approval" and snap["remediation"]["changes"]
        assert sse(client, run_id)[-1] == ("done", {"status": "awaiting_approval"})

        # the decision restores the run from its database checkpoint and carries on
        assert client.post(f"/audit/{run_id}/decision", json={"approved": True}).status_code == 200
        assert wait_for(client, run_id, {"completed", "failed"})["pr_url"]


def test_second_audit_reports_what_changed_since_the_first(stubs):
    with TestClient(app) as client:
        first = client.post("/audit", json={"repo_url": REPO + "-memory"}).json()["run_id"]
        assert wait_for(client, first, {"awaiting_approval"})["since_last"] is None
        deadline = time.time() + 5                          # the first audit is remembered just after it pauses
        while not db.kv_get("memory", "last_audit", REPO + "-memory") and time.time() < deadline:
            time.sleep(0.02)
        second = client.post("/audit", json={"repo_url": REPO + "-memory"}).json()["run_id"]
        since = wait_for(client, second, {"awaiting_approval"})["since_last"]
        assert since["previous_run_id"] == first and since["new"] == [] and since["unchanged"] == 2


def test_each_audit_has_its_own_log(stubs):
    with TestClient(app) as client:
        run_id = client.post("/audit", json={"repo_url": REPO + "-logs"}).json()["run_id"]
        wait_for(client, run_id, {"awaiting_approval"})
        deadline = time.time() + 5                          # log rows are written by a background thread
        while time.time() < deadline:
            lines = client.get(f"/audit/{run_id}/logs").json()
            if any("remediation done" in ln["message"] for ln in lines):
                break
            time.sleep(0.1)
        messages = [ln["message"] for ln in lines]
        assert any(m.startswith("sbom started") for m in messages) and any("risk_analysis done" in m for m in messages)
        assert {ln["run_id"] for ln in lines} == {run_id}
        assert {"sbom", "risk_analysis", "remediation"} <= {ln["agent"] for ln in lines}
        assert client.get("/audit/unknownrun/logs").json() == []


def test_sessions_survive_a_restart_and_tokens_are_encrypted_at_rest(monkeypatch):
    monkeypatch.setattr(config, "GITHUB_CLIENT_SECRET", "secret")
    sid = auth.create_session("gho_plain_token", {"login": "octo"})
    stored = db.get().query("SELECT sid, token FROM sessions")
    assert all("gho_plain_token" not in r["token"] and r["sid"] != sid for r in stored)

    auth._session_cache.clear()                             # restart

    class Request:
        cookies = {auth.SESSION_COOKIE: sid}

    assert auth.session_of(Request)["token"] == "gho_plain_token"
    auth.drop_session(sid)
    auth._session_cache.clear()
    assert auth.session_of(Request) is None


def test_cache_round_trips_values_including_none():
    cache.put("ns", "k", {"a": [1, 2]})
    cache.put("ns", "none", None)
    assert cache.get("ns", "k") == {"a": [1, 2]}
    assert cache.get("ns", "none", "miss") is None and cache.get("ns", "absent", "miss") == "miss"


def test_old_workspaces_are_deleted_and_recent_ones_kept(tmp_path):
    old, fresh = config.WORK_DIR / "aaaa", config.WORK_DIR / "bbbb"
    for w in (old, fresh):
        (w / "repo").mkdir(parents=True)
        (w / syft.LAST_USED).write_text("x")
    forty_days_ago = time.time() - 40 * 86400
    os.utime(old / syft.LAST_USED, (forty_days_ago, forty_days_ago))
    assert syft.cleanup_workspaces(30) == 1
    assert not old.exists() and fresh.exists()


def test_deprecations_are_discovered_from_installed_source(tmp_path, monkeypatch):
    pkg = tmp_path / "Lib" / "site-packages" / "lib"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text(
        "import warnings\n\n"
        "def old(x):\n    warnings.warn('old() is deprecated, use new()', DeprecationWarning, stacklevel=2)\n    return x\n\n"
        "def new(x):\n    return x\n\n"
        "def sometimes(x, legacy=False):\n    if legacy:\n        warnings.warn('legacy mode', DeprecationWarning)\n    return x\n\n"
        "class Client:\n"
        "    @deprecated('fetch() is deprecated, use get()')\n    def fetch(self):\n        pass\n"
        "    def get(self):\n        pass\n")
    monkeypatch.setattr("app.tools.packages.import_names", lambda venv, package: ("lib",))
    index = deprecations.Index({"lib", "datetime"}, str(tmp_path), [{"name": "lib", "version": "1.0"}])

    assert index.lookup("lib.old") == ("lib.old", "old() is deprecated, use new()")
    assert index.lookup("lib.Client.fetch") == ("lib.Client.fetch", "fetch() is deprecated, use get()")
    assert index.lookup("lib.make_client.fetch")[0] == "lib.Client.fetch"     # method on an untyped instance
    assert index.lookup("lib.new") is None and index.lookup("lib.Client.get") is None
    assert index.lookup("lib.sometimes") is None            # only warns on one branch: not deprecated as a whole
    # the standard library is scanned the same way, for the Python that is running
    name, advice = index.lookup("datetime.datetime.utcnow")
    assert name == "datetime.datetime.utcnow" and "deprecated" in advice.lower()


def test_history_is_served_from_memory_after_the_first_load(stubs, monkeypatch):
    with TestClient(app) as client:
        run_id = client.post("/audit", json={"repo_url": REPO + "-cached"}).json()["run_id"]
        wait_for(client, run_id, {"awaiting_approval"})
        deadline = time.time() + 5
        while not runs.stored_snapshot(run_id) and time.time() < deadline:
            time.sleep(0.02)
        runs.RUNS.clear()                                   # only the stored copy is left
        assert any(a["run_id"] == run_id for a in client.get("/audits").json())

        def no_database(*_a, **_k):
            raise AssertionError("history must not query the database again")

        monkeypatch.setattr(db, "list_audits", no_database)
        rows = client.get("/audits", params={"repo_url": REPO + "-cached"}).json()
        assert [a["run_id"] for a in rows] == [run_id] and rows[0]["status"] == "awaiting_approval"
