import json
import time

from fastapi.testclient import TestClient

from app import runs
from app.main import app


def wait_for(client, run_id, statuses, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        snap = client.get(f"/audit/{run_id}").json()
        if snap["status"] in statuses:
            return snap
        time.sleep(0.05)
    raise AssertionError(f"run stuck in {snap['status']}")


def sse(client, run_id):
    events, name = [], None
    with client.stream("GET", f"/audit/{run_id}/stream") as r:
        for line in r.iter_lines():
            if line.startswith("event:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("data:"):
                events.append((name, json.loads(line.split(":", 1)[1])))
    return events


def test_full_flow_over_http(stubs):
    with TestClient(app) as client:
        run_id = client.post("/audit", json={"repo_url": "https://github.com/example/demo-repo"}).json()["run_id"]
        snap = wait_for(client, run_id, {"awaiting_approval"})
        assert snap["scored"][0]["finding"]["package"] == "pyyaml" and snap["remediation"]["diff"]
        assert snap["pr_url"] is None

        events = sse(client, run_id)                       # replay, then done
        assert events[-1] == ("done", {"status": "awaiting_approval"})
        agents = [(e["agent"], e["status"]) for name, e in events if name == "agent"]
        assert agents[0] == ("sbom", "running") and agents[-1] == ("human_gate", "waiting")
        workers = {e["worker_id"] for name, e in events if name == "agent" and e["agent"] == "risk_analysis" and e["worker_id"]}
        assert len(workers) == 2

        assert client.post(f"/audit/{run_id}/decision", json={"approved": True}).json() == {"status": "resumed"}
        snap = wait_for(client, run_id, {"completed"})
        assert snap["pr_url"]
        assert client.post(f"/audit/{run_id}/decision", json={"approved": True}).status_code == 409
        assert sse(client, run_id)[-1] == ("done", {"status": "completed"})

        # history: listed while in memory, and still served from disk after a restart
        row = client.get("/audits").json()[0]
        assert row["run_id"] == run_id and row["status"] == "completed" and row["l2"] == 1 and row["changes"] == 1
        runs.RUNS.clear()
        assert client.get("/audits").json()[0]["run_id"] == run_id
        assert client.get(f"/audit/{run_id}").json()["pr_url"] == snap["pr_url"]
        assert sse(client, run_id)[-1] == ("done", {"status": "completed"})
        assert client.post(f"/audit/{run_id}/decision", json={"approved": True}).status_code == 404


def test_validation_and_404():
    with TestClient(app) as client:
        assert client.post("/audit", json={"repo_url": "file:///etc/passwd"}).status_code == 422
        assert client.post("/audit", json={"repo_url": "https://github.com/a/b --upload-pack=x"}).status_code == 422
        assert client.get("/audit/nope").status_code == 404


def test_merged_agents_report_as_one_agent_each(stubs):
    with TestClient(app) as client:
        run_id = client.post("/audit", json={"repo_url": "https://github.com/example/merged"}).json()["run_id"]
        wait_for(client, run_id, {"awaiting_approval"})
        events = [e for name, e in sse(client, run_id) if name == "agent"]
        assert {e["agent"] for e in events} == {"sbom", "vuln_intel", "risk_analysis", "remediation", "code_fix", "human_gate"}
        # risk analysis: parallel workers first, then one closing event without a worker id
        risk = [e for e in events if e["agent"] == "risk_analysis"]
        assert risk[-1]["worker_id"] is None and risk[-1]["status"] == "done" and "top risk" in risk[-1]["detail"]
        # remediation: stays running while its proposal is verified, then one done event
        rem = [(e["status"], e["detail"]) for e in events if e["agent"] == "remediation"]
        assert [s for s, _ in rem].count("done") == 1 and rem[-1][0] == "done" and "verified on attempt 1" in rem[-1][1]
        assert any(s == "running" and d.startswith("proposed") for s, d in rem)


def test_audits_stored_with_the_old_agent_names_still_load():
    from app.schemas import AgentEvent

    assert [AgentEvent(agent=a, status="done").agent for a in ("reachability", "triage", "verifier", "sbom")] == [
        "risk_analysis", "risk_analysis", "remediation", "sbom"]
