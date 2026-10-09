from langgraph.types import Command

from app.graph import graph

START = {"repo_url": "x", "reach_results": [], "verifier_attempts": 0, "bad_versions": []}


def test_stub_graph_pauses_then_opens_pr(stubs):
    cfg = {"configurable": {"thread_id": "approve"}}
    graph.invoke(START, cfg)
    state = graph.get_state(cfg)
    assert state.next == ("human_gate",)
    assert state.values.get("pr_url") is None          # FR-24: nothing written before approval
    out = graph.invoke(Command(resume={"approved": True}), cfg)
    assert out["pr_url"] and out["status"] == "completed"


def test_stub_graph_reject_makes_no_pr(stubs):
    cfg = {"configurable": {"thread_id": "reject"}}
    graph.invoke(START, cfg)
    out = graph.invoke(Command(resume={"approved": False}), cfg)
    assert out["status"] == "rejected" and not out.get("pr_url")   # FR-26
