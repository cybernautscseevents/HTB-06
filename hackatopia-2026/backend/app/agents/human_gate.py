"""Agent 7: Human Gate (no LLM). FR-24, FR-26. Pauses the graph until POST /audit/{id}/decision.

Not wrapped by events.traced: interrupt() raises to suspend the graph, and the node re-runs
from the top on resume. app/runs.py emits the `waiting` event when it sees the interrupt.
"""
from langgraph.types import interrupt

from app.events import emit
from app.state import AuditState


def human_gate_node(state: AuditState) -> dict:
    decision = interrupt({
        "remediation": state.get("remediation"),
        "verification": state.get("verification"),
        "top_findings": state.get("scored", [])[:5],
    })
    approved = bool(isinstance(decision, dict) and decision.get("approved"))
    emit("human_gate", "done", "approved" if approved else "rejected")
    return {"approved": approved}


def route_after_gate(state: AuditState) -> str:
    return "open_pr" if state.get("approved") else "rejected"
