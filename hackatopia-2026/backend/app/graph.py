"""LangGraph wiring (PRD section 5).

Seven agents. Two of them own two graph nodes each:

START -> sbom -> vuln_intel -> risk_analysis -> remediation -> code_fix -> human_gate -> open_pr

  risk_analysis = [risk_analysis_worker x N, in parallel] -> risk_analysis (score and rank)
  remediation   = remediation (propose) <-> remediation_verify (critic, max 2 retries)

human_gate pauses with interrupt(); a rejection, a failed verification or an empty fix end the run early.
"""
from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from app import config, db
from app.agents import code_fix, open_pr, remediation, risk_analysis, sbom, vuln_intel
from app.agents.human_gate import human_gate_node, route_after_gate
from app.events import traced
from app.state import AuditState


def fan_out_reachability(state: AuditState):
    """Parallel fan-out: one worker per finding (FR-10).

    vuln_intel ordered the list with imported packages first; only the first MAX_FANOUT workers
    may use the LLM (NFR-6), the rest still get the deterministic import/call scan.
    """
    findings = state.get("findings", [])
    if not findings:
        return "risk_analysis"
    return [Send("risk_analysis_worker", {"finding": f, "repo_dir": state.get("repo_dir"),
                                  "venv_dir": state.get("venv_dir"), "allow_llm": i < config.MAX_FANOUT})
            for i, f in enumerate(findings)]


def give_up_node(state: AuditState) -> dict:
    return {"status": "failed",
            "error": "Verification failed after the maximum number of retries; no pull request was "
                     "proposed. The risk report is still available."}


def rejected_node(state: AuditState) -> dict:
    return {"status": "rejected"}


def report_node(state: AuditState) -> dict:
    """Nothing safe to patch automatically: finish with the report only."""
    return {"status": "completed"}


def build_graph():
    g = StateGraph(AuditState)
    g.add_node("sbom", traced("sbom", sbom.describe)(sbom.sbom_node))
    g.add_node("vuln_intel", traced("vuln_intel", vuln_intel.describe)(vuln_intel.vuln_intel_node))
    # Risk Analysis agent: parallel reachability workers, then one scoring step.
    g.add_node("risk_analysis_worker", traced("risk_analysis", risk_analysis.describe_worker, risk_analysis.worker_id)(
        risk_analysis.worker_node))
    g.add_node("risk_analysis", traced("risk_analysis", risk_analysis.describe_ranking)(risk_analysis.rank_node))
    # Remediation agent: propose a fix, then verify it; a failed check loops back.
    g.add_node("remediation", traced("remediation", remediation.describe_proposal)(remediation.propose_node))
    g.add_node("remediation_verify", traced("remediation", remediation.describe_verification)(remediation.verify_node))
    g.add_node("code_fix", traced("code_fix", code_fix.describe)(code_fix.code_fix_node))
    g.add_node("human_gate", human_gate_node)
    g.add_node("open_pr", traced("open_pr", open_pr.describe)(open_pr.open_pr_node))
    g.add_node("give_up", give_up_node)
    g.add_node("rejected", rejected_node)
    g.add_node("report", report_node)

    g.add_edge(START, "sbom")
    g.add_edge("sbom", "vuln_intel")
    g.add_conditional_edges("vuln_intel", fan_out_reachability, ["risk_analysis_worker", "risk_analysis"])
    g.add_edge("risk_analysis_worker", "risk_analysis")
    g.add_edge("risk_analysis", "remediation")
    g.add_conditional_edges("remediation", remediation.route_after_proposal,
                            {"remediation_verify": "remediation_verify", "code_fix": "code_fix"})
    g.add_conditional_edges("remediation_verify", remediation.route_after_verification,
                            {"code_fix": "code_fix", "remediation": "remediation", "give_up": "give_up"})
    g.add_conditional_edges("code_fix", code_fix.route_after_code_fix,
                            {"human_gate": "human_gate", "report": "report"})
    g.add_conditional_edges("human_gate", route_after_gate, {"open_pr": "open_pr", "rejected": "rejected"})
    for terminal in ("open_pr", "rejected", "give_up", "report"):
        g.add_edge(terminal, END)

    # Checkpoints live in the database (Neon, or local SQLite), so an audit waiting at the human
    # gate survives a backend restart and can still be approved.
    return g.compile(checkpointer=db.get().checkpointer())


graph = build_graph()
