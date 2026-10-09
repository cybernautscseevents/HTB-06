"""Run manager: executes the graph in a worker thread, fans agent events out to SSE subscribers
and stores every audit in the database.

Graph state is checkpointed in the database after every step, so an audit that is waiting at the
human gate can still be approved after the backend restarts.
"""
import asyncio
import logging
import time
import uuid

from langgraph.types import Command

from app import config, db
from app.graph import graph
from app.schemas import AgentEvent, AuditSnapshot, AuditSummary

log = logging.getLogger(__name__)


class Run:
    def __init__(self, run_id: str, repo_url: str, user: str | None = None, created_at: float | None = None):
        self.id = run_id
        self.repo_url = repo_url
        self.user = user
        self.created_at = created_at or time.time()
        self.events: list[AgentEvent] = []
        self.subscribers: list[asyncio.Queue] = []
        self.status = "running"
        self.error: str | None = None
        self.trace_url: str | None = None
        # Latest graph state, kept in memory so reading a snapshot never touches the checkpointer
        # while the graph is writing to it (and never costs a database round trip).
        self.values: dict = {}
        self.task: asyncio.Task | None = None
        self.config = {"configurable": {"thread_id": run_id}}

    def emit(self, ev: AgentEvent | None):
        if ev:
            ev.ts = ev.ts or time.time()
            self.events.append(ev)
        for q in self.subscribers:
            q.put_nowait(ev)  # None = this stream segment is finished


RUNS: dict[str, Run] = {}
# Summaries of stored audits, loaded from the database once and kept up to date as audits are
# saved, so the dashboard and history pages do not wait on a database round trip.
_stored: dict[str, AuditSummary] | None = None


def create_run(repo_url: str, user: str | None = None) -> Run:
    run = Run(uuid.uuid4().hex[:8], repo_url, user)
    RUNS[run.id] = run
    log.info("audit %s started for %s by %s", run.id, repo_url, user or "anonymous", extra={"run_id": run.id})
    run.task = asyncio.create_task(_execute(run, {
        "repo_url": repo_url, "reach_results": [], "verifier_attempts": 0, "bad_versions": [],
    }))
    return run


def resume_run(run: Run, approved: bool) -> None:
    run.status = "running"
    log.info("audit %s %s at the human gate", run.id, "approved" if approved else "rejected", extra={"run_id": run.id})
    run.task = asyncio.create_task(_execute(run, Command(resume={"approved": approved})))


def _trace_config(run: Run, trace_id: uuid.UUID) -> dict:
    """LangSmith: one named trace per graph execution, searchable by run id, repo and user."""
    return {**run.config, "run_id": trace_id, "run_name": f"audit {run.repo_url.removeprefix('https://github.com/')}",
            "tags": ["audit", f"run:{run.id}"],
            "metadata": {"audit_run_id": run.id, "repo_url": run.repo_url, "user": run.user or "anonymous",
                         "llm_model": config.LLM_MODEL}}


def _trace_url(trace_id: uuid.UUID) -> str | None:
    if not config.LANGSMITH_ENABLED:
        return None
    try:
        from langsmith import Client

        client = Client()
        client.flush()
        return client.read_run(trace_id).url
    except Exception as e:  # noqa: BLE001 - tracing is best effort
        log.warning("could not resolve the LangSmith trace URL: %s", str(e)[:200])
        return None


async def _execute(run: Run, graph_input) -> None:
    loop = asyncio.get_running_loop()
    trace_id = uuid.uuid4()
    cfg = _trace_config(run, trace_id)

    def on_chunk(mode: str, chunk) -> None:      # runs on the event loop
        if mode == "custom":
            run.emit(AgentEvent(**chunk))
        elif mode == "values":
            run.values = chunk
        elif "__interrupt__" in chunk:
            run.status = "awaiting_approval"
            run.emit(AgentEvent(agent="human_gate", status="waiting", detail="Awaiting approval"))

    def work() -> dict:
        # The synchronous stream keeps database checkpointing off the event loop.
        for mode, chunk in graph.stream(graph_input, cfg, stream_mode=["updates", "custom", "values"]):
            loop.call_soon_threadsafe(on_chunk, mode, chunk)
        return graph.get_state(run.config).values

    try:
        values = await asyncio.to_thread(work)
        await asyncio.sleep(0)                   # let queued on_chunk callbacks run first
        run.values = values
        if run.status != "awaiting_approval":
            run.status = values.get("status", "completed")
            run.error = values.get("error")
    except Exception as e:  # noqa: BLE001 - a node raised; its `failed` event is already emitted
        log.exception("audit %s failed", run.id, extra={"run_id": run.id})
        run.status = "failed"
        run.error = str(e)[:500]
    finally:
        log.info("audit %s is now %s", run.id, run.status, extra={"run_id": run.id})
        await asyncio.to_thread(_finish, run, trace_id)
        run.emit(None)


def _finish(run: Run, trace_id: uuid.UUID) -> None:
    run.trace_url = _trace_url(trace_id) or run.trace_url
    _persist(run)


def snapshot(run: Run) -> AuditSnapshot:
    v = run.values
    return AuditSnapshot(
        run_id=run.id, repo_url=run.repo_url, status=run.status, error=run.error,
        created_at=run.created_at, user=run.user, trace_url=run.trace_url,
        components=v.get("components", []), findings=v.get("findings", []),
        scored=v.get("scored", []), remediation=v.get("remediation"),
        verification=v.get("verification"), code_fixes=v.get("code_fixes", []),
        since_last=v.get("since_last"), pr_url=v.get("pr_url"), events=run.events,
    )


# --- Database --------------------------------------------------------------------------------------

def _persist(run: Run) -> None:
    """Snapshots hold only what the API already serves: no tokens, no repository source."""
    try:
        snap = snapshot(run)
        summary = _summary(snap)
        db.save_audit(run.id, run.repo_url, run.status, run.user, run.created_at,
                      summary.model_dump(), snap.model_dump_json())
        if _stored is not None:
            _stored[run.id] = summary
        if snap.scored and run.status != "running":
            # Per-repository memory: the next audit of this repo reports what is new or resolved.
            db.kv_put("memory", "last_audit", run.repo_url, {
                "run_id": run.id, "at": run.created_at, "finding_ids": [s.finding.id for s in snap.scored]})
    except Exception:  # noqa: BLE001 - storage must never break a run
        log.exception("could not save audit %s", run.id, extra={"run_id": run.id})


def stored_snapshot(run_id: str) -> AuditSnapshot | None:
    """An audit that is not in memory (it finished earlier, or the backend restarted)."""
    raw = db.load_audit(run_id) if run_id.isalnum() else None
    if not raw:
        return None
    try:
        snap = AuditSnapshot.model_validate_json(raw)
    except ValueError:
        return None
    if snap.status == "running":
        snap.status = "failed"
        snap.error = "The backend stopped while this audit was running. Run it again."
    return snap


def revive(run_id: str) -> Run | None:
    """Bring an audit that is waiting for approval back into memory from its checkpoint."""
    snap = stored_snapshot(run_id)
    if not snap or snap.status != "awaiting_approval":
        return None
    run = Run(run_id, snap.repo_url, snap.user, snap.created_at)
    state = graph.get_state(run.config)
    if not state.next:                           # no checkpoint to resume from
        return None
    run.values = state.values
    run.status, run.events, run.trace_url = "awaiting_approval", snap.events, snap.trace_url
    RUNS[run_id] = run
    log.info("audit %s restored from its checkpoint", run_id, extra={"run_id": run_id})
    return run


def get_snapshot(run_id: str) -> AuditSnapshot | None:
    run = RUNS.get(run_id)
    return snapshot(run) if run else stored_snapshot(run_id)


def _summary(s: AuditSnapshot) -> AuditSummary:
    levels = [x.reach.level for x in s.scored]
    return AuditSummary(
        run_id=s.run_id, repo_url=s.repo_url, status=s.status, created_at=s.created_at, user=s.user,
        components=len(s.components), findings=len(s.scored),
        l2=levels.count("L2"), l1=levels.count("L1"), l0=levels.count("L0"),
        changes=len(s.remediation.changes) if s.remediation else 0,
        code_fixes=sum(len(f.changes) for f in s.code_fixes), pr_url=s.pr_url,
    )


def load_history() -> dict[str, AuditSummary]:
    """Stored audit summaries; read from the database on first use (and at startup), then from memory."""
    global _stored
    if _stored is None:
        _stored = {row["run_id"]: AuditSummary.model_validate(row) for row in db.list_audits()}
    return _stored


def history() -> list[AuditSummary]:
    """Every audit, newest first. Runs still in memory are shown with their live status."""
    live = {run_id: _summary(snapshot(run)) for run_id, run in RUNS.items()}
    merged = {}
    for run_id, row in load_history().items():
        if run_id not in live and row.status == "running":
            row = row.model_copy(update={"status": "failed"})   # it was running when the backend stopped
        merged[run_id] = row
    merged.update(live)
    return sorted(merged.values(), key=lambda s: -s.created_at)
