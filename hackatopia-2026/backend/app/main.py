"""FastAPI app (FR-27). Run: uvicorn app.main:app --reload"""
import asyncio
import json
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sse_starlette.sse import EventSourceResponse

from app import auth, config, db, logs, runs
from app.schemas import AuditRequest, AuditSnapshot, AuditSummary, DecisionRequest, LogLine
from app.tools import llm
from app.tools.syft import SbomError, cleanup_workspaces, parse_repo_url, syft_binary

log = logging.getLogger(__name__)
CLEANUP_INTERVAL = 6 * 3600


async def _cleanup_loop():
    """Delete cloned repositories that have not been audited for WORKSPACE_TTL_DAYS."""
    while True:
        try:
            removed = await asyncio.to_thread(cleanup_workspaces)
            if removed:
                log.info("removed %d cloned workspace(s) older than %g days", removed, config.WORKSPACE_TTL_DAYS)
        except Exception:  # noqa: BLE001 - housekeeping must not stop the app
            log.exception("workspace cleanup failed")
        await asyncio.sleep(CLEANUP_INTERVAL)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    logs.setup()
    log.info("starting: storage=%s, langsmith=%s, llm=%s", db.get().kind,
             "on" if config.LANGSMITH_ENABLED else "off", config.LLM_MODEL)
    await asyncio.to_thread(runs.load_history)       # warm the history so the first dashboard load is instant
    task = asyncio.create_task(_cleanup_loop())
    yield
    task.cancel()


app = FastAPI(title="Agentic SBOM Risk Auditor", lifespan=lifespan)
# allow_credentials: the session cookie set by /auth must travel with cross-origin fetches.
app.add_middleware(CORSMiddleware, allow_origins=[config.CORS_ORIGIN], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])
app.include_router(auth.router)


def _get(run_id: str) -> runs.Run:
    run = runs.RUNS.get(run_id)
    if not run:
        raise HTTPException(404, "run not found")
    return run


@app.get("/health")
def health():
    return {"ok": True, "offline": config.OFFLINE, "stubs": [k for k, v in config.STUBS.items() if v],
            "sbom_tool": "syft" if syft_binary() else "pipdeptree", "llm": llm.status(),
            "storage": db.get().kind, "langsmith": config.LANGSMITH_ENABLED,
            "workspace_ttl_days": config.WORKSPACE_TTL_DAYS}


@app.post("/audit")
async def start_audit(req: AuditRequest, request: Request):
    try:
        parse_repo_url(req.repo_url)
    except SbomError as e:
        raise HTTPException(422, str(e)) from e
    run = runs.create_run(req.repo_url.strip().rstrip("/").removesuffix(".git"), user=auth.login_of(request))
    auth.remember_run_token(run.id, request)
    return {"run_id": run.id}


@app.get("/audits", response_model=list[AuditSummary])
def list_audits(repo_url: str | None = None):
    """Audit history, newest first; kept on disk, so it survives restarts."""
    items = runs.history()
    return [a for a in items if a.repo_url == repo_url] if repo_url else items


@app.get("/audit/{run_id}", response_model=AuditSnapshot)
def get_audit(run_id: str):
    snap = runs.get_snapshot(run_id)
    if not snap:
        raise HTTPException(404, "run not found")
    return snap


@app.get("/audit/{run_id}/stream")
async def stream_audit(run_id: str):
    """SSE: replays past events, then follows the run until it pauses at the human gate or ends.

    Each `done` event closes the stream; after POST /decision the client opens it again.
    """
    run = runs.RUNS.get(run_id)
    if not run:     # an audit from before a restart: replay what was recorded
        stored = runs.stored_snapshot(run_id)
        if not stored:
            raise HTTPException(404, "run not found")

        async def replay():
            for ev in stored.events:
                yield {"event": "agent", "data": ev.model_dump_json()}
            yield {"event": "done", "data": json.dumps({"status": stored.status})}

        return EventSourceResponse(replay())
    q: asyncio.Queue = asyncio.Queue()
    for ev in run.events:  # replay for late subscribers
        q.put_nowait(ev)
    if run.task is None or run.task.done():
        q.put_nowait(None)  # nothing is executing: replay, then finish immediately
    else:
        run.subscribers.append(q)

    async def gen():
        try:
            while True:
                ev = await q.get()
                if ev is None:
                    yield {"event": "done", "data": json.dumps({"status": run.status})}
                    return
                yield {"event": "agent", "data": ev.model_dump_json()}
        finally:
            if q in run.subscribers:
                run.subscribers.remove(q)

    return EventSourceResponse(gen())


@app.get("/audit/{run_id}/logs", response_model=list[LogLine])
def audit_logs(run_id: str, limit: int = 1000):
    """Everything the backend logged while working on this audit, oldest first."""
    return db.read_logs(run_id, min(limit, 5000))


@app.get("/logs", response_model=list[LogLine])
def recent_logs(limit: int = 300):
    return db.read_logs(None, min(limit, 2000))


@app.post("/audit/{run_id}/decision")
async def decide(run_id: str, req: DecisionRequest, request: Request):
    # After a restart the audit is no longer in memory: restore it from its database checkpoint.
    run = runs.RUNS.get(run_id) or await asyncio.to_thread(runs.revive, run_id)
    if not run:
        raise HTTPException(404, "run not found")
    if run.status != "awaiting_approval":
        raise HTTPException(409, "run is not awaiting approval")
    auth.remember_run_token(run.id, request)   # the PR is opened as whoever approves it
    if req.approved and not config.STUBS["open_pr"] and not auth.token_for_run(run.id):
        raise HTTPException(401, "Sign in with GitHub to open the pull request")
    runs.resume_run(run, req.approved)
    return {"status": "resumed"}
