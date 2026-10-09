"""Agent progress events (FR-28). Nodes write to LangGraph's custom stream; app/runs.py turns
those into schemas.AgentEvent for SSE. Outside a streaming run, emit() is a no-op."""
import functools
import logging
import time
from typing import Callable

from langgraph.config import get_stream_writer


log = logging.getLogger("app.agents")


def emit(agent: str, status: str, detail: str = "", worker_id: str | None = None) -> None:
    try:
        writer = get_stream_writer()
    except Exception:  # noqa: BLE001 - not inside a graph run
        return
    writer({"agent": agent, "status": status, "detail": detail, "worker_id": worker_id})


def traced(agent: str, describe: Callable[[dict, dict], tuple[str, str]] | None = None,
           worker_id: Callable[[dict], str] | None = None):
    """Wrap a node: emit `running` on entry, then `done` (or what describe() returns), or `failed`.

    describe(input, update) -> (status, detail).
    """
    def deco(fn):
        @functools.wraps(fn)
        def node(state):
            wid = worker_id(state) if worker_id else None
            who = {"agent": agent}
            started = time.perf_counter()
            emit(agent, "running", "", wid)
            if not wid:
                log.info("%s started", agent, extra=who)
            try:
                update = fn(state)
            except Exception as e:
                emit(agent, "failed", str(e)[:300], wid)
                log.exception("%s failed after %.1fs", agent, time.perf_counter() - started, extra=who)
                raise
            status, detail = describe(state, update) if describe else ("done", "")
            emit(agent, status, detail, wid)
            log.log(logging.WARNING if status in ("failed", "retry") else logging.INFO,
                    "%s%s %s in %.1fs: %s", agent, f" [{wid}]" if wid else "", status,
                    time.perf_counter() - started, detail, extra=who)
            return update
        return node
    return deco
