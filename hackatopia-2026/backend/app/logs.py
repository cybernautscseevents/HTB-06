"""Logging: console, a rotating file, and the database (so each audit's log can be read back).

Records logged inside a graph node are tagged with the audit's run id automatically.
"""
import logging
import logging.handlers
import queue

from app import config

_configured = False


def current_run_id() -> str | None:
    try:
        from langgraph.config import get_config

        return get_config()["configurable"].get("thread_id")
    except Exception:  # noqa: BLE001 - not inside a graph run
        return None


class _RunContext(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "run_id"):
            record.run_id = current_run_id()
        if not hasattr(record, "agent"):
            record.agent = None
        return True


class _DatabaseHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            from app import db

            db.add_logs([(record.created, record.levelname, record.name, getattr(record, "run_id", None),
                          getattr(record, "agent", None), record.getMessage()[:4000])])
        except Exception:  # noqa: BLE001 - logging must never take the app down
            pass


def setup() -> None:
    """Idempotent. Database writes go through a queue so a slow connection never blocks a request."""
    global _configured
    if _configured:
        return
    _configured = True
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s [%(run_id)s] %(message)s", "%H:%M:%S")

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    file = logging.handlers.RotatingFileHandler(config.LOG_DIR / "app.log", maxBytes=5_000_000,
                                                backupCount=3, encoding="utf-8")
    file.setFormatter(fmt)

    q: queue.Queue = queue.Queue(-1)
    listener = logging.handlers.QueueListener(q, _DatabaseHandler(), respect_handler_level=True)
    listener.start()
    to_db = logging.handlers.QueueHandler(q)

    app = logging.getLogger("app")
    app.setLevel(config.LOG_LEVEL)
    app.propagate = False
    for handler in (console, file, to_db):
        handler.addFilter(_RunContext())      # stamped where the record is created, in the node's thread
        app.addHandler(handler)
