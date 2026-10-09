"""Storage for everything the app keeps: audits, logs, sessions, cache, per-repository memory
and LangGraph checkpoints.

DATABASE_URL set  -> Neon / PostgreSQL (psycopg connection pool).
DATABASE_URL unset -> a local SQLite file, so the app still runs with no setup.

SQL is written once with `?` placeholders and plain types that both engines accept.
"""
import json
import logging
import sqlite3
import threading
import time
from typing import Any

from app import config

log = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    run_id      TEXT PRIMARY KEY,
    repo_url    TEXT NOT NULL,
    status      TEXT NOT NULL,
    user_login  TEXT,
    created_at  DOUBLE PRECISION NOT NULL,
    updated_at  DOUBLE PRECISION NOT NULL,
    summary     TEXT NOT NULL,
    snapshot    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audits_created ON audits (created_at);
CREATE INDEX IF NOT EXISTS audits_repo ON audits (repo_url);
CREATE TABLE IF NOT EXISTS logs (
    id       {serial},
    ts       DOUBLE PRECISION NOT NULL,
    level    TEXT NOT NULL,
    logger   TEXT NOT NULL,
    run_id   TEXT,
    agent    TEXT,
    message  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS logs_run ON logs (run_id, id);
CREATE TABLE IF NOT EXISTS sessions (
    sid      TEXT PRIMARY KEY,
    token    TEXT NOT NULL,
    profile  TEXT NOT NULL,
    expires  DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS cache (
    namespace   TEXT NOT NULL,
    key         TEXT NOT NULL,
    value       TEXT NOT NULL,
    created_at  DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (namespace, key)
);
CREATE TABLE IF NOT EXISTS memory (
    namespace   TEXT NOT NULL,
    key         TEXT NOT NULL,
    value       TEXT NOT NULL,
    updated_at  DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (namespace, key)
);
"""


class Database:
    """Minimal query interface shared by both engines. Rows come back as dicts."""
    kind = "sqlite"

    def query(self, sql: str, params: tuple = ()) -> list[dict]:
        raise NotImplementedError

    def execute(self, sql: str, params: tuple = ()) -> None:
        self.query(sql, params)

    def checkpointer(self):
        raise NotImplementedError

    def close(self) -> None:
        pass


class SqliteDatabase(Database):
    kind = "sqlite"

    def __init__(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._path = path
        with self._lock:
            self._conn.executescript(SCHEMA.format(serial="INTEGER PRIMARY KEY AUTOINCREMENT"))

    def query(self, sql: str, params: tuple = ()) -> list[dict]:
        with self._lock:
            cur = self._conn.execute(sql, params)
            return [dict(r) for r in cur.fetchall()] if cur.description else []

    def checkpointer(self):
        from langgraph.checkpoint.sqlite import SqliteSaver

        conn = sqlite3.connect(str(self._path), check_same_thread=False)
        saver = SqliteSaver(conn)
        saver.setup()
        return saver

    def close(self) -> None:
        self._conn.close()


class PostgresDatabase(Database):
    kind = "postgres"

    def __init__(self, url: str):
        from psycopg.rows import dict_row
        from psycopg_pool import ConnectionPool

        # autocommit + no prepared statements: required by the LangGraph saver and by Neon's
        # pooled (PgBouncer) endpoints respectively.
        self._pool = ConnectionPool(url, min_size=1, max_size=8, open=True, kwargs={
            "autocommit": True, "row_factory": dict_row, "prepare_threshold": None})
        with self._pool.connection() as conn:
            for statement in SCHEMA.format(serial="BIGSERIAL PRIMARY KEY").split(";"):
                if statement.strip():
                    conn.execute(statement)

    def query(self, sql: str, params: tuple = ()) -> list[dict]:
        with self._pool.connection() as conn:
            cur = conn.execute(sql.replace("?", "%s"), params)
            return list(cur.fetchall()) if cur.description else []

    def checkpointer(self):
        from langgraph.checkpoint.postgres import PostgresSaver

        saver = PostgresSaver(self._pool)
        saver.setup()
        return saver

    def close(self) -> None:
        self._pool.close()


_db: Database | None = None
_lock = threading.Lock()


def get() -> Database:
    global _db
    with _lock:
        if _db is None:
            if config.DATABASE_URL:
                _db = PostgresDatabase(config.DATABASE_URL)
                log.info("storage: PostgreSQL (Neon)")
            else:
                _db = SqliteDatabase(config.SQLITE_PATH)
                log.info("storage: local SQLite at %s (set DATABASE_URL to use Neon)", config.SQLITE_PATH)
        return _db


# --- Audits ----------------------------------------------------------------------------------------

def save_audit(run_id: str, repo_url: str, status: str, user: str | None, created_at: float,
               summary: dict, snapshot_json: str) -> None:
    get().execute(
        "INSERT INTO audits (run_id, repo_url, status, user_login, created_at, updated_at, summary, snapshot) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (run_id) DO UPDATE SET status = excluded.status, updated_at = excluded.updated_at, "
        "summary = excluded.summary, snapshot = excluded.snapshot",
        (run_id, repo_url, status, user, created_at, time.time(), json.dumps(summary), snapshot_json))


def load_audit(run_id: str) -> str | None:
    rows = get().query("SELECT snapshot FROM audits WHERE run_id = ?", (run_id,))
    return rows[0]["snapshot"] if rows else None


def list_audits(limit: int = 500) -> list[dict]:
    rows = get().query("SELECT summary FROM audits ORDER BY created_at DESC LIMIT ?", (limit,))
    return [json.loads(r["summary"]) for r in rows]


# --- Logs ------------------------------------------------------------------------------------------

def add_logs(rows: list[tuple]) -> None:
    for row in rows:
        get().execute("INSERT INTO logs (ts, level, logger, run_id, agent, message) VALUES (?, ?, ?, ?, ?, ?)", row)


def read_logs(run_id: str | None = None, limit: int = 500) -> list[dict]:
    cols = "ts, level, logger, run_id, agent, message"
    if run_id:
        rows = get().query(f"SELECT {cols} FROM logs WHERE run_id = ? ORDER BY id DESC LIMIT ?", (run_id, limit))
    else:
        rows = get().query(f"SELECT {cols} FROM logs ORDER BY id DESC LIMIT ?", (limit,))
    return rows[::-1]


# --- Key/value tables: cache (external responses, LLM outputs) and memory (per repository) ---------

def kv_get(table: str, namespace: str, key: str) -> Any:
    rows = get().query(f"SELECT value FROM {table} WHERE namespace = ? AND key = ?", (namespace, key))
    return json.loads(rows[0]["value"]) if rows else None


def kv_put(table: str, namespace: str, key: str, value: Any) -> None:
    stamp = "created_at" if table == "cache" else "updated_at"
    get().execute(
        f"INSERT INTO {table} (namespace, key, value, {stamp}) VALUES (?, ?, ?, ?) "
        f"ON CONFLICT (namespace, key) DO UPDATE SET value = excluded.value, {stamp} = excluded.{stamp}",
        (namespace, key, json.dumps(value), time.time()))


# --- Sessions --------------------------------------------------------------------------------------

def save_session(sid: str, token: str, profile: dict, expires: float) -> None:
    get().execute(
        "INSERT INTO sessions (sid, token, profile, expires) VALUES (?, ?, ?, ?) "
        "ON CONFLICT (sid) DO UPDATE SET token = excluded.token, profile = excluded.profile, expires = excluded.expires",
        (sid, token, json.dumps(profile), expires))


def load_session(sid: str) -> dict | None:
    rows = get().query("SELECT token, profile, expires FROM sessions WHERE sid = ?", (sid,))
    if not rows:
        return None
    return {"token": rows[0]["token"], "user": json.loads(rows[0]["profile"]), "expires": rows[0]["expires"]}


def delete_session(sid: str) -> None:
    get().execute("DELETE FROM sessions WHERE sid = ?", (sid,))
    get().execute("DELETE FROM sessions WHERE expires < ?", (time.time(),))
