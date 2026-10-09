"""Cache for every external response and LLM output (FR-9, NFR-2), kept in the database so it
is shared across restarts and machines."""
import hashlib
from typing import Callable

from app import config, db

_MISS = object()


class OfflineMiss(RuntimeError):
    """OFFLINE=true and the response was never cached."""


def _key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:32]


def get(namespace: str, key: str, default=None):
    try:
        hit = db.kv_get("cache", namespace, _key(key))
    except Exception:  # noqa: BLE001 - a cache that cannot be read is a miss, never an error
        return default
    return default if hit is None else hit["v"]


def put(namespace: str, key: str, value) -> None:
    try:
        db.kv_put("cache", namespace, _key(key), {"v": value})   # wrapped: a cached null stays a hit
    except Exception:  # noqa: BLE001
        pass


def cached(namespace: str, key: str, fetch: Callable[[], object]):
    """Return the cached value, else fetch and store it. Offline misses raise OfflineMiss."""
    hit = get(namespace, key, _MISS)
    if hit is not _MISS:
        return hit
    if config.OFFLINE:
        raise OfflineMiss(f"{namespace}:{key} not cached")
    value = fetch()
    put(namespace, key, value)
    return value
