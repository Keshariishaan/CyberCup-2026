"""
PURPOSE : SessionStore implementations: in-process memory (default) and Redis (optional).
          Holds login lockouts, token revocations, rate-limit counters, encrypted vault
          entries and the response cache - everything that must be shared across instances.
INPUTS  : none (memory) or a Redis URL.
OUTPUTS : MemorySessionStore, RedisSessionStore, make_session_store().
HOW TO EXTEND : implement core.interfaces.SessionStore and add a branch in make_session_store.
"""
from __future__ import annotations

import threading
import time

from core.interfaces import SessionStore


class MemorySessionStore(SessionStore):
    """Thread-safe dict with expiry. Not shared across processes."""

    def __init__(self) -> None:
        self._d: dict[str, tuple[str, float | None]] = {}
        self._lock = threading.Lock()

    def _live(self, key: str) -> tuple[str, float | None] | None:
        item = self._d.get(key)
        if item and item[1] is not None and item[1] <= time.monotonic():
            del self._d[key]
            return None
        return item

    def get(self, key: str) -> str | None:
        with self._lock:
            item = self._live(key)
            return item[0] if item else None

    def set(self, key: str, value: str, ttl: int | None = None) -> None:
        with self._lock:
            self._d[key] = (value, time.monotonic() + ttl if ttl else None)

    def delete(self, key: str) -> None:
        with self._lock:
            self._d.pop(key, None)

    def incr(self, key: str, ttl: int | None = None) -> int:
        with self._lock:
            item = self._live(key)
            val = int(item[0]) + 1 if item else 1
            exp = item[1] if item else (time.monotonic() + ttl if ttl else None)
            self._d[key] = (str(val), exp)
            return val

    def ttl(self, key: str) -> int:
        with self._lock:
            item = self._live(key)
            if not item:
                return -2
            return -1 if item[1] is None else max(0, int(item[1] - time.monotonic() + 0.999))


class RedisSessionStore(SessionStore):
    """Redis-backed store so multiple API instances share state."""

    def __init__(self, url: str) -> None:
        import redis  # optional dependency
        self.r = redis.Redis.from_url(url, decode_responses=True)

    def get(self, key: str) -> str | None:
        return self.r.get(key)

    def set(self, key: str, value: str, ttl: int | None = None) -> None:
        self.r.set(key, value, ex=ttl)

    def delete(self, key: str) -> None:
        self.r.delete(key)

    def incr(self, key: str, ttl: int | None = None) -> int:
        pipe = self.r.pipeline()
        pipe.incr(key)
        if ttl:
            pipe.expire(key, ttl, nx=True)
        return int(pipe.execute()[0])

    def ttl(self, key: str) -> int:
        return int(self.r.ttl(key))


def make_session_store(kind: str, redis_url: str = "") -> SessionStore:
    """Factory: 'memory' (default) or 'redis'."""
    if kind == "redis":
        return RedisSessionStore(redis_url)
    return MemorySessionStore()
