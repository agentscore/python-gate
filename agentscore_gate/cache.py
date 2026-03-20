from __future__ import annotations

import time


class TTLCache[T]:
    """Simple in-memory cache with per-entry TTL expiry."""

    def __init__(self, default_ttl_seconds: float) -> None:
        self._store: dict[str, tuple[T, float]] = {}
        self._default_ttl = default_ttl_seconds

    def get(self, key: str) -> T | None:
        """Return the cached value, or ``None`` if missing or expired."""
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if time.monotonic() > expires_at:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: T, ttl: float | None = None) -> None:
        """Store *value* under *key* with an optional custom TTL (seconds)."""
        self._store[key] = (value, time.monotonic() + (ttl if ttl is not None else self._default_ttl))
