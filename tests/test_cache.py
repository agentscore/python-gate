import time

from agentscore_gate.cache import TTLCache


def test_get_returns_none_for_missing_key():
    cache: TTLCache[str] = TTLCache(default_ttl_seconds=60)
    assert cache.get("nonexistent") is None


def test_set_and_get():
    cache: TTLCache[int] = TTLCache(default_ttl_seconds=60)
    cache.set("key", 42)
    assert cache.get("key") == 42


def test_entry_expires(monkeypatch):
    real_monotonic = time.monotonic

    cache: TTLCache[str] = TTLCache(default_ttl_seconds=1)
    cache.set("key", "value")
    assert cache.get("key") == "value"

    # Fast-forward time by patching monotonic.
    base = real_monotonic()
    monkeypatch.setattr(time, "monotonic", lambda: base + 2)
    assert cache.get("key") is None


def test_custom_ttl(monkeypatch):
    real_monotonic = time.monotonic

    cache: TTLCache[str] = TTLCache(default_ttl_seconds=60)
    cache.set("key", "value", ttl=1)

    base = real_monotonic()
    monkeypatch.setattr(time, "monotonic", lambda: base + 2)
    assert cache.get("key") is None


def test_overwrite_value():
    cache: TTLCache[str] = TTLCache(default_ttl_seconds=60)
    cache.set("key", "a")
    cache.set("key", "b")
    assert cache.get("key") == "b"
