"""Tests for the tool-health cache introduced in #221 to stop GET
/api/tools/registry paying a full subprocess `--version` sweep (measured
at ~2.06s, dominated by semgrep's interpreter startup) on every single
request.

These use the in-memory fallback path deliberately (no local Redis
assumed in test environments), which is the same fallback production runs
under if Redis is ever unreachable; so this doubles as coverage for that
degradation path.
"""
import time
from unittest.mock import patch

import pytest

from app.core import tool_health_cache


@pytest.fixture(autouse=True)
def force_memory_backend():
    """Every test in this file exercises the in-memory path specifically,
    regardless of whether a real Redis happens to be reachable in whatever
    environment runs the suite."""
    with patch("app.core.tool_health_cache._get_redis", return_value=None):
        tool_health_cache._memory_cache.clear()
        yield
    tool_health_cache._memory_cache.clear()


def test_get_is_a_clean_miss_when_nothing_was_ever_set():
    assert tool_health_cache.get("semgrep") is None


def test_set_then_get_round_trips():
    health = {"tool": "semgrep", "installed": True, "version": "1.136.0", "response_ms": 2061}
    tool_health_cache.set("semgrep", health)
    assert tool_health_cache.get("semgrep") == health


def test_different_tools_do_not_collide():
    tool_health_cache.set("semgrep", {"tool": "semgrep", "installed": True})
    tool_health_cache.set("trivy", {"tool": "trivy", "installed": False})
    assert tool_health_cache.get("semgrep")["installed"] is True
    assert tool_health_cache.get("trivy")["installed"] is False


def test_invalidate_forces_the_next_read_to_miss():
    # This is the property the install flow depends on: the tool an admin
    # just installed must not keep showing its pre-install state.
    tool_health_cache.set("checkov", {"tool": "checkov", "installed": False})
    tool_health_cache.invalidate("checkov")
    assert tool_health_cache.get("checkov") is None


def test_invalidating_an_unset_tool_does_not_raise():
    tool_health_cache.invalidate("never-set")  # must not raise


def test_entries_expire_after_the_ttl():
    tool_health_cache.set("semgrep", {"tool": "semgrep", "installed": True})
    # Force the stored expiry into the past rather than sleeping
    # TTL_SECONDS in a test.
    with tool_health_cache._memory_lock:
        _, health = tool_health_cache._memory_cache["semgrep"]
        tool_health_cache._memory_cache["semgrep"] = (time.monotonic() - 1, health)
    assert tool_health_cache.get("semgrep") is None


def test_a_fresh_entry_is_not_expired():
    tool_health_cache.set("semgrep", {"tool": "semgrep", "installed": True})
    assert tool_health_cache.get("semgrep") is not None


class _FailingRedis:
    """Simulates Redis going away mid-request without the process having
    cached that unreachability yet (app.core.rate_limit has the same
    pattern for the same reason)."""

    def get(self, *_a, **_k):
        raise ConnectionError("redis is down")

    def setex(self, *_a, **_k):
        raise ConnectionError("redis is down")

    def delete(self, *_a, **_k):
        raise ConnectionError("redis is down")


def test_get_falls_back_to_memory_when_redis_raises():
    with patch("app.core.tool_health_cache._get_redis", return_value=_FailingRedis()):
        tool_health_cache.set("semgrep", {"tool": "semgrep", "installed": True})
        assert tool_health_cache.get("semgrep") == {"tool": "semgrep", "installed": True}


def test_invalidate_falls_back_to_memory_when_redis_raises():
    with patch("app.core.tool_health_cache._get_redis", return_value=_FailingRedis()):
        tool_health_cache.set("semgrep", {"tool": "semgrep", "installed": True})
        tool_health_cache.invalidate("semgrep")
        assert tool_health_cache.get("semgrep") is None
