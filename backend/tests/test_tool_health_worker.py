"""Tests for finding CTX-03: a one-click install that succeeds must not
report permanent failure.

What the external evaluation hit: Checkov installed from the Tool
Marketplace, run status `completed`, version 3.3.13, and
`docker exec ...-celery-worker-1 which checkov` resolving fine, while the
marketplace card said **"not installed"**, and still said it after pressing
"Recheck all".

Cause: the install runs on the Celery worker; the health probe ran
`shutil.which()` inside the backend web process. Same image, different
containers. Scans run on the worker, so the tool was genuinely usable and
the operator had no way to know.
"""

import pytest

from app.api.tools.health import _check_one
from app.api.tools.registry import _merge_worker_health
from app.core import tool_health_cache


@pytest.fixture(autouse=True)
def clear_cache(monkeypatch):
    # Force the in-memory path so these never depend on a live Redis, and
    # start from a clean slate each test.
    monkeypatch.setattr(tool_health_cache, "_get_redis", lambda: None)
    with tool_health_cache._memory_lock:
        tool_health_cache._memory_cache.clear()
    yield
    with tool_health_cache._memory_lock:
        tool_health_cache._memory_cache.clear()


def _worker_health(tool="checkov", version="3.3.13", installed=True):
    return {
        "tool": tool,
        "installed": installed,
        "version": version,
        "response_ms": None,
        "checked_in": "worker",
    }


def _local_miss(tool="checkov"):
    return {"tool": tool, "installed": False, "version": None, "response_ms": None, "checked_in": "api"}


def _local_hit(tool="checkov", version="9.9.9"):
    return {"tool": tool, "installed": True, "version": version, "response_ms": 12, "checked_in": "api"}


def test_check_one_records_where_it_ran():
    # Something guaranteed present in any environment running these tests.
    health = _check_one("python", ["python3", "--version"])
    assert health["checked_in"] == "api"

    health = _check_one("python", ["python3", "--version"], checked_in="worker")
    assert health["checked_in"] == "worker"


def test_missing_tool_still_reports_where_it_was_checked():
    health = _check_one("nope", ["definitely-not-a-real-binary-xyz", "--version"])
    assert health["installed"] is False
    assert health["checked_in"] == "api"


def test_the_reported_bug_a_worker_install_no_longer_reads_as_not_installed():
    tool_health_cache.set_worker_health("checkov", _worker_health())

    merged = _merge_worker_health("checkov", _local_miss())

    assert merged["installed"] is True, "a tool installed on the worker must not read as 'not installed'"
    assert merged["version"] == "3.3.13"
    assert merged["checked_in"] == "worker"


def test_a_local_probe_wins_over_a_worker_record():
    # Direct evidence beats a memory of an install: the local probe is a live
    # check, the worker record is not.
    tool_health_cache.set_worker_health("checkov", _worker_health(version="3.3.13"))

    merged = _merge_worker_health("checkov", _local_hit(version="9.9.9"))

    assert merged["version"] == "9.9.9"
    assert merged["checked_in"] == "api"


def test_no_worker_record_leaves_the_local_answer_untouched():
    merged = _merge_worker_health("checkov", _local_miss())
    assert merged["installed"] is False
    assert merged["checked_in"] == "api"


def test_a_worker_record_saying_not_installed_never_upgrades_anything():
    tool_health_cache.set_worker_health("checkov", _worker_health(installed=False, version=None))

    merged = _merge_worker_health("checkov", _local_miss())

    assert merged["installed"] is False


def test_worker_health_is_scoped_per_tool():
    tool_health_cache.set_worker_health("checkov", _worker_health(tool="checkov"))

    assert tool_health_cache.get_worker_health("checkov") is not None
    assert tool_health_cache.get_worker_health("tfsec") is None


def test_worker_health_does_not_collide_with_the_short_ttl_probe_cache():
    """The two keyspaces answer different questions and must not overwrite
    each other; if they shared a key, the next 30s probe would clobber the
    worker's record and the card would flip back to 'not installed'."""
    tool_health_cache.set_worker_health("checkov", _worker_health())
    tool_health_cache.set("checkov", _local_miss())

    assert tool_health_cache.get("checkov")["installed"] is False
    assert tool_health_cache.get_worker_health("checkov")["installed"] is True


def test_invalidate_does_not_wipe_the_worker_record():
    """tool_install calls invalidate() on every settled install. If that also
    dropped the worker record, the fix would undo itself one line later."""
    tool_health_cache.set_worker_health("checkov", _worker_health())
    tool_health_cache.set("checkov", _local_miss())

    tool_health_cache.invalidate("checkov")

    assert tool_health_cache.get("checkov") is None
    assert tool_health_cache.get_worker_health("checkov")["installed"] is True


def test_successful_install_publishes_worker_health(monkeypatch):
    """End-to-end on the real _finish path: a completed install must leave a
    worker record behind, not just invalidate the probe cache."""
    from app.core import tool_install

    class FakeRun:
        tool = "checkov"
        status = ""
        completed_at = None
        error = ""
        installed_version = ""
        output_tail = ""

    class FakeSession:
        def add(self, obj):
            pass

        def commit(self):
            pass

        def refresh(self, obj):
            pass

    tool_install._finish(FakeSession(), FakeRun(), status="completed", version="3.3.13")

    recorded = tool_health_cache.get_worker_health("checkov")
    assert recorded is not None
    assert recorded["installed"] is True
    assert recorded["version"] == "3.3.13"
    assert recorded["checked_in"] == "worker"


def test_failed_install_publishes_nothing():
    from app.core import tool_install

    class FakeRun:
        tool = "checkov"
        status = ""
        completed_at = None
        error = ""
        installed_version = ""
        output_tail = ""

    class FakeSession:
        def add(self, obj):
            pass

        def commit(self):
            pass

        def refresh(self, obj):
            pass

    tool_install._finish(FakeSession(), FakeRun(), status="failed", error="pip exited 1")

    # A failed install must never leave a record claiming the tool is there.
    assert tool_health_cache.get_worker_health("checkov") is None
