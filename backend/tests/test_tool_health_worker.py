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

The second half of this module covers the same defect on the other surface:
`GET /api/tools/health`, which backs the Tool Health page, probed only the
api process and so reported every marketplace-installed tool as missing --
four present tools out of eighteen, all eighteen working.
"""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.api.tools import health as health_module
from app.api.tools.health import _check_one, _health_for, _merge_worker_health
from app.core import tool_health_cache
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import User, UserRole


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


# ---------------------------------------------------------------------------
# GET /api/tools/health -- the Tool Health page (same defect, second surface)
#
# The endpoint returned `_check_one` straight out, so every answer described
# the api container alone. Marketplace installs land on the worker, so the
# page showed the four tools bundled next to the web process as present and
# the other fourteen as missing, while all of them were installed and
# running scans.
# ---------------------------------------------------------------------------

# Written out rather than derived from TOOL_REGISTRY on purpose: the endpoint
# derives its own tool set from that same registry, so an expectation built
# the same way would agree with it under any input, including the four-tool
# regression this is here to catch.
EXPECTED_TOOLS = frozenset(
    {
        "semgrep",
        "gitleaks",
        "noseyparker",
        "trivy",
        "trivy-license",
        "gosec",
        "checkov",
        "tfsec",
        "modelscan",
        "semgrep-llm",
        "semgrep-core",
        "semgrep-registry",
        "garak",
        "medusa",
        "snyk-agent-scan",
        "cisco-aibom",
        "kics",
        "nuclei",
    }
)


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    return eng


@pytest.fixture()
def client(engine):
    """Admin-authenticated TestClient. The whole /api/tools router sits behind
    `login_required` (app.main), so an anonymous GET never reaches the
    handler under test."""

    def override_get_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    original_engine = deps_module.engine
    deps_module.engine = engine

    with Session(engine) as session:
        user = User(
            email="tools-health@example.com",
            name="Test",
            password_hash=hash_password("whatever123"),
            role=UserRole.ADMIN,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        token = create_session_token(user.id, user.token_version)

    c = TestClient(app)
    c.cookies.set("toleman_session", token)
    yield c
    app.dependency_overrides.clear()
    deps_module.engine = original_engine


@pytest.fixture()
def api_sees_no_binaries(monkeypatch):
    """The CTX-03 topology: none of these tools is on the PATH of the
    container serving the request, because installs land on the worker.

    Doubles as a guard on test runtime -- `_check_one` short-circuits on the
    `shutil.which` miss, so the endpoint spawns no subprocesses at all.
    """
    monkeypatch.setattr(health_module.shutil, "which", lambda _cmd: None)


def test_the_page_reports_a_worker_installed_tool_as_installed(client, api_sees_no_binaries):
    """The reported defect: checkov is installed and running scans on the
    worker, invisible to this process, and the page said "not installed"."""
    tool_health_cache.set_worker_health("checkov", _worker_health())

    by_tool = {e["tool"]: e for e in client.get("/api/tools/health").json()}

    assert by_tool["checkov"]["installed"] is True
    assert by_tool["checkov"]["version"] == "3.3.13"
    assert by_tool["checkov"]["checked_in"] == "worker"


def test_a_tool_neither_process_has_reported_reads_unknown_not_missing(client, api_sees_no_binaries):
    """No evidence in either direction is not a negative finding."""
    # checkov has a worker record; tfsec has none anywhere.
    tool_health_cache.set_worker_health("checkov", _worker_health())

    by_tool = {e["tool"]: e for e in client.get("/api/tools/health").json()}

    assert by_tool["tfsec"]["installed"] is None
    assert by_tool["tfsec"]["checked_in"] is None
    # The contrast is the point: one response distinguishes "known present"
    # from "nobody knows", rather than flattening both into a red negative.
    assert by_tool["checkov"]["installed"] is True


def test_every_registry_tool_is_reported(client, api_sees_no_binaries):
    body = client.get("/api/tools/health").json()
    reported = {e["tool"] for e in body}

    # The count the page is supposed to show. Shrinking this set is how a
    # regression gets made to look green, so it is asserted, not implied.
    assert len(EXPECTED_TOOLS) == 18
    # Superset, so adding a nineteenth tool to the registry is not a failure.
    assert EXPECTED_TOOLS <= reported, f"missing from /health: {sorted(EXPECTED_TOOLS - reported)}"

    for entry in body:
        assert set(entry) == {"tool", "installed", "version", "response_ms", "checked_in"}


def test_a_live_api_probe_is_still_the_answer_when_this_process_can_see_the_tool():
    tool_health_cache.set_worker_health("checkov", _worker_health(version="3.3.13"))

    with patch("app.api.tools.health._check_one", return_value=_local_hit(version="9.9.9")):
        health = _health_for("checkov", ["checkov", "--version"])

    assert health["installed"] is True
    assert health["version"] == "9.9.9"
    assert health["checked_in"] == "api"


def test_a_worker_negative_stays_a_confident_negative():
    """Only silence is unknown. If the worker looked and reported nothing
    there, that is a real answer from the environment that runs scans."""
    tool_health_cache.set_worker_health("checkov", _worker_health(installed=False, version=None))

    with patch("app.api.tools.health._check_one", return_value=_local_miss()):
        health = _health_for("checkov", ["checkov", "--version"])

    assert health["installed"] is False


def test_both_endpoints_share_one_merge_implementation():
    """/registry and /health must not drift into two CTX-03 merges with two
    sets of rules; registry.py resolves the function this module defines."""
    from app.api.tools import registry as registry_module

    assert registry_module._merge_worker_health is _merge_worker_health
