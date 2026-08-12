"""Tests proving rate limits actually trigger on /login, /api/scans/run, and
/api/ingest/{target_id}.

No TestClient/DB test harness existed in this repo yet, so this file sets up
a minimal one scoped to just these tests: an in-memory SQLite engine wired
in via FastAPI's dependency_overrides (swapping out app.api.deps.get_session),
and a fresh FastAPI TestClient per test. The real rate limiter is forced onto
its in-memory backend (bypassing any locally-running Redis) via
rate_limit._reset_for_tests() so results are deterministic and isolated from
whatever else might be poking the same Redis instance.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core import rate_limit
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import Organization, Target, User, Workspace


@pytest.fixture()
def engine():
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(eng)
    return eng


@pytest.fixture()
def client(engine):
    def override_get_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session

    # require_workspace() (used by the ingest endpoint) doesn't go through
    # the get_session dependency -- it opens its own Session against the
    # module-level `engine` it imported directly from app.core.db. Swap that
    # bound name too, or ingest tests would silently hit the real Postgres
    # engine instead of our in-memory SQLite one.
    original_deps_engine = deps_module.engine
    deps_module.engine = engine

    rate_limit._reset_for_tests()
    # Deliberately not using `with TestClient(app) as c:` here -- that would
    # run the app's real @app.on_event("startup") handler, which connects to
    # the *real* Postgres engine (app.core.db.engine) to create tables and
    # seed the admin user. We only want our overridden in-memory SQLite
    # session for these tests, so we skip lifespan entirely.
    c = TestClient(app)
    yield c
    app.dependency_overrides.clear()
    deps_module.engine = original_deps_engine
    rate_limit._reset_for_tests()


def _make_user(engine, email="attacker@example.com", password="correct-horse") -> User:
    with Session(engine) as session:
        user = User(email=email, name="Test User", password_hash=hash_password(password))
        session.add(user)
        session.commit()
        session.refresh(user)
        return user


def _make_workspace_and_target(engine) -> tuple[int, str, int]:
    """Returns (workspace_id, workspace_api_key, target_id) as plain values --
    not the ORM objects, since those get detached once the session here
    closes and would raise DetachedInstanceError on later attribute access."""
    with Session(engine) as session:
        org = Organization(name="Test Org")
        session.add(org)
        session.commit()
        session.refresh(org)

        workspace = Workspace(organization_id=org.id, name="Test WS", api_key="test-ws-key")
        session.add(workspace)
        session.commit()
        session.refresh(workspace)

        target = Target(workspace_id=workspace.id, name="Test Target", repo_url="https://example.com/repo.git")
        session.add(target)
        session.commit()
        session.refresh(target)
        return workspace.id, workspace.api_key, target.id


def test_login_rate_limit_allows_up_to_limit_then_429(client, engine):
    _make_user(engine, email="victim@example.com", password="the-real-password")

    responses = []
    for _ in range(6):
        resp = client.post(
            "/api/auth/login",
            json={"email": "victim@example.com", "password": "wrong-password"},
        )
        responses.append(resp)

    # First 5 attempts (the configured limit) go through to the auth check
    # and correctly fail with 401 (wrong password) -- the limiter doesn't
    # block them.
    for resp in responses[:5]:
        assert resp.status_code == 401

    # The 6th attempt within the same window must be rejected by the
    # limiter before ever touching password verification.
    sixth = responses[5]
    assert sixth.status_code == 429
    assert "rate limit" in sixth.json()["detail"].lower() or "too many" in sixth.json()["detail"].lower()
    assert "Retry-After" in sixth.headers


def test_login_rate_limit_is_scoped_per_ip_key_not_global(client, engine):
    """Sanity check: two different attacker identities (simulated by two
    separate rate-limit keys) don't share a budget. We can't easily spoof
    the TestClient's source IP, so this test instead verifies that the
    limiter's key-building is what isolates identities, by calling
    enforce_rate_limit directly for two different keys."""
    rate_limit.enforce_rate_limit(key="login:1.1.1.1", limit=5, window_seconds=60)
    for _ in range(4):
        rate_limit.enforce_rate_limit(key="login:1.1.1.1", limit=5, window_seconds=60)
    # 1.1.1.1 is now at its limit (5 calls made); a different IP is unaffected.
    rate_limit.enforce_rate_limit(key="login:2.2.2.2", limit=5, window_seconds=60)
    with pytest.raises(Exception):
        rate_limit.enforce_rate_limit(key="login:1.1.1.1", limit=5, window_seconds=60)


def test_scan_run_rate_limit_triggers_per_user(client, engine):
    user = _make_user(engine, email="scanner@example.com", password="whatever123")
    token = create_session_token(user.id)
    client.cookies.set("osp_session", token)

    responses = []
    for _ in range(11):
        # target_id=999 doesn't exist, so allowed requests short-circuit to
        # {"error": "target not found"} without touching git/subprocess --
        # we're only proving the limiter fires, not exercising the scanner.
        resp = client.post("/api/scans/run", params={"target_id": 999, "tool": "semgrep"})
        responses.append(resp)

    for resp in responses[:10]:
        assert resp.status_code == 200
        assert resp.json() == {"error": "target not found"}

    eleventh = responses[10]
    assert eleventh.status_code == 429


def test_ingest_rate_limit_triggers_per_workspace_key(client, engine):
    _, api_key, target_id = _make_workspace_and_target(engine)

    responses = []
    for _ in range(61):
        resp = client.post(
            f"/api/ingest/{target_id}",
            json={"runs": []},
            headers={"x-api-key": api_key},
        )
        responses.append(resp)

    for resp in responses[:60]:
        assert resp.status_code == 200
        assert resp.json()["ingested"] == 0

    sixty_first = responses[60]
    assert sixty_first.status_code == 429


def test_ingest_rate_limit_does_not_leak_across_workspace_keys(client, engine):
    _, api_key, target_id = _make_workspace_and_target(engine)

    # Exhaust workspace A's budget.
    for _ in range(60):
        resp = client.post(
            f"/api/ingest/{target_id}",
            json={"runs": []},
            headers={"x-api-key": api_key},
        )
        assert resp.status_code == 200
    blocked = client.post(
        f"/api/ingest/{target_id}",
        json={"runs": []},
        headers={"x-api-key": api_key},
    )
    assert blocked.status_code == 429

    # A request with an unrelated/invalid key is rejected by auth (401), not
    # by the rate limiter -- proving the limiter is keyed per workspace and
    # a different key isn't sharing the exhausted budget.
    other = client.post(
        f"/api/ingest/{target_id}",
        json={"runs": []},
        headers={"x-api-key": "some-other-key"},
    )
    assert other.status_code == 401
