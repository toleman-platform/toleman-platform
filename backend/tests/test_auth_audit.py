"""Tests for the auth-hardening changes: 24h session timeout, no concurrent
logins per user, and the security audit log (login/logout/password-change/
permission-change events, app.core.auth_audit / app.models.models.AuthAuditLog).

Uses the same in-memory-SQLite + dependency_overrides TestClient harness as
tests/test_rate_limit.py -- not tests/test_security.py's logout_test_user
fixture, which needs a real Postgres connection and only runs in CI.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core import rate_limit
from app.core.security import SESSION_TTL_SECONDS, create_session_token, hash_password
from app.main import app
from app.models.models import AuthAuditLog, AuthEventType, Organization, User, UserRole, Workspace

PASSWORD = "correct horse battery staple"


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    return eng


@pytest.fixture()
def client(engine):
    def override_get_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    original_deps_engine = deps_module.engine
    deps_module.engine = engine

    # The login rate limiter's in-memory fallback is module-level state,
    # shared across every test in this process; without resetting it here
    # this file's own login calls (this file alone makes more than
    # LOGIN_RATE_LIMIT=5 of them) start 429ing partway through the run.
    rate_limit._reset_for_tests()

    c = TestClient(app)
    yield c
    app.dependency_overrides.clear()
    deps_module.engine = original_deps_engine
    rate_limit._reset_for_tests()


def _make_user(engine, email="alice@example.com", password=PASSWORD, role=UserRole.USER) -> int:
    with Session(engine) as session:
        user = User(email=email, name="Test User", password_hash=hash_password(password), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        return user.id


def _login_as(client, engine, email, role=UserRole.ADMIN) -> TestClient:
    """Direct cookie injection (bypasses the real /login flow, same pattern
    as _login() in tests/test_pr_guardrail_ignore.py etc.), for tests that
    need an authenticated caller but aren't themselves testing the login
    event -- avoids a stray extra LOGIN_SUCCESS row muddying assertions."""
    with Session(engine) as session:
        user = User(email=email, name="Test", password_hash=hash_password(PASSWORD), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return client


def _make_workspace(engine) -> int:
    with Session(engine) as session:
        org = Organization(name="org")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws", api_key="key")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        return ws.id


def _events(engine, event_type: AuthEventType) -> list[AuthAuditLog]:
    with Session(engine) as session:
        return session.exec(select(AuthAuditLog).where(AuthAuditLog.event_type == event_type)).all()


# --- 24h session timeout ----------------------------------------------------


def test_session_ttl_is_24_hours():
    assert SESSION_TTL_SECONDS == 60 * 60 * 24


# --- No concurrent logins for the same user ---------------------------------


def test_second_login_invalidates_the_first_session(client, engine):
    _make_user(engine)
    first = client.post("/api/auth/login", json={"email": "alice@example.com", "password": PASSWORD})
    first_cookie = first.cookies.get("toleman_session")
    assert first_cookie
    assert client.get("/api/auth/me", cookies={"toleman_session": first_cookie}).status_code == 200

    # A second login (e.g. from a different device) must invalidate the
    # first session, not just add a second valid one.
    second = client.post("/api/auth/login", json={"email": "alice@example.com", "password": PASSWORD})
    second_cookie = second.cookies.get("toleman_session")
    assert second_cookie
    assert second_cookie != first_cookie

    assert client.get("/api/auth/me", cookies={"toleman_session": first_cookie}).status_code == 401
    assert client.get("/api/auth/me", cookies={"toleman_session": second_cookie}).status_code == 200


# --- Logout really invalidates the token server-side ------------------------


def test_logout_invalidates_the_session_token(client, engine):
    _make_user(engine)
    login_resp = client.post("/api/auth/login", json={"email": "alice@example.com", "password": PASSWORD})
    cookie = login_resp.cookies.get("toleman_session")
    assert client.get("/api/auth/me", cookies={"toleman_session": cookie}).status_code == 200

    logout_resp = client.post("/api/auth/logout", cookies={"toleman_session": cookie})
    assert logout_resp.status_code == 200

    # Same token, unchanged, still cryptographically valid (signature/expiry
    # intact) -- rejected only because logout bumped the DB token_version,
    # not because the client dropped the cookie.
    assert client.get("/api/auth/me", cookies={"toleman_session": cookie}).status_code == 401


# --- Security audit log: login/logout/password-change ----------------------


def test_successful_login_logs_login_success_event(client, engine):
    _make_user(engine)
    res = client.post("/api/auth/login", json={"email": "alice@example.com", "password": PASSWORD})
    assert res.status_code == 200

    events = _events(engine, AuthEventType.LOGIN_SUCCESS)
    assert len(events) == 1
    assert events[0].actor == "alice@example.com"
    assert events[0].target_email == "alice@example.com"


def test_failed_login_logs_login_failed_event(client, engine):
    _make_user(engine)
    res = client.post("/api/auth/login", json={"email": "alice@example.com", "password": "wrong password"})
    assert res.status_code == 401

    events = _events(engine, AuthEventType.LOGIN_FAILED)
    assert len(events) == 1
    assert events[0].actor == "alice@example.com"
    assert _events(engine, AuthEventType.LOGIN_SUCCESS) == []


def test_failed_login_logs_event_even_for_an_unknown_email(client, engine):
    """A real, actionable security signal (repeated failed attempts against
    one address) regardless of whether that email is actually registered --
    the DB write must not itself become a way to distinguish "no such
    account" from "wrong password" that the 401 response already avoids."""
    res = client.post("/api/auth/login", json={"email": "ghost@example.com", "password": "whatever"})
    assert res.status_code == 401

    events = _events(engine, AuthEventType.LOGIN_FAILED)
    assert len(events) == 1
    assert events[0].actor == "ghost@example.com"


def test_logout_logs_logout_event(client, engine):
    _make_user(engine)
    login_resp = client.post("/api/auth/login", json={"email": "alice@example.com", "password": PASSWORD})
    cookie = login_resp.cookies.get("toleman_session")

    res = client.post("/api/auth/logout", cookies={"toleman_session": cookie})
    assert res.status_code == 200

    events = _events(engine, AuthEventType.LOGOUT)
    assert len(events) == 1
    assert events[0].actor == "alice@example.com"


def test_password_change_logs_password_changed_event(client, engine):
    _make_user(engine)
    login_resp = client.post("/api/auth/login", json={"email": "alice@example.com", "password": PASSWORD})
    cookie = login_resp.cookies.get("toleman_session")

    res = client.post(
        "/api/auth/change-password",
        json={"current_password": PASSWORD, "new_password": "a brand new password 123"},
        cookies={"toleman_session": cookie},
    )
    assert res.status_code == 200

    events = _events(engine, AuthEventType.PASSWORD_CHANGED)
    assert len(events) == 1
    assert events[0].actor == "alice@example.com"


# --- Security audit log: permission changes ---------------------------------


def test_role_change_logs_role_changed_event(client, engine):
    target_user_id = _make_user(engine, email="bob@example.com", role=UserRole.USER)
    admin_client = _login_as(client, engine, "admin@example.com", role=UserRole.ADMIN)

    res = admin_client.patch(f"/api/admin/users/{target_user_id}/role", json={"role": "security_engineer"})
    assert res.status_code == 200

    events = _events(engine, AuthEventType.ROLE_CHANGED)
    assert len(events) == 1
    assert events[0].actor == "admin@example.com"
    assert events[0].target_email == "bob@example.com"
    assert events[0].detail == "user -> security_engineer"


def test_role_change_is_a_noop_when_the_role_does_not_actually_change(client, engine):
    target_user_id = _make_user(engine, email="bob@example.com", role=UserRole.USER)
    admin_client = _login_as(client, engine, "admin@example.com", role=UserRole.ADMIN)

    res = admin_client.patch(f"/api/admin/users/{target_user_id}/role", json={"role": "user"})
    assert res.status_code == 200
    assert _events(engine, AuthEventType.ROLE_CHANGED) == []


def test_workspace_role_assignment_logs_workspace_role_changed_event(client, engine):
    ws_id = _make_workspace(engine)
    target_user_id = _make_user(engine, email="bob@example.com")
    admin_client = _login_as(client, engine, "admin@example.com", role=UserRole.ADMIN)

    res = admin_client.put(
        "/api/admin/workspace-roles",
        json={"user_id": target_user_id, "workspace_id": ws_id, "role": "developer"},
    )
    assert res.status_code == 200

    events = _events(engine, AuthEventType.WORKSPACE_ROLE_CHANGED)
    assert len(events) == 1
    assert events[0].actor == "admin@example.com"
    assert events[0].target_email == "bob@example.com"
    assert "developer" in events[0].detail


def test_reassigning_the_same_workspace_role_does_not_log_a_change(client, engine):
    ws_id = _make_workspace(engine)
    target_user_id = _make_user(engine, email="bob@example.com")
    admin_client = _login_as(client, engine, "admin@example.com", role=UserRole.ADMIN)
    admin_client.put(
        "/api/admin/workspace-roles",
        json={"user_id": target_user_id, "workspace_id": ws_id, "role": "developer"},
    )

    res = admin_client.put(
        "/api/admin/workspace-roles",
        json={"user_id": target_user_id, "workspace_id": ws_id, "role": "developer"},
    )
    assert res.status_code == 200
    assert len(_events(engine, AuthEventType.WORKSPACE_ROLE_CHANGED)) == 1  # only the first, real change


def test_workspace_role_removal_logs_event(client, engine):
    ws_id = _make_workspace(engine)
    target_user_id = _make_user(engine, email="bob@example.com")
    admin_client = _login_as(client, engine, "admin@example.com", role=UserRole.ADMIN)
    assign_res = admin_client.put(
        "/api/admin/workspace-roles",
        json={"user_id": target_user_id, "workspace_id": ws_id, "role": "developer"},
    )
    membership_id = assign_res.json()["id"]

    res = admin_client.delete(f"/api/admin/workspace-roles/{membership_id}")
    assert res.status_code == 200

    events = _events(engine, AuthEventType.WORKSPACE_ROLE_REMOVED)
    assert len(events) == 1
    assert events[0].actor == "admin@example.com"
    assert events[0].target_email == "bob@example.com"


# --- GET /api/audit/security-log (admin-only) -------------------------------


def test_security_log_requires_admin(client, engine):
    _login_as(client, engine, "user@example.com", role=UserRole.USER)
    res = client.get("/api/audit/security-log")
    assert res.status_code == 403


def test_security_log_lists_recorded_events(client, engine):
    _make_user(engine)
    client.post("/api/auth/login", json={"email": "alice@example.com", "password": PASSWORD})
    admin_client = _login_as(client, engine, "admin@example.com", role=UserRole.ADMIN)

    res = admin_client.get("/api/audit/security-log")
    assert res.status_code == 200
    body = res.json()
    assert body["total"] >= 1
    assert any(e["event_type"] == "login_success" and e["actor"] == "alice@example.com" for e in body["items"])


def test_security_log_filters_by_event_type(client, engine):
    _make_user(engine)
    client.post("/api/auth/login", json={"email": "alice@example.com", "password": PASSWORD})
    client.post("/api/auth/login", json={"email": "alice@example.com", "password": "wrong"})
    admin_client = _login_as(client, engine, "admin@example.com", role=UserRole.ADMIN)

    res = admin_client.get("/api/audit/security-log", params={"event_type": "login_failed"})
    assert res.status_code == 200
    items = res.json()["items"]
    assert all(e["event_type"] == "login_failed" for e in items)
    assert len(items) == 1


def test_security_log_filters_by_email_matches_actor_or_target(client, engine):
    target_user_id = _make_user(engine, email="bob@example.com")
    admin_client = _login_as(client, engine, "admin@example.com", role=UserRole.ADMIN)
    admin_client.patch(f"/api/admin/users/{target_user_id}/role", json={"role": "security_engineer"})

    # bob is the target, not the actor, but should still be found.
    res = admin_client.get("/api/audit/security-log", params={"email": "bob@example.com"})
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) == 1
    assert items[0]["target_email"] == "bob@example.com"


def test_security_log_actors_endpoint_lists_both_actor_and_target_emails(client, engine):
    target_user_id = _make_user(engine, email="bob@example.com")
    admin_client = _login_as(client, engine, "admin@example.com", role=UserRole.ADMIN)
    admin_client.patch(f"/api/admin/users/{target_user_id}/role", json={"role": "security_engineer"})

    res = admin_client.get("/api/audit/security-log/actors")
    assert res.status_code == 200
    actors = res.json()
    assert "admin@example.com" in actors
    assert "bob@example.com" in actors
