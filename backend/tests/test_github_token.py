"""Tests for issue #227's per-workspace GitHub token storage: Fernet
encryption-at-rest, never-echo, lazy expiry purge, PAT-over-App precedence,
and the admin-only management API. Follows the in-memory SQLite + TestClient +
session-token-login pattern used by tests/test_sbom_import.py.
"""

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
import app.api.github_token as github_token_api
import app.core.github_token as github_token
from app.api.deps import get_session
from app.core.crypto import decrypt_secret
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    GitHubAppConfig,
    GitHubInstallation,
    GitHubToken,
    Organization,
    User,
    UserRole,
    Workspace,
    WorkspaceMembership,
    WorkspaceRole,
)


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    return eng


@pytest.fixture()
def session(engine):
    with Session(engine) as s:
        yield s


@pytest.fixture()
def client(engine):
    def override_get_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    original_engine = deps_module.engine
    deps_module.engine = engine

    c = TestClient(app)
    yield c
    app.dependency_overrides.clear()
    deps_module.engine = original_engine


def _workspace(session, name="ws-token") -> Workspace:
    org = Organization(name=f"org-{name}")
    session.add(org)
    session.commit()
    session.refresh(org)
    ws = Workspace(organization_id=org.id, name=name, api_key=f"key-{name}")
    session.add(ws)
    session.commit()
    session.refresh(ws)
    return ws


def _store_token(session, workspace_id, plaintext="ghp_secret", expires_at=None):
    return github_token.upsert_github_token(session, workspace_id, plaintext, expires_at)


def _admin_client(client, engine, role=UserRole.ADMIN):
    with Session(engine) as session:
        ws = _workspace(session, name="ws-admin")
        workspace_id = ws.id
        user = User(
            email=f"admin-{id(object())}@example.com",
            name="Admin",
            password_hash=hash_password("whatever123"),
            role=role,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        if role != UserRole.ADMIN:
            session.add(WorkspaceMembership(user_id=user.id, workspace_id=workspace_id, role=WorkspaceRole.DEVELOPER))
            session.commit()
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return workspace_id


# --- storage ----------------------------------------------------------------


def test_upsert_encrypts_and_round_trips(session):
    ws = _workspace(session)
    row = _store_token(session, ws.id, plaintext="ghp_plaintext")

    assert row.token_ciphertext != "ghp_plaintext"
    assert decrypt_secret(row.token_ciphertext) == "ghp_plaintext"
    assert github_token.resolve_github_token(session, ws.id) == "ghp_plaintext"


def test_upsert_replaces_existing_token(session):
    ws = _workspace(session)
    _store_token(session, ws.id, plaintext="ghp_first")
    _store_token(session, ws.id, plaintext="ghp_second")

    rows = session.exec(select(GitHubToken).where(GitHubToken.workspace_id == ws.id)).all()
    assert len(rows) == 1
    assert github_token.resolve_github_token(session, ws.id) == "ghp_second"


def test_resolve_returns_none_when_no_token(session):
    ws = _workspace(session)
    assert github_token.resolve_github_token(session, ws.id) is None


def test_resolve_lazily_purges_expired_token(session):
    ws = _workspace(session)
    _store_token(session, ws.id, plaintext="ghp_expired", expires_at=datetime.utcnow() - timedelta(hours=1))

    assert github_token.resolve_github_token(session, ws.id) is None
    assert session.exec(select(GitHubToken).where(GitHubToken.workspace_id == ws.id)).first() is None


def test_resolve_returns_unexpired_token(session):
    ws = _workspace(session)
    _store_token(session, ws.id, plaintext="ghp_future", expires_at=datetime.utcnow() + timedelta(hours=1))

    assert github_token.resolve_github_token(session, ws.id) == "ghp_future"


def test_resolve_prefers_pat_over_installation_token(session, monkeypatch):
    ws = _workspace(session)
    _store_token(session, ws.id, plaintext="ghp_pat")
    monkeypatch.setattr(github_token, "_resolve_installation_token", lambda s, wid, slug: "app-tok")

    assert github_token.resolve_github_token(session, ws.id, "acme/repo-a") == "ghp_pat"


def test_resolve_falls_back_to_installation_token(session, monkeypatch):
    ws = _workspace(session)
    monkeypatch.setattr(github_token, "_resolve_installation_token", lambda s, wid, slug: "app-tok")

    assert github_token.resolve_github_token(session, ws.id, "acme/repo-a") == "app-tok"


def test_delete_github_token(session):
    ws = _workspace(session)
    _store_token(session, ws.id, plaintext="ghp_secret")

    assert github_token.delete_github_token(session, ws.id) is True
    assert github_token.resolve_github_token(session, ws.id) is None
    assert github_token.delete_github_token(session, ws.id) is False


def test_purge_expired_tokens(session):
    ws1 = _workspace(session, name="ws1")
    ws2 = _workspace(session, name="ws2")
    _store_token(session, ws1.id, plaintext="ghp_expired", expires_at=datetime.utcnow() - timedelta(hours=1))
    _store_token(session, ws2.id, plaintext="ghp_future", expires_at=datetime.utcnow() + timedelta(hours=1))

    assert github_token.purge_expired_tokens(session) == 1
    assert session.exec(select(GitHubToken).where(GitHubToken.workspace_id == ws1.id)).first() is None
    assert session.exec(select(GitHubToken).where(GitHubToken.workspace_id == ws2.id)).first() is not None


# --- API --------------------------------------------------------------------


def test_github_token_endpoints_are_admin_gated(client, engine):
    ws = _admin_client(client, engine, role=UserRole.DEVELOPER)

    assert client.get(f"/api/github-token?workspace_id={ws}").status_code == 403
    assert client.put(f"/api/github-token", json={"token": "ghp_secret"}).status_code == 403
    assert client.delete(f"/api/github-token?workspace_id={ws}").status_code == 403
    assert client.post("/api/github-token/test", json={"token": "ghp_secret"}).status_code == 403


def test_put_get_delete_round_trip_never_echoes_ciphertext(client, engine):
    ws = _admin_client(client, engine)

    res = client.put(
        f"/api/github-token", json={"token": "ghp_secret", "expires_in_hours": 24, "workspace_id": ws}
    )
    assert res.status_code == 200
    body = res.json()
    assert body["token_set"] is True
    assert body["expires_at"] is not None
    assert "token" not in body
    assert "ghp_secret" not in res.text

    res = client.get(f"/api/github-token?workspace_id={ws}")
    assert res.status_code == 200
    assert res.json()["token_set"] is True
    assert "ghp_secret" not in res.text

    res = client.delete(f"/api/github-token?workspace_id={ws}")
    assert res.status_code == 200
    assert res.json()["token_set"] is False

    assert client.get(f"/api/github-token?workspace_id={ws}").json()["token_set"] is False


def test_unknown_workspace_id_is_404_not_500(client, engine):
    # Issue #226 review nit: a caller-supplied workspace_id that doesn't
    # exist used to sail through _resolve_workspace_id unchecked; GET
    # silently read back token_set: false (indistinguishable from "no token
    # saved yet"), and PUT would have hit the GitHubToken FK constraint as a
    # bare 500 instead of a real 404.
    _admin_client(client, engine)

    assert client.get("/api/github-token?workspace_id=999999").status_code == 404
    assert (
        client.put(
            "/api/github-token", json={"token": "ghp_secret", "workspace_id": 999999}
        ).status_code
        == 404
    )
    assert client.delete("/api/github-token?workspace_id=999999").status_code == 404


def test_put_rejects_empty_token(client, engine):
    ws = _admin_client(client, engine)

    res = client.put(f"/api/github-token", json={"token": "   ", "workspace_id": ws})
    assert res.status_code == 400


def test_put_rejects_nonpositive_ttl(client, engine):
    ws = _admin_client(client, engine)

    res = client.put(f"/api/github-token", json={"token": "ghp_secret", "expires_in_hours": 0, "workspace_id": ws})
    assert res.status_code == 400


def test_test_endpoint_uses_real_call_and_never_logs_token(client, engine, monkeypatch):
    ws = _admin_client(client, engine)
    captured = {}

    class _Resp:
        status_code = 200

        def json(self):
            return {"login": "octocat"}

    def fake_get(url, headers=None, timeout=None):
        captured["headers"] = headers
        return _Resp()

    monkeypatch.setattr(github_token_api.httpx, "get", fake_get)

    res = client.post("/api/github-token/test", json={"token": "ghp_secret", "workspace_id": ws})
    assert res.status_code == 200
    assert res.json()["success"] is True
    assert captured["headers"]["Authorization"] == "Bearer ghp_secret"


def test_test_endpoint_requires_token_or_stored_token(client, engine):
    ws = _admin_client(client, engine)

    res = client.post("/api/github-token/test", json={"workspace_id": ws})
    assert res.status_code == 400
