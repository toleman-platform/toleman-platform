"""Tests for issue #129: the workspace API key (X-API-Key, used for CI push
ingestion via POST /api/ingest/{target_id}; see app.api.deps.require_workspace)
had no rotation path. POST /api/targets/{target_id}/workspace-key/regenerate
now mints a new key, gated at WorkspaceRole.DEVELOPER (the same bar as the
other workspace-settings writes, PATCH /api/targets/{id} and PATCH
/api/workspaces/{id}; see test_workspace_roles.py).

Follows the same in-memory SQLite + TestClient + session-token-login pattern
used in tests/test_workspace_roles.py and tests/test_rate_limit.py. The real
proof that rotation matters: after regenerating, the *old* key must stop
authenticating against the real ingest endpoint (401), and the *new* key
must work; not just that the DB row changed.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import Organization, Target, User, UserRole, Workspace, WorkspaceMembership, WorkspaceRole


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
    # require_workspace() (the ingest auth dependency) opens its own Session
    # against the module-level `engine` name it imported directly, not via
    # get_session; swap that too or ingest calls would hit real Postgres.
    original_deps_engine = deps_module.engine
    deps_module.engine = engine

    c = TestClient(app)
    yield c
    app.dependency_overrides.clear()
    deps_module.engine = original_deps_engine


def _login(client, engine, role=UserRole.USER, email=None):
    email = email or f"{role.value}-{id(object())}@example.com"
    with Session(engine) as session:
        user = User(email=email, name="Test", password_hash=hash_password("whatever123"), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        uid = user.id
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return client, uid


def _make_workspace_and_target(engine, name="ws") -> tuple[int, str, int]:
    with Session(engine) as session:
        org = Organization(name=f"org-{name}")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name=name, api_key=f"original-key-{name}")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        target = Target(workspace_id=ws.id, name="target", repo_url="https://github.com/acme/repo")
        session.add(target)
        session.commit()
        session.refresh(target)
        return ws.id, ws.api_key, target.id


def _assign(engine, user_id: int, workspace_id: int, role: WorkspaceRole):
    with Session(engine) as session:
        session.add(WorkspaceMembership(user_id=user_id, workspace_id=workspace_id, role=role))
        session.commit()


SARIF_PAYLOAD = {
    "runs": [
        {
            "tool": {"driver": {"name": "semgrep", "rules": []}},
            "results": [],
        }
    ]
}


def test_regenerate_rotates_key_and_old_key_stops_working(client, engine):
    ws_id, old_key, target_id = _make_workspace_and_target(engine)
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_id, WorkspaceRole.DEVELOPER)

    # Old key authenticates against real CI push ingestion before rotation.
    pre = client.post(f"/api/ingest/{target_id}", json=SARIF_PAYLOAD, headers={"x-api-key": old_key})
    assert pre.status_code == 200

    res = client.post(f"/api/targets/{target_id}/workspace-key/regenerate")
    assert res.status_code == 200
    new_key = res.json()["api_key"]
    assert new_key != old_key
    assert len(new_key) > 16

    # Old key is dead immediately, real 401 against the real ingest route.
    stale = client.post(f"/api/ingest/{target_id}", json=SARIF_PAYLOAD, headers={"x-api-key": old_key})
    assert stale.status_code == 401

    # New key works.
    fresh = client.post(f"/api/ingest/{target_id}", json=SARIF_PAYLOAD, headers={"x-api-key": new_key})
    assert fresh.status_code == 200

    # GET reflects the rotated key too.
    get_res = client.get(f"/api/targets/{target_id}/workspace-key")
    assert get_res.json()["api_key"] == new_key


def test_regenerate_requires_developer_role_viewer_forbidden(client, engine):
    ws_id, old_key, target_id = _make_workspace_and_target(engine, "ws-viewer")
    client, uid = _login(client, engine, role=UserRole.USER)
    _assign(engine, uid, ws_id, WorkspaceRole.VIEWER)

    res = client.post(f"/api/targets/{target_id}/workspace-key/regenerate")
    assert res.status_code == 403

    # Key unchanged.
    get_res = client.get(f"/api/targets/{target_id}/workspace-key")
    assert get_res.json()["api_key"] == old_key


def test_regenerate_forbidden_with_no_workspace_membership(client, engine):
    ws_id, old_key, target_id = _make_workspace_and_target(engine, "ws-none")
    client, uid = _login(client, engine, role=UserRole.USER)
    # no WorkspaceMembership assigned at all

    res = client.post(f"/api/targets/{target_id}/workspace-key/regenerate")
    assert res.status_code == 403


def test_regenerate_allowed_for_developer_in_own_workspace_not_other(client, engine):
    ws_a, _, target_a = _make_workspace_and_target(engine, "ws-a")
    ws_b, key_b, target_b = _make_workspace_and_target(engine, "ws-b")
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, WorkspaceRole.DEVELOPER)  # only in A

    ok = client.post(f"/api/targets/{target_a}/workspace-key/regenerate")
    assert ok.status_code == 200

    forbidden = client.post(f"/api/targets/{target_b}/workspace-key/regenerate")
    assert forbidden.status_code == 403

    # workspace B's key untouched by the forbidden attempt; read directly
    # from the DB rather than via the API, since this user (no membership in
    # B) correctly can't read B's key either (same 404-not-403 IDOR guard as
    # the regenerate route).
    with Session(engine) as session:
        ws_b = session.get(Workspace, ws_b)
        assert ws_b.api_key == key_b


def test_regenerate_allowed_for_global_admin(client, engine):
    ws_id, old_key, target_id = _make_workspace_and_target(engine, "ws-admin")
    client, uid = _login(client, engine, role=UserRole.ADMIN)
    # global admin, no WorkspaceMembership row needed (enforce_workspace_role bypasses)

    res = client.post(f"/api/targets/{target_id}/workspace-key/regenerate")
    assert res.status_code == 200
    assert res.json()["api_key"] != old_key
