"""Tests for issue #109: public API (/api/public/v1/*, Bearer-token auth)
and its token management endpoints (/api/api-tokens, session-authenticated).
"""
import itertools

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
import app.tasks.scan_tasks as scan_tasks_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    ApiToken,
    ApiTokenScope,
    Finding,
    Organization,
    Scan,
    Severity,
    Target,
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


_email_counter = itertools.count()


def _login(client, engine, role=UserRole.DEVELOPER) -> tuple[TestClient, int]:
    email = f"{role.value}-{next(_email_counter)}@example.com"
    with Session(engine) as session:
        user = User(email=email, name="Test", password_hash=hash_password("whatever123"), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        uid = user.id
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("rikugan_session", token)
    return client, uid


def _make_workspace_and_target(engine) -> tuple[int, int]:
    with Session(engine) as session:
        org = Organization(name="org")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws", api_key="key")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        target = Target(workspace_id=ws.id, name="repo", repo_url="https://github.com/acme/repo")
        session.add(target)
        session.commit()
        session.refresh(target)
        return ws.id, target.id


def _assign(engine, user_id: int, workspace_id: int, role: WorkspaceRole = WorkspaceRole.DEVELOPER):
    with Session(engine) as session:
        session.add(WorkspaceMembership(user_id=user_id, workspace_id=workspace_id, role=role))
        session.commit()


# ---------------------------------------------------------------------------
# Token management (/api/api-tokens) -- session-authenticated
# ---------------------------------------------------------------------------


def test_create_token_returns_plaintext_once(client, engine):
    client, _ = _login(client, engine)
    res = client.post("/api/api-tokens", json={"name": "ci-token"})
    assert res.status_code == 200
    body = res.json()
    assert body["token"].startswith("rikugan_pat_")
    assert body["scope"] == "read"
    assert body["token_prefix"] in body["token"]


def test_list_tokens_never_includes_plaintext(client, engine):
    client, _ = _login(client, engine)
    client.post("/api/api-tokens", json={"name": "ci-token"})

    res = client.get("/api/api-tokens")
    assert res.status_code == 200
    body = res.json()
    assert len(body) == 1
    assert "token" not in body[0]
    assert body[0]["token_prefix"]


def test_revoke_token_then_it_stops_authenticating(client, engine):
    client, _ = _login(client, engine)
    created = client.post("/api/api-tokens", json={"name": "ci-token"}).json()

    res = client.get(f"/api/public/v1/targets", headers={"Authorization": f"Bearer {created['token']}"})
    assert res.status_code == 200

    revoke_res = client.post(f"/api/api-tokens/{created['id']}/revoke")
    assert revoke_res.status_code == 200
    assert revoke_res.json()["revoked_at"] is not None

    res2 = client.get(f"/api/public/v1/targets", headers={"Authorization": f"Bearer {created['token']}"})
    assert res2.status_code == 401


def test_cannot_revoke_someone_elses_token(client, engine):
    client, _ = _login(client, engine)
    created = client.post("/api/api-tokens", json={"name": "ci-token"}).json()

    other_client = TestClient(app)
    other_client, _ = _login(other_client, engine)
    res = other_client.post(f"/api/api-tokens/{created['id']}/revoke")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# Public API (/api/public/v1) -- Bearer-token authenticated
# ---------------------------------------------------------------------------


def _make_token_for_user(engine, user_id: int, scope: ApiTokenScope = ApiTokenScope.READ) -> str:
    from app.core.security import generate_api_token

    plaintext, token_hash, token_prefix = generate_api_token()
    with Session(engine) as session:
        session.add(ApiToken(user_id=user_id, name="t", token_hash=token_hash, token_prefix=token_prefix, scope=scope))
        session.commit()
    return plaintext


def test_public_api_rejects_missing_auth_header(client, engine):
    res = client.get("/api/public/v1/targets")
    assert res.status_code == 401


def test_public_api_rejects_garbage_token(client, engine):
    res = client.get("/api/public/v1/targets", headers={"Authorization": "Bearer not-a-real-token"})
    assert res.status_code == 401


def test_public_api_lists_only_accessible_targets(client, engine):
    ws_id, target_id = _make_workspace_and_target(engine)
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_id)
    token = _make_token_for_user(engine, uid)

    res = client.get("/api/public/v1/targets", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    ids = [t["id"] for t in res.json()]
    assert target_id in ids


def test_public_api_get_target_404s_outside_workspace(client, engine):
    ws_id, target_id = _make_workspace_and_target(engine)
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    # Deliberately NOT assigned to ws_id.
    token = _make_token_for_user(engine, uid)

    res = client.get(f"/api/public/v1/targets/{target_id}", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 404


def test_public_api_lists_findings_for_accessible_target(client, engine):
    ws_id, target_id = _make_workspace_and_target(engine)
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_id)
    token = _make_token_for_user(engine, uid)

    with Session(engine) as session:
        session.add(Finding(
            target_id=target_id, dedup_hash="h1", tool="semgrep", rule_id="r1", title="t",
            file_path="a.py", severity=Severity.HIGH,
        ))
        session.commit()

    res = client.get("/api/public/v1/findings", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 1


def test_read_scoped_token_cannot_trigger_scan(client, engine, monkeypatch):
    ws_id, target_id = _make_workspace_and_target(engine)
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_id)
    token = _make_token_for_user(engine, uid, scope=ApiTokenScope.READ)

    res = client.post(
        f"/api/public/v1/scans?target_id={target_id}&tool=semgrep",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 403


def test_read_write_scoped_token_can_trigger_scan(client, engine, monkeypatch):
    monkeypatch.setattr(scan_tasks_module.run_scan, "delay", lambda **kwargs: None)
    ws_id, target_id = _make_workspace_and_target(engine)
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_id)
    token = _make_token_for_user(engine, uid, scope=ApiTokenScope.READ_WRITE)

    res = client.post(
        f"/api/public/v1/scans?target_id={target_id}&tool=semgrep",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "running"

    with Session(engine) as session:
        scan = session.get(Scan, res.json()["scan_id"])
        assert scan.tool == "semgrep"


# ---------------------------------------------------------------------------
# OpenAPI: the spec must describe how to authenticate
# ---------------------------------------------------------------------------


def test_openapi_declares_the_api_token_security_scheme(client):
    """Reading the Authorization header manually works at runtime but is
    invisible to the schema, so Swagger UI, Postman imports and generated
    clients all showed these endpoints as unauthenticated with no way to send
    a token. The published spec is only useful if it says how to authenticate.
    """
    spec = client.get("/openapi.json").json()
    schemes = spec.get("components", {}).get("securitySchemes", {})
    assert "ApiToken" in schemes
    assert schemes["ApiToken"]["type"] == "http"
    assert schemes["ApiToken"]["scheme"] == "bearer"


def test_every_public_endpoint_requires_the_token_scheme(client):
    spec = client.get("/openapi.json").json()
    public = {p: v for p, v in spec["paths"].items() if p.startswith("/api/public/v1")}
    assert public, "no public API paths found in the spec"
    for path, methods in public.items():
        for method, op in methods.items():
            assert op.get("security") == [{"ApiToken": []}], f"{method.upper()} {path}"
