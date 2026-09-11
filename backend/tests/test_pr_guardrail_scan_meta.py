"""Tests for GET /api/pr-guardrail/{pr_scan_id}: minimal scan metadata for
surfaces that only have a pr_scan_id in hand, e.g. the /ignore-request
confirmation page's "back to PR" link.
"""
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
import pytest
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    Organization,
    PRGuardrailScan,
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


def _login(client, engine, role=UserRole.VIEWER):
    email = f"{role.value}-{id(object())}@example.com"
    with Session(engine) as session:
        user = User(email=email, name="Test", password_hash=hash_password("whatever123"), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        uid = user.id
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return client, uid


def _setup(engine, repo_url="https://github.com/acme/repo", pr_number=7):
    with Session(engine) as session:
        org = Organization(name="org")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws", api_key="key")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        target = Target(workspace_id=ws.id, name="target", repo_url=repo_url)
        session.add(target)
        session.commit()
        session.refresh(target)
        scan = PRGuardrailScan(target_id=target.id, pr_number=pr_number, pr_title="t", branch="feature")
        session.add(scan)
        session.commit()
        session.refresh(scan)
        return ws.id, scan.id


def test_returns_pr_number_and_url_for_an_accessible_scan(client, engine):
    ws_id, scan_id = _setup(engine)
    client, uid = _login(client, engine)
    with Session(engine) as session:
        session.add(WorkspaceMembership(user_id=uid, workspace_id=ws_id, role=WorkspaceRole.VIEWER))
        session.commit()

    res = client.get(f"/api/pr-guardrail/{scan_id}")
    assert res.status_code == 200
    body = res.json()
    assert body["pr_number"] == 7
    assert body["pr_url"] == "https://github.com/acme/repo/pull/7"


def test_pr_url_is_none_for_an_unparseable_repo_url(client, engine):
    ws_id, scan_id = _setup(engine, repo_url="")
    client, uid = _login(client, engine)
    with Session(engine) as session:
        session.add(WorkspaceMembership(user_id=uid, workspace_id=ws_id, role=WorkspaceRole.VIEWER))
        session.commit()

    res = client.get(f"/api/pr-guardrail/{scan_id}")
    assert res.status_code == 200
    assert res.json()["pr_url"] is None


def test_404s_for_a_scan_outside_the_callers_workspace(client, engine):
    """Same 404-not-403 pattern as every other workspace-scoped read (#57):
    a caller with no membership on this scan's workspace must not learn the
    scan exists at all."""
    _setup(engine)
    client, _uid = _login(client, engine)  # no WorkspaceMembership row

    res = client.get("/api/pr-guardrail/1")
    assert res.status_code == 404


def test_404s_for_a_nonexistent_scan_id(client, engine):
    client, _uid = _login(client, engine, role=UserRole.ADMIN)
    res = client.get("/api/pr-guardrail/999999")
    assert res.status_code == 404
