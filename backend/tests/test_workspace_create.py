"""Tests for POST /api/workspaces: the real create path for a new workspace.

Unlike /bootstrap (an explicitly-labeled local/dev helper never called by
the frontend), this is what the Workspaces management page's "New
workspace" button hits. Gated to admin, same bar as /bootstrap, since
creating a workspace (and its org, when one doesn't already exist) is a
platform-level action.

Follows the same in-memory SQLite + TestClient + session-token-login
pattern used in tests/test_workspace_bootstrap_admin_gate.py.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import Organization, User, UserRole, Workspace


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


def test_non_admin_cannot_create_workspace(client, engine):
    client, _uid = _login(client, engine, role=UserRole.DEVELOPER)
    res = client.post("/api/workspaces", json={"name": "prod"})
    assert res.status_code == 403
    with Session(engine) as session:
        assert session.exec(select(Workspace).where(Workspace.name == "prod")).first() is None


def test_create_workspace_with_no_existing_org_makes_a_default(client, engine):
    client, _uid = _login(client, engine, role=UserRole.ADMIN)
    res = client.post("/api/workspaces", json={"name": "prod"})
    assert res.status_code == 200
    body = res.json()
    assert body["name"] == "prod"
    assert body["api_key"]

    with Session(engine) as session:
        org = session.exec(select(Organization).where(Organization.name == "Default")).first()
        assert org is not None
        ws = session.exec(select(Workspace).where(Workspace.id == body["id"])).first()
        assert ws is not None
        assert ws.organization_id == org.id


def test_create_workspace_reuses_existing_org_when_unspecified(client, engine):
    client, _uid = _login(client, engine, role=UserRole.ADMIN)
    with Session(engine) as session:
        org = Organization(name="acme")
        session.add(org)
        session.commit()
        session.refresh(org)
        org_id = org.id

    res = client.post("/api/workspaces", json={"name": "prod"})
    assert res.status_code == 200
    assert res.json()["organization_id"] == org_id


def test_create_workspace_finds_or_creates_named_org(client, engine):
    client, _uid = _login(client, engine, role=UserRole.ADMIN)
    res = client.post("/api/workspaces", json={"name": "prod", "organization_name": "acme-2"})
    assert res.status_code == 200
    with Session(engine) as session:
        org = session.exec(select(Organization).where(Organization.name == "acme-2")).first()
        assert org is not None
        assert res.json()["organization_id"] == org.id


def test_duplicate_workspace_name_in_same_org_is_rejected(client, engine):
    client, _uid = _login(client, engine, role=UserRole.ADMIN)
    res1 = client.post("/api/workspaces", json={"name": "prod", "organization_name": "acme-3"})
    assert res1.status_code == 200
    res2 = client.post("/api/workspaces", json={"name": "prod", "organization_name": "acme-3"})
    assert res2.status_code == 409


def test_blank_name_is_rejected(client, engine):
    client, _uid = _login(client, engine, role=UserRole.ADMIN)
    res = client.post("/api/workspaces", json={"name": "   "})
    assert res.status_code == 422


def test_create_workspace_requires_login(client, engine):
    res = client.post("/api/workspaces", json={"name": "prod"})
    assert res.status_code == 401
