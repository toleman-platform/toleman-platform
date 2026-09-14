"""The workspace API key must not ride along on ordinary workspace reads.

Workspace.api_key is a real credential: it is what a CI pipeline presents
to ingest scan results. Both GET /api/workspaces and PATCH
/api/workspaces/{id} used to return the Workspace ORM row directly, with
no response_model, so every caller who asked for the workspace list -- or
who saved an unrelated setting like enforcement_mode -- got the key back
in the response body for every workspace they can see.

That is excessive data exposure rather than a privilege bypass: a member
can already read the key deliberately via GET /{workspace_id}/key, which
applies the same accessible_workspace_ids check. The problem is that the
key travelled everywhere the list travelled, into logs, proxies and
browser caches, for callers who never asked for it and whose UI never
reads it (the frontend's WorkspaceSummary type has no api_key field at
all).

So the boundary these tests pin is a deliberate split, not a blanket ban:
routes that *read* a workspace must omit the key, and the three routes
whose whole purpose is to hand a freshly-minted or explicitly-requested
key to the caller must keep returning it. Asserting only the first half
would let someone "fix" the second half too and silently break CI setup.

Follows the in-memory SQLite + TestClient + session-token-login pattern
from tests/test_workspace_create.py.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

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


def _login(client, engine, role=UserRole.ADMIN):
    with Session(engine) as session:
        user = User(
            email=f"{role.value}-{id(object())}@example.com",
            name="Test",
            password_hash=hash_password("whatever123"),
            role=role,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return client


def _seed_workspace(engine, name="prod"):
    with Session(engine) as session:
        org = Organization(name="Acme")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name=name, api_key="super-secret-key")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        return ws.id


def test_workspace_list_does_not_leak_the_api_key(client, engine):
    client = _login(client, engine)
    _seed_workspace(engine)

    res = client.get("/api/workspaces")

    assert res.status_code == 200
    body = res.json()
    assert body, "expected at least one workspace"
    for item in body:
        assert "api_key" not in item
    # Asserted as a raw substring too: a future response model that renamed
    # the field, or nested the ORM row under another key, would still slip
    # the credential past a check that only looks for the "api_key" name.
    assert "super-secret-key" not in res.text


def test_workspace_list_still_returns_the_fields_the_ui_reads(client, engine):
    """The frontend's WorkspaceSummary type. Narrowing the response model
    must not narrow it past what the Workspaces page actually renders."""
    client = _login(client, engine)
    _seed_workspace(engine)

    item = client.get("/api/workspaces").json()[0]

    assert set(item) >= {"id", "name", "organization_id", "enforcement_mode"}


def test_workspace_update_does_not_leak_the_api_key(client, engine):
    client = _login(client, engine)
    ws_id = _seed_workspace(engine)

    res = client.patch(f"/api/workspaces/{ws_id}", json={"enforcement_mode": "alert"})

    assert res.status_code == 200
    body = res.json()
    assert "api_key" not in body
    assert "super-secret-key" not in res.text
    assert body["enforcement_mode"] == "alert"


def test_create_still_returns_the_key_once(client, engine):
    """Creating a workspace mints its key, and this is the response that
    hands it over -- narrowing this route would leave an admin unable to
    wire up CI without a second call."""
    client = _login(client, engine)

    res = client.post("/api/workspaces", json={"name": "newspace"})

    assert res.status_code == 200
    assert res.json()["api_key"]


def test_dedicated_key_route_still_returns_the_key(client, engine):
    client = _login(client, engine)
    ws_id = _seed_workspace(engine)

    res = client.get(f"/api/workspaces/{ws_id}/key")

    assert res.status_code == 200
    assert res.json()["api_key"] == "super-secret-key"


def test_key_regeneration_still_returns_the_new_key(client, engine):
    client = _login(client, engine)
    ws_id = _seed_workspace(engine)

    res = client.post(f"/api/workspaces/{ws_id}/key/regenerate")

    assert res.status_code == 200
    new_key = res.json()["api_key"]
    assert new_key and new_key != "super-secret-key"
