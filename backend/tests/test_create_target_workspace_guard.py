"""Issue #356: POST /api/targets (and POST /api/groups) must reject a
workspace_id with no row behind it, cleanly.

`Target.workspace_id` and `Group.workspace_id` are real FK columns, and
nothing used to prove the referenced row existed before `session.commit()`:
`enforce_workspace_role` returns immediately for a global admin, and for
everyone else it only asks whether a WorkspaceMembership exists, which for a
nonexistent workspace simply doesn't, so that path 403s earlier. An admin
POSTing a stale or invented workspace_id therefore reached the insert, where
Postgres raised ForeignKeyViolation -> an unhandled IntegrityError. That
escapes CORSMiddleware before it has built a response, so the fallback 500
carries no Access-Control-Allow-Origin header and the browser reports it as a
CORS failure; the frontend's own banner then blames CORS configuration, which
is not the problem. On a fresh deployment with zero workspaces this was the
*default* outcome of the manual add-a-repo form, whose workspace_id defaulted
to a hardcoded 1.

Note these tests run on in-memory SQLite, which does not enforce foreign keys
unless `PRAGMA foreign_keys=ON` is set, so they cannot reproduce the
IntegrityError itself; before the fix the insert here would have succeeded and
left an orphan row. What they pin is the contract either way: a workspace_id
that does not resolve is a 404, not a 500 and not a silent orphan.

Ordering matters as much as the check: the existence check is placed *after*
the role check, so a caller outside the workspace still gets the same 403 it
always got and cannot use this route to probe which workspace ids are real.

Follows the same in-memory SQLite + TestClient + session-token-login pattern
as tests/test_workspace_create.py and tests/test_workspace_roles.py.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import Group, Organization, Target, User, UserRole, Workspace


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


def _login(client, engine, role=UserRole.ADMIN, email=None):
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


def _make_workspace(engine, name="ws") -> int:
    with Session(engine) as session:
        org = Organization(name=f"org-{name}")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name=name, api_key=f"key-{name}")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        return ws.id


def test_create_target_with_nonexistent_workspace_returns_404(client, engine):
    """The reported symptom: a fresh deployment with no workspace rows at
    all, and a form that posted workspace_id=1 anyway."""
    client, _uid = _login(client, engine, role=UserRole.ADMIN)

    res = client.post(
        "/api/targets",
        json={"workspace_id": 999, "name": "repo", "repo_url": "https://github.com/acme/repo"},
    )

    assert res.status_code == 404
    assert res.json()["detail"] == "workspace not found"
    with Session(engine) as session:
        assert session.exec(select(Target)).all() == []


def test_create_target_with_a_real_workspace_still_works(client, engine):
    """The guard must not cost the happy path; without this, a check that
    rejected everything would still pass the test above."""
    ws_id = _make_workspace(engine, "real")
    client, _uid = _login(client, engine, role=UserRole.ADMIN)

    res = client.post(
        "/api/targets",
        json={"workspace_id": ws_id, "name": "repo", "repo_url": "https://github.com/acme/repo"},
    )

    assert res.status_code == 200
    assert res.json()["workspace_id"] == ws_id


def test_nonexistent_workspace_is_403_not_404_for_a_non_member(client, engine):
    """Existence is only disclosed to callers who already cleared the role
    bar. A developer with no membership sees the same 403 whether or not the
    id exists, so the new 404 can't be used to enumerate workspace ids."""
    client, _uid = _login(client, engine, role=UserRole.DEVELOPER)

    res = client.post(
        "/api/targets",
        json={"workspace_id": 999, "name": "repo", "repo_url": "https://github.com/acme/repo"},
    )

    assert res.status_code == 403


def test_create_group_with_nonexistent_workspace_returns_404(client, engine):
    """POST /api/groups had the identical unguarded-FK shape, reachable from
    the Repo Groups admin panel, and would fail the same misleading way."""
    client, _uid = _login(client, engine, role=UserRole.ADMIN)

    res = client.post("/api/groups", json={"workspace_id": 999, "name": "production"})

    assert res.status_code == 404
    assert res.json()["detail"] == "workspace not found"
    with Session(engine) as session:
        assert session.exec(select(Group)).all() == []


def test_create_group_with_a_real_workspace_still_works(client, engine):
    ws_id = _make_workspace(engine, "groups")
    client, _uid = _login(client, engine, role=UserRole.ADMIN)

    res = client.post("/api/groups", json={"workspace_id": ws_id, "name": "production"})

    assert res.status_code == 200
    assert res.json()["workspace_id"] == ws_id
