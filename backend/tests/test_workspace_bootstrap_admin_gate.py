"""Tests for issue #56: POST /api/workspaces/bootstrap creates a brand-new
Organization + Workspace + API key, which is a platform-level action, not a
within-workspace one; it must be gated to the global admin role, not just
any authenticated user (the router's blanket login_required previously let
any logged-in user, including role=viewer/developer, create arbitrary new
orgs/workspaces and mint their API keys).

Follows the same in-memory SQLite + TestClient + session-token-login pattern
used in tests/test_workspace_roles.py / tests/test_pr_guardrail_ignore.py.
"""
from sqlmodel import Session, select

from app.core.security import create_session_token, hash_password
from app.models.models import Organization, User, UserRole, Workspace


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


def test_non_admin_cannot_bootstrap_workspace(client, engine):
    client, _uid = _login(client, engine, role=UserRole.DEVELOPER)

    res = client.post("/api/workspaces/bootstrap", params={
        "org_name": "acme", "workspace_name": "prod",
    })
    assert res.status_code == 403

    with Session(engine) as session:
        assert session.exec(select(Organization).where(Organization.name == "acme")).first() is None
        assert session.exec(select(Workspace).where(Workspace.name == "prod")).first() is None


def test_viewer_cannot_bootstrap_workspace(client, engine):
    """Also covers the lowest-privileged authenticated role, not just
    developer, since the whole point is that this isn't a within-workspace
    permission at all."""
    client, _uid = _login(client, engine, role=UserRole.VIEWER)

    res = client.post("/api/workspaces/bootstrap", params={
        "org_name": "acme-viewer", "workspace_name": "prod",
    })
    assert res.status_code == 403


def test_admin_can_bootstrap_workspace(client, engine):
    client, _uid = _login(client, engine, role=UserRole.ADMIN)

    res = client.post("/api/workspaces/bootstrap", params={
        "org_name": "acme-admin", "workspace_name": "prod",
    })
    assert res.status_code == 200
    body = res.json()
    assert body["name"] == "prod"
    assert body["api_key"]

    with Session(engine) as session:
        org = session.exec(select(Organization).where(Organization.name == "acme-admin")).first()
        assert org is not None
        ws = session.exec(select(Workspace).where(Workspace.id == body["id"])).first()
        assert ws is not None
        assert ws.organization_id == org.id


def test_bootstrap_still_requires_login_at_all(client, engine):
    """No session cookie; should 401 (login_required from the router),
    not fall through to the admin check with a None user."""
    res = client.post("/api/workspaces/bootstrap", params={
        "org_name": "acme-anon", "workspace_name": "prod",
    })
    assert res.status_code == 401
