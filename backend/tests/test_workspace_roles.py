"""Tests for issue #32 (workspace/project-scoped RBAC): the WorkspaceMembership
model, the require_workspace_role/enforce_workspace_role dependency, the
admin workspace-roles management endpoints, and that the role boundary is
actually enforced on real workspace-scoped routes (not just asserted in
isolation).

Follows the same in-memory SQLite + TestClient + session-token-login pattern
used in tests/test_pr_guardrail_ignore.py.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    Organization,
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


def _login(client, engine, role=UserRole.USER, email=None):
    email = email or f"{role.value}-{id(object())}@example.com"
    with Session(engine) as session:
        user = User(email=email, name="Test", password_hash=hash_password("whatever123"), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        uid = user.id
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("rikugan_session", token)
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


def _make_target(engine, workspace_id: int, name="target") -> int:
    with Session(engine) as session:
        target = Target(workspace_id=workspace_id, name=name, repo_url="https://github.com/acme/repo")
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


def _assign(engine, user_id: int, workspace_id: int, role: WorkspaceRole):
    with Session(engine) as session:
        m = WorkspaceMembership(user_id=user_id, workspace_id=workspace_id, role=role)
        session.add(m)
        session.commit()


# ---------------------------------------------------------------------------
# Two real workspaces, a developer scoped to only one of them -- the
# workspace boundary must be enforced through a real workspace-scoped route
# (PATCH /api/targets/{id}), not just in an isolated unit test of the
# dependency function.
# ---------------------------------------------------------------------------

def test_developer_can_update_target_in_their_workspace(client, engine):
    ws_a = _make_workspace(engine, "ws-a")
    target_a = _make_target(engine, ws_a)
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, WorkspaceRole.DEVELOPER)

    res = client.patch(f"/api/targets/{target_a}", json={"label": "Prod"})
    assert res.status_code == 200
    assert res.json()["label"] == "Prod"


def test_developer_cannot_update_target_in_other_workspace(client, engine):
    ws_a = _make_workspace(engine, "ws-a")
    ws_b = _make_workspace(engine, "ws-b")
    target_b = _make_target(engine, ws_b, "target-b")
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, WorkspaceRole.DEVELOPER)  # only in A, not B

    res = client.patch(f"/api/targets/{target_b}", json={"label": "Prod"})
    assert res.status_code == 403


def test_user_with_no_membership_anywhere_is_forbidden(client, engine):
    ws_a = _make_workspace(engine, "ws-a")
    target_a = _make_target(engine, ws_a)
    client, _uid = _login(client, engine, role=UserRole.DEVELOPER)  # no WorkspaceMembership row at all

    res = client.patch(f"/api/targets/{target_a}", json={"label": "Prod"})
    assert res.status_code == 403


def test_viewer_role_cannot_update_target(client, engine):
    ws_a = _make_workspace(engine, "ws-a")
    target_a = _make_target(engine, ws_a)
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, WorkspaceRole.VIEWER)  # below DEVELOPER, the min required

    res = client.patch(f"/api/targets/{target_a}", json={"label": "Prod"})
    assert res.status_code == 403


def test_security_engineer_role_satisfies_developer_minimum(client, engine):
    """security_engineer outranks developer in WORKSPACE_ROLE_RANK, so it
    should also pass a route gated at the developer minimum."""
    ws_a = _make_workspace(engine, "ws-a")
    target_a = _make_target(engine, ws_a)
    client, uid = _login(client, engine, role=UserRole.SECURITY_ENGINEER)
    _assign(engine, uid, ws_a, WorkspaceRole.SECURITY_ENGINEER)

    res = client.patch(f"/api/targets/{target_a}", json={"label": "Prod"})
    assert res.status_code == 200


def test_global_admin_bypasses_workspace_membership_entirely(client, engine):
    """Admin should still be able to manage everything -- the workspace role
    model layers on top of the global role, it doesn't replace it."""
    ws_a = _make_workspace(engine, "ws-a")
    target_a = _make_target(engine, ws_a)
    client, _uid = _login(client, engine, role=UserRole.ADMIN)  # no WorkspaceMembership row

    res = client.patch(f"/api/targets/{target_a}", json={"label": "Prod"})
    assert res.status_code == 200


def test_create_target_checks_workspace_id_from_request_body(client, engine):
    """workspace_id lives inside the JSON body for POST /api/targets, not a
    path/query param -- exercises the enforce_workspace_role() direct-call
    path rather than the require_workspace_role Depends() path."""
    ws_a = _make_workspace(engine, "ws-a")
    ws_b = _make_workspace(engine, "ws-b")
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, WorkspaceRole.DEVELOPER)

    ok = client.post("/api/targets", json={
        "workspace_id": ws_a, "name": "t1", "repo_url": "https://github.com/acme/repo",
    })
    assert ok.status_code == 200

    forbidden = client.post("/api/targets", json={
        "workspace_id": ws_b, "name": "t2", "repo_url": "https://github.com/acme/repo2",
    })
    assert forbidden.status_code == 403


def test_bulk_triage_checks_each_findings_workspace_independently(client, engine):
    from app.models.models import Finding, Severity

    ws_a = _make_workspace(engine, "ws-a")
    ws_b = _make_workspace(engine, "ws-b")
    target_a = _make_target(engine, ws_a, "target-a")
    target_b = _make_target(engine, ws_b, "target-b")

    with Session(engine) as session:
        f_a = Finding(target_id=target_a, dedup_hash="h1", tool="semgrep", rule_id="r1", title="t1", file_path="a.py", severity=Severity.HIGH)
        f_b = Finding(target_id=target_b, dedup_hash="h2", tool="semgrep", rule_id="r2", title="t2", file_path="b.py", severity=Severity.HIGH)
        session.add(f_a)
        session.add(f_b)
        session.commit()
        session.refresh(f_a)
        session.refresh(f_b)
        fid_a, fid_b = f_a.id, f_b.id

    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, WorkspaceRole.DEVELOPER)  # only workspace A

    res = client.post("/api/findings/bulk-triage", json={
        "finding_ids": [fid_a, fid_b], "to_state": "Accepted Risk", "reason": "test",
    })
    assert res.status_code == 403


def test_sbom_generate_requires_developer_role_not_viewer(client, engine):
    ws_a = _make_workspace(engine, "ws-a")
    target_a = _make_target(engine, ws_a)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a, WorkspaceRole.VIEWER)

    res = client.post(f"/api/sbom/{target_a}")
    assert res.status_code == 403


# ---------------------------------------------------------------------------
# Admin workspace-roles management endpoints
# ---------------------------------------------------------------------------

def test_non_admin_cannot_manage_workspace_roles(client, engine):
    ws_a = _make_workspace(engine, "ws-a")
    client, uid = _login(client, engine, role=UserRole.USER)

    res = client.put("/api/admin/workspace-roles", json={
        "user_id": uid, "workspace_id": ws_a, "role": "developer",
    })
    assert res.status_code == 403


def test_admin_can_assign_and_list_and_remove_workspace_role(client, engine):
    ws_a = _make_workspace(engine, "ws-a")
    admin_client, _admin_id = _login(client, engine, role=UserRole.ADMIN)

    with Session(engine) as session:
        target_user = User(email="dev@example.com", name="Dev", password_hash=hash_password("whatever123"), role=UserRole.DEVELOPER)
        session.add(target_user)
        session.commit()
        session.refresh(target_user)
        target_uid = target_user.id

    assign_res = admin_client.put("/api/admin/workspace-roles", json={
        "user_id": target_uid, "workspace_id": ws_a, "role": "developer",
    })
    assert assign_res.status_code == 200
    body = assign_res.json()
    assert body["role"] == "developer"
    assert body["workspace_id"] == ws_a
    membership_id = body["id"]

    list_res = admin_client.get(f"/api/admin/workspace-roles?workspace_id={ws_a}")
    assert list_res.status_code == 200
    assert any(m["id"] == membership_id for m in list_res.json())

    # Re-assigning updates in place rather than duplicating.
    reassign_res = admin_client.put("/api/admin/workspace-roles", json={
        "user_id": target_uid, "workspace_id": ws_a, "role": "security_engineer",
    })
    assert reassign_res.status_code == 200
    assert reassign_res.json()["id"] == membership_id
    assert reassign_res.json()["role"] == "security_engineer"

    with Session(engine) as session:
        rows = session.exec(select(WorkspaceMembership).where(WorkspaceMembership.user_id == target_uid)).all()
        assert len(rows) == 1

    del_res = admin_client.delete(f"/api/admin/workspace-roles/{membership_id}")
    assert del_res.status_code == 200

    with Session(engine) as session:
        assert session.get(WorkspaceMembership, membership_id) is None


def test_list_workspaces_returns_multiple_real_workspaces(client, engine):
    """Guards against the design silently assuming a single seeded
    workspace -- the whole point of #32 is real multi-workspace support.

    Logs in as a global admin (issue #224: GET /api/workspaces used to be
    unscoped -- any authenticated user, including a plain UserRole.USER
    with zero WorkspaceMembership rows, saw every workspace platform-wide.
    accessible_workspace_ids() now filters it the same way every other
    workspace-owned list route is filtered, so this asserts the
    multi-workspace behavior via the one role that's still meant to see
    everything.)"""
    _make_workspace(engine, "ws-a")
    _make_workspace(engine, "ws-b")
    client, _uid = _login(client, engine, role=UserRole.ADMIN)

    res = client.get("/api/workspaces")
    assert res.status_code == 200
    names = {w["name"] for w in res.json()}
    assert {"ws-a", "ws-b"}.issubset(names)


def test_list_workspaces_excludes_workspaces_without_membership(client, engine):
    """Issue #224: the regression this scoping fix actually targets -- a
    non-admin, non-member user must not see a workspace's name/id/api_key
    just by being logged in."""
    ws_a = _make_workspace(engine, "ws-a")
    _make_workspace(engine, "ws-b")
    client, uid = _login(client, engine, role=UserRole.USER)
    _assign(engine, uid, ws_a, WorkspaceRole.VIEWER)

    res = client.get("/api/workspaces")
    assert res.status_code == 200
    names = {w["name"] for w in res.json()}
    assert names == {"ws-a"}
