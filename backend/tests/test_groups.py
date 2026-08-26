"""Tests for issue #61 (target groups/tags): the Group/TargetGroup models,
the group CRUD API, target<->group assignment, and that GET /api/targets and
GET /api/findings actually filter by group_id end to end; not just storage
with no way to use it.

Follows the same in-memory SQLite + TestClient + session-token-login pattern
used in tests/test_workspace_roles.py, including its real workspace-scoping
assertions (a developer scoped to one workspace must not be able to touch
another workspace's groups or read across the boundary).
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
    Finding,
    Group,
    Organization,
    Severity,
    Target,
    TargetGroup,
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


def _make_target(engine, workspace_id: int, name="target") -> int:
    with Session(engine) as session:
        target = Target(workspace_id=workspace_id, name=name, repo_url="https://github.com/acme/repo")
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


def _make_group(engine, workspace_id: int, name="group", color="#ff0000") -> int:
    with Session(engine) as session:
        group = Group(workspace_id=workspace_id, name=name, color=color)
        session.add(group)
        session.commit()
        session.refresh(group)
        return group.id


def _make_finding(engine, target_id: int, dedup_hash="h1") -> int:
    with Session(engine) as session:
        f = Finding(
            target_id=target_id, dedup_hash=dedup_hash, tool="semgrep", rule_id="r1",
            title="t1", file_path="a.py", severity=Severity.HIGH,
        )
        session.add(f)
        session.commit()
        session.refresh(f)
        return f.id


def _assign(engine, user_id: int, workspace_id: int, role: WorkspaceRole):
    with Session(engine) as session:
        m = WorkspaceMembership(user_id=user_id, workspace_id=workspace_id, role=role)
        session.add(m)
        session.commit()


# ---------------------------------------------------------------------------
# Group CRUD
# ---------------------------------------------------------------------------

def test_developer_can_create_and_list_group_in_their_workspace(client, engine):
    ws_a = _make_workspace(engine, "ws-a")
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, WorkspaceRole.DEVELOPER)

    res = client.post("/api/groups", json={"workspace_id": ws_a, "name": "production", "color": "#e11d48"})
    assert res.status_code == 200
    body = res.json()
    assert body["name"] == "production"
    assert body["color"] == "#e11d48"
    assert body["workspace_id"] == ws_a

    list_res = client.get(f"/api/groups?workspace_id={ws_a}")
    assert list_res.status_code == 200
    names = {g["name"] for g in list_res.json()}
    assert "production" in names


def test_developer_cannot_create_group_in_other_workspace(client, engine):
    ws_a = _make_workspace(engine, "ws-a")
    ws_b = _make_workspace(engine, "ws-b")
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, WorkspaceRole.DEVELOPER)  # only in A

    res = client.post("/api/groups", json={"workspace_id": ws_b, "name": "pci-scope"})
    assert res.status_code == 403


def test_viewer_cannot_create_group(client, engine):
    ws_a = _make_workspace(engine, "ws-a")
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, WorkspaceRole.VIEWER)

    res = client.post("/api/groups", json={"workspace_id": ws_a, "name": "internal-tool"})
    assert res.status_code == 403


def test_list_groups_only_returns_callers_workspaces(client, engine):
    """A developer scoped to workspace A should never see workspace B's
    groups, even though both exist in the same DB (issue #57's read-path
    boundary, applied to the new Group resource)."""
    ws_a = _make_workspace(engine, "ws-a")
    ws_b = _make_workspace(engine, "ws-b")
    _make_group(engine, ws_a, "group-a")
    _make_group(engine, ws_b, "group-b")

    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, WorkspaceRole.DEVELOPER)

    res = client.get("/api/groups")
    assert res.status_code == 200
    names = {g["name"] for g in res.json()}
    assert "group-a" in names
    assert "group-b" not in names


def test_user_with_no_membership_sees_no_groups(client, engine):
    ws_a = _make_workspace(engine, "ws-a")
    _make_group(engine, ws_a, "group-a")
    client, _uid = _login(client, engine, role=UserRole.DEVELOPER)  # no membership at all

    res = client.get("/api/groups")
    assert res.status_code == 200
    assert res.json() == []


def test_admin_can_update_and_delete_group(client, engine):
    ws_a = _make_workspace(engine, "ws-a")
    group_id = _make_group(engine, ws_a, "temp")
    client, _uid = _login(client, engine, role=UserRole.ADMIN)

    upd = client.patch(f"/api/groups/{group_id}", json={"name": "renamed", "color": "#00ff00"})
    assert upd.status_code == 200
    assert upd.json()["name"] == "renamed"

    dele = client.delete(f"/api/groups/{group_id}")
    assert dele.status_code == 200

    with Session(engine) as session:
        assert session.get(Group, group_id) is None


def test_developer_cannot_update_group_in_other_workspace(client, engine):
    ws_a = _make_workspace(engine, "ws-a")
    ws_b = _make_workspace(engine, "ws-b")
    group_b = _make_group(engine, ws_b, "group-b")
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, WorkspaceRole.DEVELOPER)

    res = client.patch(f"/api/groups/{group_b}", json={"name": "renamed"})
    assert res.status_code == 403


def test_deleting_group_removes_target_assignments(client, engine):
    ws_a = _make_workspace(engine, "ws-a")
    target_a = _make_target(engine, ws_a)
    group_id = _make_group(engine, ws_a, "production")
    with Session(engine) as session:
        session.add(TargetGroup(target_id=target_a, group_id=group_id))
        session.commit()

    client, _uid = _login(client, engine, role=UserRole.ADMIN)
    res = client.delete(f"/api/groups/{group_id}")
    assert res.status_code == 200

    with Session(engine) as session:
        assert session.exec(select(TargetGroup).where(TargetGroup.group_id == group_id)).first() is None


# ---------------------------------------------------------------------------
# Target <-> Group assignment
# ---------------------------------------------------------------------------

def test_developer_can_assign_and_remove_target_group(client, engine):
    ws_a = _make_workspace(engine, "ws-a")
    target_a = _make_target(engine, ws_a)
    group_a = _make_group(engine, ws_a, "production")
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, WorkspaceRole.DEVELOPER)

    assign_res = client.post(f"/api/targets/{target_a}/groups/{group_a}")
    assert assign_res.status_code == 200
    assert any(g["id"] == group_a for g in assign_res.json())

    get_res = client.get(f"/api/targets/{target_a}/groups")
    assert get_res.status_code == 200
    assert any(g["id"] == group_a for g in get_res.json())

    remove_res = client.delete(f"/api/targets/{target_a}/groups/{group_a}")
    assert remove_res.status_code == 200
    assert remove_res.json() == []


def test_assigning_same_group_twice_is_idempotent(client, engine):
    ws_a = _make_workspace(engine, "ws-a")
    target_a = _make_target(engine, ws_a)
    group_a = _make_group(engine, ws_a, "production")
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, WorkspaceRole.DEVELOPER)

    assert client.post(f"/api/targets/{target_a}/groups/{group_a}").status_code == 200
    assert client.post(f"/api/targets/{target_a}/groups/{group_a}").status_code == 200

    with Session(engine) as session:
        rows = session.exec(
            select(TargetGroup).where(TargetGroup.target_id == target_a, TargetGroup.group_id == group_a)
        ).all()
        assert len(rows) == 1


def test_cannot_assign_group_from_another_workspace_to_target(client, engine):
    ws_a = _make_workspace(engine, "ws-a")
    ws_b = _make_workspace(engine, "ws-b")
    target_a = _make_target(engine, ws_a)
    group_b = _make_group(engine, ws_b, "pci-scope")
    client, _uid = _login(client, engine, role=UserRole.ADMIN)

    res = client.post(f"/api/targets/{target_a}/groups/{group_b}")
    assert res.status_code == 400


def test_developer_cannot_assign_group_to_target_in_other_workspace(client, engine):
    ws_a = _make_workspace(engine, "ws-a")
    ws_b = _make_workspace(engine, "ws-b")
    target_b = _make_target(engine, ws_b)
    group_b = _make_group(engine, ws_b, "production")
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, WorkspaceRole.DEVELOPER)  # only in A

    res = client.post(f"/api/targets/{target_b}/groups/{group_b}")
    assert res.status_code == 403


def test_target_list_includes_group_badges(client, engine):
    ws_a = _make_workspace(engine, "ws-a")
    target_a = _make_target(engine, ws_a)
    group_a = _make_group(engine, ws_a, "production", "#e11d48")
    with Session(engine) as session:
        session.add(TargetGroup(target_id=target_a, group_id=group_a))
        session.commit()

    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, WorkspaceRole.DEVELOPER)

    res = client.get("/api/targets")
    assert res.status_code == 200
    target = next(t for t in res.json() if t["id"] == target_a)
    assert target["groups"] == [{"id": group_a, "name": "production", "color": "#e11d48"}]


# ---------------------------------------------------------------------------
# group_id filtering on GET /api/targets and GET /api/findings
# ---------------------------------------------------------------------------

def test_targets_filtered_by_group_id(client, engine):
    ws_a = _make_workspace(engine, "ws-a")
    target_tagged = _make_target(engine, ws_a, "tagged")
    target_untagged = _make_target(engine, ws_a, "untagged")
    group_a = _make_group(engine, ws_a, "production")
    with Session(engine) as session:
        session.add(TargetGroup(target_id=target_tagged, group_id=group_a))
        session.commit()

    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, WorkspaceRole.DEVELOPER)

    res = client.get(f"/api/targets?group_id={group_a}")
    assert res.status_code == 200
    ids = {t["id"] for t in res.json()}
    assert ids == {target_tagged}
    assert target_untagged not in ids


def test_findings_filtered_by_group_id(client, engine):
    ws_a = _make_workspace(engine, "ws-a")
    target_tagged = _make_target(engine, ws_a, "tagged")
    target_untagged = _make_target(engine, ws_a, "untagged")
    group_a = _make_group(engine, ws_a, "production")
    with Session(engine) as session:
        session.add(TargetGroup(target_id=target_tagged, group_id=group_a))
        session.commit()
    finding_tagged = _make_finding(engine, target_tagged, "h-tagged")
    finding_untagged = _make_finding(engine, target_untagged, "h-untagged")

    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, WorkspaceRole.DEVELOPER)

    res = client.get(f"/api/findings?group_id={group_a}")
    assert res.status_code == 200
    body = res.json()
    ids = {f["id"] for f in body["items"]}
    assert finding_tagged in ids
    assert finding_untagged not in ids


def test_findings_group_filter_respects_workspace_boundary(client, engine):
    """A group in a workspace the caller can't see should filter to nothing,
    not silently ignore the scoping and leak another workspace's findings."""
    ws_a = _make_workspace(engine, "ws-a")
    ws_b = _make_workspace(engine, "ws-b")
    target_b = _make_target(engine, ws_b, "target-b")
    group_b = _make_group(engine, ws_b, "internal-tool")
    with Session(engine) as session:
        session.add(TargetGroup(target_id=target_b, group_id=group_b))
        session.commit()
    _make_finding(engine, target_b, "h1")

    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, WorkspaceRole.DEVELOPER)  # only in A, not B

    res = client.get(f"/api/findings?group_id={group_b}")
    assert res.status_code == 200
    assert res.json()["items"] == []
