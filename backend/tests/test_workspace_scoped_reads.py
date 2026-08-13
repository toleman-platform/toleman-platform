"""Tests for issue #57: GET/list routes on findings and targets (plus the
dashboard aggregates) never filtered by workspace, so any authenticated user
-- including a viewer with no WorkspaceMembership at all -- could list or
view every workspace's findings and targets. #32 already gated the write
paths; this covers the read-path counterpart added by
app.api.auth.accessible_workspace_ids.

Follows the same in-memory SQLite + TestClient + session-token-login pattern
used in tests/test_workspace_roles.py.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    Finding,
    FindingState,
    Organization,
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


def _login(client, engine, role=UserRole.USER, email=None):
    email = email or f"{role.value}-{id(object())}@example.com"
    with Session(engine) as session:
        user = User(email=email, name="Test", password_hash=hash_password("whatever123"), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        uid = user.id
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("osp_session", token)
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


def _make_finding(engine, target_id: int, **overrides) -> int:
    defaults = dict(
        target_id=target_id,
        dedup_hash=f"hash-{target_id}-{overrides.get('rule_id', 'r')}",
        tool="semgrep",
        rule_id="rule-1",
        title="Finding",
        file_path="app/main.py",
        severity=Severity.HIGH,
        state=FindingState.OPEN,
    )
    defaults.update(overrides)
    with Session(engine) as session:
        finding = Finding(**defaults)
        session.add(finding)
        session.commit()
        session.refresh(finding)
        return finding.id


def _assign(engine, user_id: int, workspace_id: int, role: WorkspaceRole = WorkspaceRole.VIEWER):
    with Session(engine) as session:
        m = WorkspaceMembership(user_id=user_id, workspace_id=workspace_id, role=role)
        session.add(m)
        session.commit()


# ---------------------------------------------------------------------------
# Fixture shape used across most tests: two real workspaces, each with a
# target and a finding, and a user with membership in only workspace A.
# ---------------------------------------------------------------------------

def _two_workspace_setup(engine):
    ws_a = _make_workspace(engine, "ws-a")
    ws_b = _make_workspace(engine, "ws-b")
    target_a = _make_target(engine, ws_a, "target-a")
    target_b = _make_target(engine, ws_b, "target-b")
    finding_a = _make_finding(engine, target_a, rule_id="r-a")
    finding_b = _make_finding(engine, target_b, rule_id="r-b")
    return ws_a, ws_b, target_a, target_b, finding_a, finding_b


def test_list_targets_only_returns_callers_workspace(client, engine):
    ws_a, ws_b, target_a, target_b, _fa, _fb = _two_workspace_setup(engine)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get("/api/targets")
    assert res.status_code == 200
    ids = {t["id"] for t in res.json()}
    assert ids == {target_a}


def test_list_findings_only_returns_callers_workspace(client, engine):
    ws_a, ws_b, target_a, target_b, finding_a, finding_b = _two_workspace_setup(engine)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get("/api/findings")
    assert res.status_code == 200
    body = res.json()
    ids = {f["id"] for f in body["items"]}
    assert ids == {finding_a}
    assert body["total"] == 1


def test_get_target_in_other_workspace_returns_404(client, engine):
    ws_a, ws_b, target_a, target_b, _fa, _fb = _two_workspace_setup(engine)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get(f"/api/targets/{target_b}")
    assert res.status_code == 404

    own = client.get(f"/api/targets/{target_a}")
    assert own.status_code == 200


def test_get_finding_in_other_workspace_returns_404(client, engine):
    ws_a, ws_b, target_a, target_b, finding_a, finding_b = _two_workspace_setup(engine)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get(f"/api/findings/{finding_b}")
    assert res.status_code == 404

    own = client.get(f"/api/findings/{finding_a}")
    assert own.status_code == 200


def test_get_workspace_key_in_other_workspace_returns_404(client, engine):
    """The workspace-key endpoint leaks a secret (api_key), not just data --
    same scoping applies."""
    ws_a, ws_b, target_a, target_b, _fa, _fb = _two_workspace_setup(engine)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get(f"/api/targets/{target_b}/workspace-key")
    assert res.status_code == 404


def test_admin_sees_all_targets_and_findings(client, engine):
    ws_a, ws_b, target_a, target_b, finding_a, finding_b = _two_workspace_setup(engine)
    client, _uid = _login(client, engine, role=UserRole.ADMIN)  # no WorkspaceMembership row at all

    targets_res = client.get("/api/targets")
    assert targets_res.status_code == 200
    assert {t["id"] for t in targets_res.json()} == {target_a, target_b}

    findings_res = client.get("/api/findings")
    assert findings_res.status_code == 200
    assert {f["id"] for f in findings_res.json()["items"]} == {finding_a, finding_b}

    assert client.get(f"/api/targets/{target_b}").status_code == 200
    assert client.get(f"/api/findings/{finding_b}").status_code == 200


def test_user_with_no_membership_sees_empty_lists_not_error(client, engine):
    _two_workspace_setup(engine)
    client, _uid = _login(client, engine, role=UserRole.VIEWER)  # zero WorkspaceMembership rows

    targets_res = client.get("/api/targets")
    assert targets_res.status_code == 200
    assert targets_res.json() == []

    findings_res = client.get("/api/findings")
    assert findings_res.status_code == 200
    body = findings_res.json()
    assert body["items"] == []
    assert body["total"] == 0


def test_dashboard_summary_scoped_to_caller_workspace(client, engine):
    ws_a, ws_b, target_a, target_b, finding_a, finding_b = _two_workspace_setup(engine)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get("/api/dashboard/summary")
    assert res.status_code == 200
    assert res.json()["total"] == 1  # only finding_a, not finding_b


def test_dashboard_summary_empty_for_user_with_no_membership(client, engine):
    _two_workspace_setup(engine)
    client, _uid = _login(client, engine, role=UserRole.VIEWER)

    res = client.get("/api/dashboard/summary")
    assert res.status_code == 200
    assert res.json() == {"total": 0, "open": 0, "mitigated": 0}


def test_dashboard_posture_scoped_to_caller_workspace(client, engine):
    ws_a, ws_b, target_a, target_b, _fa, _fb = _two_workspace_setup(engine)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get("/api/dashboard/posture")
    assert res.status_code == 200
    target_ids = {row["target"]["id"] for row in res.json()}
    assert target_ids == {target_a}
