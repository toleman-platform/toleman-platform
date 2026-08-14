"""Tests for issue #64: GET /api/pr-guardrail/log with no target_id returns
an org-wide aggregate of PR Guardrail scan history, scoped to the caller's
accessible workspaces via accessible_workspace_ids (#57) -- not every
workspace's scans. Mirrors the pattern in test_workspace_scoped_reads.py.
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
    Organization,
    PRGuardrailScan,
    PRGuardrailStatus,
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


def _make_scan(engine, target_id: int, pr_number: int, status: PRGuardrailStatus) -> int:
    with Session(engine) as session:
        scan = PRGuardrailScan(target_id=target_id, pr_number=pr_number, pr_title=f"pr {pr_number}", branch="feature", status=status)
        session.add(scan)
        session.commit()
        session.refresh(scan)
        return scan.id


def _assign(engine, user_id: int, workspace_id: int, role: WorkspaceRole = WorkspaceRole.VIEWER):
    with Session(engine) as session:
        m = WorkspaceMembership(user_id=user_id, workspace_id=workspace_id, role=role)
        session.add(m)
        session.commit()


def _two_workspace_setup(engine):
    ws_a = _make_workspace(engine, "ws-a")
    ws_b = _make_workspace(engine, "ws-b")
    target_a = _make_target(engine, ws_a, "target-a")
    target_b = _make_target(engine, ws_b, "target-b")
    scan_a = _make_scan(engine, target_a, 1, PRGuardrailStatus.PASSED)
    scan_b = _make_scan(engine, target_b, 2, PRGuardrailStatus.BLOCKED)
    return ws_a, ws_b, target_a, target_b, scan_a, scan_b


def test_org_log_only_returns_callers_workspace_scans(client, engine):
    ws_a, ws_b, target_a, target_b, scan_a, scan_b = _two_workspace_setup(engine)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get("/api/pr-guardrail/log")
    assert res.status_code == 200
    body = res.json()
    ids = {s["id"] for s in body["scans"]}
    assert ids == {scan_a}
    assert body["stats"]["total"] == 1
    assert body["stats"]["passed"] == 1
    assert body["stats"]["blocked"] == 0
    # each row should carry which target it belongs to
    assert body["scans"][0]["target_id"] == target_a
    assert body["scans"][0]["target_name"] == "target-a"
    # issue #65: each row also carries a direct link back to the GitHub PR,
    # built from the target's repo_url ("https://github.com/acme/repo") +
    # pr_number (1)
    assert body["scans"][0]["pr_url"] == "https://github.com/acme/repo/pull/1"


def test_org_log_pr_url_none_when_repo_url_unparseable(client, engine):
    """A target with an empty repo_url shouldn't crash the endpoint -- pr_url
    just comes back None for that row (issue #65)."""
    ws_a = _make_workspace(engine, "ws-no-url")
    with Session(engine) as session:
        target = Target(workspace_id=ws_a, name="no-url-target", repo_url="")
        session.add(target)
        session.commit()
        session.refresh(target)
        target_id = target.id
    scan_id = _make_scan(engine, target_id, 9, PRGuardrailStatus.PASSED)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get("/api/pr-guardrail/log")
    assert res.status_code == 200
    body = res.json()
    row = next(s for s in body["scans"] if s["id"] == scan_id)
    assert row["pr_url"] is None


def test_org_log_admin_sees_all_workspaces_scans(client, engine):
    ws_a, ws_b, target_a, target_b, scan_a, scan_b = _two_workspace_setup(engine)
    client, _uid = _login(client, engine, role=UserRole.ADMIN)  # no WorkspaceMembership row at all

    res = client.get("/api/pr-guardrail/log")
    assert res.status_code == 200
    body = res.json()
    ids = {s["id"] for s in body["scans"]}
    assert ids == {scan_a, scan_b}
    assert body["stats"]["total"] == 2
    assert body["stats"]["passed"] == 1
    assert body["stats"]["blocked"] == 1


def test_org_log_user_with_no_membership_sees_empty(client, engine):
    _two_workspace_setup(engine)
    client, _uid = _login(client, engine, role=UserRole.VIEWER)  # zero WorkspaceMembership rows

    res = client.get("/api/pr-guardrail/log")
    assert res.status_code == 200
    body = res.json()
    assert body["scans"] == []
    assert body["stats"]["total"] == 0


def test_org_log_most_recent_first(client, engine):
    ws_a = _make_workspace(engine, "ws-recent")
    target_a = _make_target(engine, ws_a, "target-recent")
    scan_1 = _make_scan(engine, target_a, 1, PRGuardrailStatus.PASSED)
    scan_2 = _make_scan(engine, target_a, 2, PRGuardrailStatus.BLOCKED)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get("/api/pr-guardrail/log")
    assert res.status_code == 200
    scan_ids_in_order = [s["id"] for s in res.json()["scans"]]
    assert scan_ids_in_order[0] == scan_2
    assert scan_ids_in_order[1] == scan_1


def test_single_target_log_unaffected_by_org_wide_change(client, engine):
    """Regression check: passing target_id still returns the pre-#64 flat
    list shape (a plain array, not {scans, stats}), unscoped by workspace
    membership (single-target mode never claimed to enforce that)."""
    ws_a, ws_b, target_a, target_b, scan_a, scan_b = _two_workspace_setup(engine)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get(f"/api/pr-guardrail/log?target_id={target_a}")
    assert res.status_code == 200
    body = res.json()
    assert isinstance(body, list)
    assert {s["id"] for s in body} == {scan_a}
    assert "target_name" not in body[0]
    # issue #65: pr_url is still present/correct in single-target mode, it's
    # not an org-wide-only addition
    assert body[0]["pr_url"] == "https://github.com/acme/repo/pull/1"
