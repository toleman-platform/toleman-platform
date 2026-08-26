"""Tests for GET /api/targets/summary (issue #174): the per-target
open-finding counts the Repo Sync inventory renders alongside each repo.

The point of the endpoint is that its numbers cannot disagree with the
Posture dashboard or the composite security score, so these tests pin the
two scoping rules that could drift (default-branch-only and open-state-only)
plus the workspace isolation every list endpoint over workspace-owned
resources has to honour (issue #57).

Same in-memory SQLite + TestClient + session-token-login pattern as
tests/test_groups.py.
"""
import itertools

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

_emails = itertools.count()


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
            email=f"user-{next(_emails)}@example.com",
            name="Test",
            password_hash=hash_password("whatever123"),
            role=role,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        uid = user.id
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return uid


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


def _make_target(engine, workspace_id: int, name="target", default_branch="main") -> int:
    with Session(engine) as session:
        target = Target(
            workspace_id=workspace_id,
            name=name,
            repo_url="https://github.com/acme/repo",
            default_branch=default_branch,
        )
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


def _make_finding(
    engine,
    target_id: int,
    dedup_hash: str,
    severity=Severity.HIGH,
    state=FindingState.OPEN,
    branch="main",
):
    with Session(engine) as session:
        session.add(
            Finding(
                target_id=target_id,
                dedup_hash=dedup_hash,
                tool="semgrep",
                rule_id="r1",
                title="t1",
                file_path="a.py",
                severity=severity,
                state=state,
                branch=branch,
            )
        )
        session.commit()


def test_counts_open_findings_by_severity(client, engine):
    _login(client, engine)
    ws = _make_workspace(engine)
    target_id = _make_target(engine, ws)
    _make_finding(engine, target_id, "h1", severity=Severity.CRITICAL)
    _make_finding(engine, target_id, "h2", severity=Severity.HIGH)
    _make_finding(engine, target_id, "h3", severity=Severity.LOW)

    body = client.get("/api/targets/summary").json()
    assert body[str(target_id)] == {
        "open": 3,
        "critical": 1,
        "high": 1,
        "medium": 0,
        "low": 1,
        "informational": 0,
    }


def test_reopened_counts_as_open_but_closed_states_do_not(client, engine):
    """Mirrors app.core.security_score.OPEN_STATES; if these two drift, the
    Repo Sync count and the security score start contradicting each other."""
    _login(client, engine)
    ws = _make_workspace(engine)
    target_id = _make_target(engine, ws)
    _make_finding(engine, target_id, "h1", state=FindingState.OPEN)
    _make_finding(engine, target_id, "h2", state=FindingState.REOPENED)
    _make_finding(engine, target_id, "h3", state=FindingState.MITIGATED)
    _make_finding(engine, target_id, "h4", state=FindingState.FALSE_POSITIVE)

    body = client.get("/api/targets/summary").json()
    assert body[str(target_id)]["open"] == 2


def test_only_default_branch_findings_are_counted(client, engine):
    _login(client, engine)
    ws = _make_workspace(engine)
    target_id = _make_target(engine, ws, default_branch="main")
    _make_finding(engine, target_id, "h1", branch="main")
    _make_finding(engine, target_id, "h2", branch="feature/x")

    body = client.get("/api/targets/summary").json()
    assert body[str(target_id)]["open"] == 1


def test_target_with_no_findings_reports_zero_not_missing(client, engine):
    """The client distinguishes "scanned and clean" from "no data"; a target
    present with a zero count is the former, an absent key is the latter."""
    _login(client, engine)
    ws = _make_workspace(engine)
    target_id = _make_target(engine, ws)

    body = client.get("/api/targets/summary").json()
    assert body[str(target_id)] == {
        "open": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }


def test_scoped_to_accessible_workspaces(client, engine):
    """Issue #57: a non-admin sees only workspaces they're a member of."""
    uid = _login(client, engine, role=UserRole.USER)
    mine = _make_workspace(engine, "mine")
    theirs = _make_workspace(engine, "theirs")
    with Session(engine) as session:
        session.add(WorkspaceMembership(workspace_id=mine, user_id=uid, role=WorkspaceRole.DEVELOPER))
        session.commit()

    my_target = _make_target(engine, mine, name="mine")
    their_target = _make_target(engine, theirs, name="theirs")
    _make_finding(engine, my_target, "h1")
    _make_finding(engine, their_target, "h2")

    body = client.get("/api/targets/summary").json()
    assert str(my_target) in body
    assert str(their_target) not in body


def test_summary_path_is_not_parsed_as_a_target_id(client, engine):
    """/summary is declared before /{target_id}; if that order regresses this
    request 422s trying to parse "summary" as an int."""
    _login(client, engine)
    resp = client.get("/api/targets/summary")
    assert resp.status_code == 200
