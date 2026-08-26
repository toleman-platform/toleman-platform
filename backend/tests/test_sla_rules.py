"""Tests for issue #70 (SLA configuration): the
group -> workspace-default -> "no SLA" resolution
(app.core.sla.resolve_sla_days / compute_sla_status), the SlaRule CRUD
endpoints (SECURITY_ENGINEER-or-admin gated), and the extra sla_days/
sla_violated fields on the findings endpoints + GET /api/dashboard/sla-compliance.

Follows the same in-memory SQLite + TestClient + session-token-login pattern
used across tests/test_enforcement_mode.py and tests/test_groups.py.
"""
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.sla import compute_sla_status, resolve_sla_days, resolve_sla_days_with_source
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    Finding,
    FindingState,
    Group,
    Organization,
    Severity,
    SlaRule,
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


def _make_target(engine, workspace_id) -> int:
    with Session(engine) as session:
        t = Target(workspace_id=workspace_id, name="repo", repo_url="https://github.com/acme/repo")
        session.add(t)
        session.commit()
        session.refresh(t)
        return t.id


def _make_group(engine, workspace_id, name="g") -> int:
    with Session(engine) as session:
        g = Group(workspace_id=workspace_id, name=name)
        session.add(g)
        session.commit()
        session.refresh(g)
        return g.id


def _assign_group(engine, target_id, group_id):
    with Session(engine) as session:
        session.add(TargetGroup(target_id=target_id, group_id=group_id))
        session.commit()


def _make_rule(engine, workspace_id, group_id, severity, days_to_fix) -> int:
    with Session(engine) as session:
        r = SlaRule(workspace_id=workspace_id, group_id=group_id, severity=severity, days_to_fix=days_to_fix)
        session.add(r)
        session.commit()
        session.refresh(r)
        return r.id


def _make_finding(engine, target_id, severity=Severity.CRITICAL, first_seen=None, state=FindingState.OPEN) -> int:
    with Session(engine) as session:
        f = Finding(
            target_id=target_id,
            dedup_hash=f"hash-{id(object())}",
            tool="semgrep",
            rule_id="r1",
            title="t1",
            file_path="a.py",
            severity=severity,
            state=state,
            first_seen=first_seen or datetime.utcnow(),
        )
        session.add(f)
        session.commit()
        session.refresh(f)
        return f.id


def _membership(engine, user_id, workspace_id, role):
    with Session(engine) as session:
        session.add(WorkspaceMembership(user_id=user_id, workspace_id=workspace_id, role=role))
        session.commit()


# ---------------------------------------------------------------------------
# Resolver unit tests
# ---------------------------------------------------------------------------

def test_no_rule_means_no_sla(engine):
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    finding_id = _make_finding(engine, target_id)
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)
        assert resolve_sla_days(session, finding) is None
        days, violated = compute_sla_status(session, finding)
        assert days is None
        assert violated is False


def test_workspace_default_used_when_no_group_rule(engine):
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _make_rule(engine, ws_id, None, Severity.CRITICAL, 7)
    finding_id = _make_finding(engine, target_id, severity=Severity.CRITICAL)
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)
        days, source = resolve_sla_days_with_source(session, finding)
        assert days == 7
        assert source == "workspace_default"


def test_group_rule_wins_over_workspace_default(engine):
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    group_id = _make_group(engine, ws_id, name="production")
    _assign_group(engine, target_id, group_id)
    _make_rule(engine, ws_id, None, Severity.CRITICAL, 30)  # lenient workspace default
    _make_rule(engine, ws_id, group_id, Severity.CRITICAL, 7)  # stricter group rule
    finding_id = _make_finding(engine, target_id, severity=Severity.CRITICAL)
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)
        days, source = resolve_sla_days_with_source(session, finding)
        assert days == 7
        assert source == "group"


def test_severity_specific_rules_are_independent(engine):
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    group_id = _make_group(engine, ws_id, name="dev")
    _assign_group(engine, target_id, group_id)
    _make_rule(engine, ws_id, group_id, Severity.CRITICAL, 7)
    _make_rule(engine, ws_id, group_id, Severity.MEDIUM, 30)
    critical_id = _make_finding(engine, target_id, severity=Severity.CRITICAL)
    medium_id = _make_finding(engine, target_id, severity=Severity.MEDIUM)
    low_id = _make_finding(engine, target_id, severity=Severity.LOW)
    with Session(engine) as session:
        assert resolve_sla_days(session, session.get(Finding, critical_id)) == 7
        assert resolve_sla_days(session, session.get(Finding, medium_id)) == 30
        assert resolve_sla_days(session, session.get(Finding, low_id)) is None  # no rule for Low


def test_conflicting_multi_group_resolves_most_restrictive(engine):
    """A target in two groups with different Critical SLAs must resolve to
    the fewest days; most-restrictive-wins, same fail-closed philosophy as
    #62's conflicting-groups enforcement_mode resolution."""
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    lenient_group = _make_group(engine, ws_id, name="lenient")
    strict_group = _make_group(engine, ws_id, name="strict")
    _assign_group(engine, target_id, lenient_group)
    _assign_group(engine, target_id, strict_group)
    _make_rule(engine, ws_id, lenient_group, Severity.CRITICAL, 30)
    _make_rule(engine, ws_id, strict_group, Severity.CRITICAL, 3)
    finding_id = _make_finding(engine, target_id, severity=Severity.CRITICAL)
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)
        assert resolve_sla_days(session, finding) == 3


def test_violation_computed_against_real_first_seen(engine):
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _make_rule(engine, ws_id, None, Severity.HIGH, 5)

    old_finding_id = _make_finding(
        engine, target_id, severity=Severity.HIGH, first_seen=datetime.utcnow() - timedelta(days=10)
    )
    recent_finding_id = _make_finding(
        engine, target_id, severity=Severity.HIGH, first_seen=datetime.utcnow() - timedelta(days=1)
    )
    with Session(engine) as session:
        old_finding = session.get(Finding, old_finding_id)
        recent_finding = session.get(Finding, recent_finding_id)
        days, violated = compute_sla_status(session, old_finding)
        assert days == 5
        assert violated is True
        days, violated = compute_sla_status(session, recent_finding)
        assert days == 5
        assert violated is False


def test_closed_finding_never_in_violation(engine):
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _make_rule(engine, ws_id, None, Severity.CRITICAL, 1)
    finding_id = _make_finding(
        engine,
        target_id,
        severity=Severity.CRITICAL,
        first_seen=datetime.utcnow() - timedelta(days=100),
        state=FindingState.MITIGATED,
    )
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)
        days, violated = compute_sla_status(session, finding)
        assert days == 1  # a rule does apply
        assert violated is False  # but it's resolved, so not "in violation"


def test_reopened_finding_still_counts_as_open(engine):
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _make_rule(engine, ws_id, None, Severity.CRITICAL, 1)
    finding_id = _make_finding(
        engine,
        target_id,
        severity=Severity.CRITICAL,
        first_seen=datetime.utcnow() - timedelta(days=100),
        state=FindingState.REOPENED,
    )
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)
        days, violated = compute_sla_status(session, finding)
        assert violated is True


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------

def test_create_sla_rule_requires_security_engineer(client, engine):
    client, uid = _login(client, engine)
    ws_id = _make_workspace(engine)
    _membership(engine, uid, ws_id, WorkspaceRole.DEVELOPER)

    res = client.post(
        "/api/sla-rules",
        json={"workspace_id": ws_id, "group_id": None, "severity": "Critical", "days_to_fix": 7},
    )
    assert res.status_code == 403


def test_create_sla_rule_as_security_engineer(client, engine):
    client, uid = _login(client, engine)
    ws_id = _make_workspace(engine)
    _membership(engine, uid, ws_id, WorkspaceRole.SECURITY_ENGINEER)

    res = client.post(
        "/api/sla-rules",
        json={"workspace_id": ws_id, "group_id": None, "severity": "Critical", "days_to_fix": 7},
    )
    assert res.status_code == 200, res.text
    assert res.json()["days_to_fix"] == 7
    assert res.json()["group_id"] is None


def test_duplicate_sla_rule_rejected(client, engine):
    client, uid = _login(client, engine)
    ws_id = _make_workspace(engine)
    _membership(engine, uid, ws_id, WorkspaceRole.SECURITY_ENGINEER)
    _make_rule(engine, ws_id, None, Severity.CRITICAL, 7)

    res = client.post(
        "/api/sla-rules",
        json={"workspace_id": ws_id, "group_id": None, "severity": "Critical", "days_to_fix": 3},
    )
    assert res.status_code == 409


def test_admin_can_create_sla_rule_without_membership(client, engine):
    client, uid = _login(client, engine, role=UserRole.ADMIN)
    ws_id = _make_workspace(engine)

    res = client.post(
        "/api/sla-rules",
        json={"workspace_id": ws_id, "group_id": None, "severity": "Low", "days_to_fix": 90},
    )
    assert res.status_code == 200, res.text


def test_findings_endpoint_reports_sla_fields(client, engine):
    client, uid = _login(client, engine, role=UserRole.ADMIN)
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _make_rule(engine, ws_id, None, Severity.CRITICAL, 1)
    finding_id = _make_finding(
        engine, target_id, severity=Severity.CRITICAL, first_seen=datetime.utcnow() - timedelta(days=5)
    )

    res = client.get(f"/api/findings/{finding_id}")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["sla_days"] == 1
    assert body["sla_violated"] is True

    list_res = client.get(f"/api/findings?target_id={target_id}")
    assert list_res.status_code == 200
    items = list_res.json()["items"]
    assert len(items) == 1
    assert items[0]["sla_days"] == 1
    assert items[0]["sla_violated"] is True


def test_findings_endpoint_no_sla_fields_when_no_rule(client, engine):
    client, uid = _login(client, engine, role=UserRole.ADMIN)
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    finding_id = _make_finding(engine, target_id, severity=Severity.LOW)

    res = client.get(f"/api/findings/{finding_id}")
    assert res.status_code == 200
    body = res.json()
    assert body["sla_days"] is None
    assert body["sla_violated"] is False


def test_dashboard_sla_compliance(client, engine):
    client, uid = _login(client, engine, role=UserRole.ADMIN)
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _make_rule(engine, ws_id, None, Severity.CRITICAL, 1)
    _make_rule(engine, ws_id, None, Severity.LOW, 90)

    _make_finding(engine, target_id, severity=Severity.CRITICAL, first_seen=datetime.utcnow() - timedelta(days=5))  # violated
    _make_finding(engine, target_id, severity=Severity.LOW, first_seen=datetime.utcnow() - timedelta(days=5))  # compliant
    _make_finding(engine, target_id, severity=Severity.MEDIUM, first_seen=datetime.utcnow() - timedelta(days=5))  # no rule, excluded

    res = client.get("/api/dashboard/sla-compliance")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["with_sla"] == 2
    assert body["in_violation"] == 1
    assert body["compliant"] == 1
