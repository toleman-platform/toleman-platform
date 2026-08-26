"""Tests for issue #63 (single-number security health score):
app.core.security_score.compute_security_score's component formulas and the
GET /api/dashboard/security-score endpoint's org/group/target scoping.

Follows the same in-memory SQLite + TestClient + session-token-login pattern
used in tests/test_sla_rules.py.
"""
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.core.security_score import compute_security_score
from app.main import app
from app.models.models import (
    Finding,
    FindingState,
    FindingStateLog,
    Group,
    Organization,
    Scan,
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


def _make_target(engine, workspace_id, default_branch="main") -> int:
    with Session(engine) as session:
        t = Target(workspace_id=workspace_id, name="repo", repo_url="https://github.com/acme/repo", default_branch=default_branch)
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


def _make_finding(
    engine,
    target_id,
    severity=Severity.CRITICAL,
    first_seen=None,
    state=FindingState.OPEN,
    branch="main",
) -> int:
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
            branch=branch,
            first_seen=first_seen or datetime.utcnow(),
        )
        session.add(f)
        session.commit()
        session.refresh(f)
        return f.id


def _make_scan(engine, target_id, started_at=None) -> int:
    with Session(engine) as session:
        s = Scan(target_id=target_id, tool="semgrep", branch="main", status="completed", started_at=started_at or datetime.utcnow())
        session.add(s)
        session.commit()
        session.refresh(s)
        return s.id


def _log_transition(engine, finding_id, from_state, to_state, created_at):
    with Session(engine) as session:
        session.add(
            FindingStateLog(finding_id=finding_id, from_state=from_state, to_state=to_state, reason="test", created_at=created_at)
        )
        session.commit()


def _membership(engine, user_id, workspace_id, role):
    with Session(engine) as session:
        session.add(WorkspaceMembership(user_id=user_id, workspace_id=workspace_id, role=role))
        session.commit()


# ---------------------------------------------------------------------------
# compute_security_score unit tests (hand-calculated expectations)
# ---------------------------------------------------------------------------

def test_no_targets_yields_zero_score(engine):
    with Session(engine) as session:
        result = compute_security_score(session, [])
    assert result["score"] == 0.0
    assert result["grade"] is None
    assert result["target_count"] == 0


def test_clean_target_no_findings_scores_high(engine):
    """No findings, one recent scan, no SLA rules configured anywhere ->
    findings=100 (no open findings), sla=100 (neutral, none tracked),
    coverage=100 (scanned within window), fp_rate=100 (no findings ever),
    trend=100 (0 == 0, stable). Composite must be a perfect 100, grade A."""
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _make_scan(engine, target_id)

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    assert result["score"] == 100.0
    assert result["grade"] == "A"
    c = result["components"]
    assert c["findings"]["score"] == 100.0
    assert c["sla"]["score"] == 100.0
    assert c["coverage"]["score"] == 100.0
    assert c["fp_rate"]["score"] == 100.0
    assert c["trend"]["score"] == 100.0


def test_findings_component_hand_calculated(engine):
    """One target, one open Critical (weight 5) + one open High (weight 4)
    default-branch finding -> weighted_sum=9, target_count=1,
    avg_per_target=9. score = 100 - (9/20)*100 = 55.0 exactly."""
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _make_finding(engine, target_id, severity=Severity.CRITICAL)
    _make_finding(engine, target_id, severity=Severity.HIGH)

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    f = result["components"]["findings"]
    assert f["weighted_severity_sum"] == 9
    assert f["open_findings"] == 2
    assert f["score"] == 55.0


def test_findings_component_ignores_non_default_branch(engine):
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id, default_branch="main")
    _make_finding(engine, target_id, severity=Severity.CRITICAL, branch="feature/x")

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    assert result["components"]["findings"]["open_findings"] == 0
    assert result["components"]["findings"]["score"] == 100.0


def test_sla_component_hand_calculated(engine):
    """2 Critical open findings with a 1-day SLA rule, one first_seen 5 days
    ago (violated) and one first_seen today (compliant) -> with_sla=2,
    in_violation=1 -> score = 100 * (2-1)/2 = 50.0."""
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _make_rule(engine, ws_id, None, Severity.CRITICAL, 1)
    _make_finding(engine, target_id, severity=Severity.CRITICAL, first_seen=datetime.utcnow() - timedelta(days=5))
    _make_finding(engine, target_id, severity=Severity.CRITICAL, first_seen=datetime.utcnow())

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    sla = result["components"]["sla"]
    assert sla["with_sla"] == 2
    assert sla["in_violation"] == 1
    assert sla["score"] == 50.0


def test_coverage_component_hand_calculated(engine):
    """2 targets in scope, only 1 has a recent Scan -> coverage = 50.0."""
    ws_id = _make_workspace(engine)
    scanned_target = _make_target(engine, ws_id)
    unscanned_target = _make_target(engine, ws_id)
    _make_scan(engine, scanned_target)

    with Session(engine) as session:
        result = compute_security_score(session, [scanned_target, unscanned_target])

    cov = result["components"]["coverage"]
    assert cov["scanned_targets"] == 1
    assert cov["total_targets"] == 2
    assert cov["score"] == 50.0


def test_coverage_component_ignores_stale_scan(engine):
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _make_scan(engine, target_id, started_at=datetime.utcnow() - timedelta(days=60))

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    assert result["components"]["coverage"]["score"] == 0.0


def test_fp_rate_component_hand_calculated(engine):
    """4 findings ever, 1 currently False Positive -> fp_rate=0.25,
    score = 100*(1-0.25) = 75.0."""
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _make_finding(engine, target_id, state=FindingState.OPEN)
    _make_finding(engine, target_id, state=FindingState.OPEN)
    _make_finding(engine, target_id, state=FindingState.MITIGATED)
    _make_finding(engine, target_id, state=FindingState.FALSE_POSITIVE)

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    fp = result["components"]["fp_rate"]
    assert fp["total_findings"] == 4
    assert fp["false_positives"] == 1
    assert fp["score"] == 75.0


def test_trend_component_worsening_from_new_finding(engine):
    """A finding first_seen 2 days ago (inside the 7-day trend window) means
    it did NOT exist 7 days ago (prior_sum contribution 0) but IS open now
    (current_sum includes its weight). prior=0, current=5 (Critical) ->
    pct_increase = 5/max(0,1) = 5.0 -> score = max(0, 100-500) = 0,
    direction 'worsening'."""
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _make_finding(engine, target_id, severity=Severity.CRITICAL, first_seen=datetime.utcnow() - timedelta(days=2))

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    trend = result["components"]["trend"]
    assert trend["prior_weighted_sum"] == 0.0
    assert trend["current_weighted_sum"] == 5.0
    assert trend["direction"] == "worsening"
    assert trend["score"] == 0.0


def test_trend_component_improving_after_mitigation(engine):
    """A Critical finding existed 10 days ago and was mitigated 3 days ago
    (before the 7-day-ago snapshot... wait, mitigated 3 days ago means it
    WAS still open 7 days ago). Use a mitigation 10 days ago instead so it's
    closed by both the 7-day-ago snapshot and now -> prior=0, current=0,
    stable, not improving. To get a genuine 'improving' case: finding
    existed 10 days ago (open at day -7), mitigated 3 days ago (closed by
    now) -> prior_sum=5 (open 7 days ago), current_sum=0 (closed now) ->
    improving, score 100."""
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    finding_id = _make_finding(
        engine, target_id, severity=Severity.CRITICAL, first_seen=datetime.utcnow() - timedelta(days=10), state=FindingState.MITIGATED
    )
    _log_transition(
        engine, finding_id, "Open", "Mitigated", created_at=datetime.utcnow() - timedelta(days=3)
    )

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    trend = result["components"]["trend"]
    assert trend["prior_weighted_sum"] == 5.0
    assert trend["current_weighted_sum"] == 0.0
    assert trend["direction"] == "improving"
    assert trend["score"] == 100.0


def test_weakest_component_reported(engine):
    """Zero SLA rules (sla=100), zero scans (coverage=0) -> coverage should
    be reported as the weakest component alongside findings if findings
    also drop, but with no findings at all, coverage (0) is strictly the
    minimum."""
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    assert result["weakest_component"] == "coverage"


# ---------------------------------------------------------------------------
# API endpoint tests: org/group/target scoping + workspace isolation
# ---------------------------------------------------------------------------

def test_endpoint_org_wide(client, engine):
    client, uid = _login(client, engine, role=UserRole.ADMIN)
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _make_scan(engine, target_id)

    res = client.get("/api/dashboard/security-score")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["target_count"] == 1
    assert body["score"] == 100.0
    assert body["grade"] == "A"


def test_endpoint_target_scope(client, engine):
    client, uid = _login(client, engine, role=UserRole.ADMIN)
    ws_id = _make_workspace(engine)
    healthy = _make_target(engine, ws_id)
    unhealthy = _make_target(engine, ws_id)
    _make_scan(engine, healthy)
    _make_finding(engine, unhealthy, severity=Severity.CRITICAL)

    res = client.get(f"/api/dashboard/security-score?target_id={unhealthy}")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["target_count"] == 1
    assert body["components"]["findings"]["open_findings"] == 1


def test_endpoint_group_scope(client, engine):
    client, uid = _login(client, engine, role=UserRole.ADMIN)
    ws_id = _make_workspace(engine)
    in_group = _make_target(engine, ws_id)
    outside_group = _make_target(engine, ws_id)
    group_id = _make_group(engine, ws_id)
    _assign_group(engine, in_group, group_id)
    _make_finding(engine, in_group, severity=Severity.CRITICAL)
    _make_finding(engine, outside_group, severity=Severity.CRITICAL)

    res = client.get(f"/api/dashboard/security-score?group_id={group_id}")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["target_count"] == 1
    assert body["components"]["findings"]["open_findings"] == 1


def test_endpoint_rejects_both_filters(client, engine):
    client, uid = _login(client, engine, role=UserRole.ADMIN)
    res = client.get("/api/dashboard/security-score?target_id=1&group_id=1")
    assert res.status_code == 400


def test_endpoint_404_for_inaccessible_target(client, engine):
    client, uid = _login(client, engine, role=UserRole.USER)
    ws_id = _make_workspace(engine)
    other_ws_id = _make_workspace(engine, name="other")
    _membership(engine, uid, ws_id, WorkspaceRole.VIEWER)
    other_target = _make_target(engine, other_ws_id)

    res = client.get(f"/api/dashboard/security-score?target_id={other_target}")
    assert res.status_code == 404


def test_endpoint_workspace_scoped_org_wide(client, engine):
    """A non-admin viewer only sees their own workspace's targets in the
    org-wide (no filter) score; another workspace's Critical findings
    must not drag their score down."""
    client, uid = _login(client, engine, role=UserRole.USER)
    my_ws = _make_workspace(engine, name="mine")
    other_ws = _make_workspace(engine, name="other")
    _membership(engine, uid, my_ws, WorkspaceRole.VIEWER)
    my_target = _make_target(engine, my_ws)
    other_target = _make_target(engine, other_ws)
    _make_scan(engine, my_target)
    _make_finding(engine, other_target, severity=Severity.CRITICAL)

    res = client.get("/api/dashboard/security-score")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["target_count"] == 1
    assert body["components"]["findings"]["open_findings"] == 0
    assert body["score"] == 100.0
