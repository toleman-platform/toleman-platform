"""Tests for issue #63 (single-number security health score):
app.core.security_score.compute_security_score's component formulas and the
GET /api/dashboard/security-score endpoint's org/group/target scoping.

Follows the same in-memory SQLite + TestClient + session-token-login pattern
used in tests/test_sla_rules.py.
"""
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.core import security_score
from app.core.security_score import compute_security_score
from app.core.time import utcnow
from app.core.tool_registry import NON_VULNERABILITY_CATEGORIES
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


def _make_target(engine, workspace_id, default_branch="main", criticality_weight=1) -> int:
    with Session(engine) as session:
        t = Target(
            workspace_id=workspace_id,
            name="repo",
            repo_url="https://github.com/acme/repo",
            default_branch=default_branch,
            criticality_weight=criticality_weight,
        )
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
    tool="semgrep",
) -> int:
    with Session(engine) as session:
        f = Finding(
            target_id=target_id,
            dedup_hash=f"hash-{id(object())}",
            tool=tool,
            rule_id="r1",
            title="t1",
            file_path="a.py",
            severity=severity,
            state=state,
            branch=branch,
            first_seen=first_seen or utcnow(),
        )
        session.add(f)
        session.commit()
        session.refresh(f)
        return f.id


def _make_scan(engine, target_id, started_at=None) -> int:
    with Session(engine) as session:
        s = Scan(target_id=target_id, tool="semgrep", branch="main", status="completed", started_at=started_at or utcnow())
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


def test_findings_score_never_bottoms_out(engine):
    """The findings component must keep discriminating past the old zero point.

    It used a linear ramp that reached 0 at an average of 20 weighted severity
    points -- four Criticals on a single Prod repo -- after which a repo with
    four critical findings and one with four hundred scored identically, and a
    team fixing findings saw the number not move at all until they were most of
    the way through. The saturating curve is steep early and still separates a
    bad estate from a catastrophic one.
    """
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)

    for _ in range(4):
        _make_finding(engine, target_id, severity=Severity.CRITICAL)
    with Session(engine) as session:
        four = compute_security_score(session, [target_id])["components"]["findings"]["score"]

    for _ in range(20):
        _make_finding(engine, target_id, severity=Severity.CRITICAL)
    with Session(engine) as session:
        twenty_four = compute_security_score(session, [target_id])["components"]["findings"]["score"]

    assert four > 0.0, "four Criticals must not zero the component"
    assert twenty_four > 0.0, "the curve must never reach zero"
    assert twenty_four < four, "more findings must still score worse"


def test_findings_score_is_steep_where_it_matters(engine):
    """The first few findings should move the number meaningfully.

    A saturating curve that is too gentle early would be as useless as a linear
    one that flattens late: a clean repo and a repo with a Critical open must
    not look alike.
    """
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)

    with Session(engine) as session:
        clean = compute_security_score(session, [target_id])["components"]["findings"]["score"]
    _make_finding(engine, target_id, severity=Severity.CRITICAL)
    with Session(engine) as session:
        one_critical = compute_security_score(session, [target_id])["components"]["findings"]["score"]

    assert clean == 100.0
    assert one_critical < 80.0, "a Critical must visibly cost score"


def test_clean_target_no_findings_scores_high(engine):
    """No findings, one recent scan, no SLA rules configured anywhere ->
    findings=100 (no open findings), sla=100 (neutral, none tracked),
    coverage=100 (scanned within window), fp_rate=100 (no findings ever).

    The only scan is from today, so there is nothing from 7 days ago to
    compare against and the trend component is unmeasurable; its 15 points
    drop out and the remaining 85 are renormalized. Composite must still be
    a perfect 100, grade A -- scoring the unmeasured component 0 over the
    full 100 would cap this at 85 and call a spotless estate a B.
    """
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
    assert c["trend"]["measurable"] is False
    assert c["trend"]["score"] is None


def test_findings_component_hand_calculated(engine):
    """One target, one open Critical (weight 5) + one open High (weight 4)
    default-branch finding -> weighted_sum=9, target_count=1, avg_per_target=9.
    score = 100 * 10/(9 + 10) = 52.6 to one decimal place.

    The arithmetic changed with the curve (FINDINGS_SCORE_HALF_LIFE replacing a
    linear ramp to zero); what this test is actually pinning down is the
    weighting that feeds it -- weighted_severity_sum and open_findings -- which
    is unchanged.
    """
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _make_finding(engine, target_id, severity=Severity.CRITICAL)
    _make_finding(engine, target_id, severity=Severity.HIGH)

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    f = result["components"]["findings"]
    assert f["weighted_severity_sum"] == 9
    assert f["open_findings"] == 2
    assert f["score"] == 52.6


def test_findings_component_weights_by_target_criticality(engine):
    """One Prod target (criticality_weight=5) with an open Critical, one Dev
    target (criticality_weight=1) with an open Critical: weighted_sum =
    5*5 + 5*1 = 30, total_criticality = 5+1 = 6, avg_per_target = 5.0 ->
    score = 100 * 10/(5 + 10) = 66.7. The same two findings at uniform
    criticality (1 each) would instead average 5.0 too by coincidence here,
    so also assert the raw weighted_sum reflects the 5x multiplier -- that's
    the part a plain target-count average couldn't show."""
    ws_id = _make_workspace(engine)
    prod_target = _make_target(engine, ws_id, criticality_weight=5)
    dev_target = _make_target(engine, ws_id, criticality_weight=1)
    _make_finding(engine, prod_target, severity=Severity.CRITICAL)
    _make_finding(engine, dev_target, severity=Severity.CRITICAL)

    with Session(engine) as session:
        result = compute_security_score(session, [prod_target, dev_target])

    f = result["components"]["findings"]
    assert f["weighted_severity_sum"] == 30.0
    assert f["avg_weighted_severity_per_target"] == 5.0
    assert f["score"] == 66.7


def test_findings_component_same_criticality_everywhere_is_unaffected(engine):
    """Sanity check that per-target criticality weighting is a genuine
    no-op for an org that never configured it (every target defaults to
    criticality_weight=1): this must reproduce
    test_findings_component_hand_calculated's numbers exactly."""
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _make_finding(engine, target_id, severity=Severity.CRITICAL)
    _make_finding(engine, target_id, severity=Severity.HIGH)

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    f = result["components"]["findings"]
    assert f["weighted_severity_sum"] == 9
    assert f["score"] == 52.6


def test_findings_component_discounts_license_findings(engine):
    """A License-category finding (tool="trivy-license") graded Critical by
    the scanner for legal/compliance reasons should not move the score at
    all the way an actually-exploitable Critical would: weighted
    contribution is SEVERITY_WEIGHT(5) x criticality(1) x
    CATEGORY_RISK_WEIGHT["License"] (0.0) = 0, not 5."""
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _make_finding(engine, target_id, severity=Severity.CRITICAL, tool="trivy-license")

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    f = result["components"]["findings"]
    assert f["weighted_severity_sum"] == pytest.approx(0.0)
    assert f["score"] == pytest.approx(100.0)


def test_findings_component_counts_licences_apart_from_vulnerabilities(engine):
    """The count reported next to the score has to be the count the score was
    computed from.

    A live workspace showed "13/100 (188 open on default branch)" where 148
    of the 188 were licence rows contributing exactly nothing to the 13,
    which reads as though 188 findings produced that score. The total is
    still reported, but the vulnerability count and the excluded licence
    count are reported alongside it so the two can never be conflated:
    1 Critical semgrep finding (weight 5) + 3 Critical trivy-license
    findings (weight 0 each) -> weighted_sum 5, score 100*10/(5+10) = 66.7.
    """
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _make_finding(engine, target_id, severity=Severity.CRITICAL, tool="semgrep")
    for _ in range(3):
        _make_finding(engine, target_id, severity=Severity.CRITICAL, tool="trivy-license")

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    f = result["components"]["findings"]
    assert f["open_findings"] == 4
    assert f["open_vulnerabilities"] == 1
    assert f["license_findings_excluded"] == 3
    assert f["weighted_severity_sum"] == pytest.approx(5.0)
    assert f["score"] == 66.7


def test_licence_zero_weighting_is_derived_from_one_definition():
    """CATEGORY_RISK_WEIGHT is built from tool_registry's
    NON_VULNERABILITY_CATEGORIES rather than restating the category list, so
    the score cannot come to disagree with the counts printed beside it."""
    for category in NON_VULNERABILITY_CATEGORIES:
        assert security_score.CATEGORY_RISK_WEIGHT[category] == 0.0
    # Deliberately not set-equality: the constant's own comment invites adding
    # a category with a partial rather than zero weight, and an assertion that
    # forbids the documented extension is a test of the test, not of the code.
    assert set(NON_VULNERABILITY_CATEGORIES) <= set(security_score.CATEGORY_RISK_WEIGHT)


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
    _make_finding(engine, target_id, severity=Severity.CRITICAL, first_seen=utcnow() - timedelta(days=5))
    _make_finding(engine, target_id, severity=Severity.CRITICAL, first_seen=utcnow())

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    sla = result["components"]["sla"]
    assert sla["with_sla"] == 2
    assert sla["in_violation"] == 1
    assert sla["score"] == 50.0


def test_sla_component_excludes_license_findings(engine):
    """SlaRule is keyed purely on severity, with no category awareness, so a
    workspace's "Critical: 1 day" rule would otherwise apply just as
    literally to a License finding a scanner happens to grade Critical (e.g.
    a copyleft license) as to an actually exploitable one. A stale-by-5-days
    License finding must not be counted as with_sla/in_violation, and must
    not drag the score below the neutral 100 a findings-free scope gets."""
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _make_rule(engine, ws_id, None, Severity.CRITICAL, 1)
    _make_finding(
        engine,
        target_id,
        severity=Severity.CRITICAL,
        tool="trivy-license",
        first_seen=utcnow() - timedelta(days=5),
    )

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    sla = result["components"]["sla"]
    assert sla["with_sla"] == 0
    assert sla["in_violation"] == 0
    assert sla["score"] == 100.0


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
    _make_scan(engine, target_id, started_at=utcnow() - timedelta(days=60))

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
    direction 'worsening'.

    The scan from 10 days ago is what makes that a measurement rather than a
    guess: this platform was looking at the repo a week ago and saw nothing,
    so "it was clean then and has a Critical now" is a real comparison.
    Without it there would be no baseline at all (see
    test_trend_is_unmeasurable_without_any_observation_from_the_window_ago).
    """
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _make_scan(engine, target_id, started_at=utcnow() - timedelta(days=10))
    _make_finding(engine, target_id, severity=Severity.CRITICAL, first_seen=utcnow() - timedelta(days=2))

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    trend = result["components"]["trend"]
    assert trend["measurable"] is True
    assert trend["prior_weighted_sum"] == 0.0
    assert trend["current_weighted_sum"] == 5.0
    assert trend["direction"] == "worsening"
    assert trend["score"] == 0.0


def test_onboarding_repos_into_an_established_org_is_not_a_worsening_trend(engine):
    """Adding targets must not read as posture getting worse.

    An established repo scanned a fortnight ago with one open Low is the only
    thing with a baseline. Ten repos onboarded today bring 200 Criticals
    between them. Measuring the trend across the whole scope compared a prior
    sum that could not include those repos against a current sum that does,
    which scored 0/100 and raised a red penalty on the day an operator did
    exactly what the product asks. Targets without a baseline belong on
    neither side of the comparison.
    """
    ws_id = _make_workspace(engine)
    established = _make_target(engine, ws_id)
    _make_scan(engine, established, started_at=utcnow() - timedelta(days=14))
    _make_finding(engine, established, severity=Severity.LOW, first_seen=utcnow() - timedelta(days=14))

    target_ids = [established]
    for _ in range(10):
        fresh = _make_target(engine, ws_id)
        target_ids.append(fresh)
        for _ in range(20):
            _make_finding(engine, fresh, severity=Severity.CRITICAL, first_seen=utcnow())

    with Session(engine) as session:
        result = compute_security_score(session, target_ids)

    trend = result["components"]["trend"]
    assert trend["measurable"] is True
    # The established repo is unchanged across the window, so the comparison
    # it is the only participant in is flat.
    assert trend["direction"] != "worsening"
    assert trend["score"] == 100.0
    assert result["weakest_component"] != "trend"


def test_trend_is_unmeasurable_without_any_observation_from_the_window_ago(engine):
    """An instance younger than the trend window has no week-ago baseline,
    and must say so rather than score 0.

    Every finding's first_seen is inside the window and there is no scan
    predating it, so `_weighted_open_sum_at(7 days ago)` returns 0 because
    nothing had been looked at -- not because the repo was clean. Reading
    that 0 as a baseline turned one open Critical into a 500% week-on-week
    increase and a flat 0/100, on an instance with no 7-day history at all.
    That is frontend/AGENTS.md 1.4: an unmeasured value is unknown, never a
    confident zero.
    """
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _make_finding(engine, target_id, severity=Severity.CRITICAL, first_seen=utcnow() - timedelta(days=2))

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    trend = result["components"]["trend"]
    assert trend["measurable"] is False
    assert trend["score"] is None, "an unmeasurable component must not report a number"
    assert trend["prior_weighted_sum"] is None, "there was no prior observation to report"
    assert trend["direction"] == "unknown"
    assert trend["current_weighted_sum"] == 5.0, "what IS measurable is still reported"
    assert trend["note"]


def test_trend_is_measurable_from_a_clean_scan_predating_the_window(engine):
    """A repo scanned a fortnight ago and clean ever since has a genuine
    baseline of zero, even with no findings to date. Evidence of having
    looked is enough; there need not be anything to have found."""
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _make_scan(engine, target_id, started_at=utcnow() - timedelta(days=14))

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    trend = result["components"]["trend"]
    assert trend["measurable"] is True
    assert trend["prior_weighted_sum"] == 0.0
    assert trend["current_weighted_sum"] == 0.0
    assert trend["direction"] == "stable"
    assert trend["score"] == 100.0


def test_composite_renormalises_over_the_measured_components_only(engine):
    """An unmeasurable component drops out of the weighting; it is not
    scored 0 against the full 100.

    One target, criticality 1, one open Critical semgrep finding first seen
    2 days ago, no scans and no SLA rules:

        findings  100 * 10/(5 + 10)      =  66.7  (weight 35)
        sla       no applicable rules    = 100.0  (weight 25)
        coverage  0 of 1 scanned         =   0.0  (weight 15)
        fp_rate   0 of 1 ever FP         = 100.0  (weight 10)
        trend     no week-ago baseline   = unmeasurable (weight 15, dropped)

        (66.7*35 + 100*25 + 0*15 + 100*10) / 85 = 5834.5 / 85 = 68.6 -> D

    Scoring the trend 0 and dividing by 100 instead gives 58.3, a grade F,
    with 15 of the missing 41.7 points charged for a measurement nobody
    took. That is the number the live instance was showing.
    """
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _make_finding(engine, target_id, severity=Severity.CRITICAL, first_seen=utcnow() - timedelta(days=2))

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    assert result["components"]["trend"]["measurable"] is False
    assert result["components"]["findings"]["score"] == 66.7
    assert result["components"]["coverage"]["score"] == 0.0
    assert result["score"] == 68.6
    assert result["grade"] == "D"


def test_unmeasurable_component_is_never_named_as_the_score_penalty(engine, monkeypatch):
    """The dashboard renders `weakest_component` as a red "Score penalty"
    callout. A component nobody could measure is not costing score -- it was
    renormalized out -- so naming it would send a reader off to fix a number
    this platform never produced. Every measured component is perfect here,
    so there is no penalty to name at all."""
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)

    for name, weight in (
        ("_findings_score", security_score.FINDINGS_WEIGHT),
        ("_sla_score", security_score.SLA_WEIGHT),
        ("_coverage_score", security_score.COVERAGE_WEIGHT),
        ("_fp_rate_score", security_score.FP_WEIGHT),
    ):
        monkeypatch.setattr(
            security_score, name, lambda *a, _w=weight, **k: {"score": 100.0, "weight": _w, "measurable": True}
        )
    monkeypatch.setattr(
        security_score,
        "_trend_score",
        lambda *a, **k: {"score": None, "weight": security_score.TREND_WEIGHT, "measurable": False},
    )

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    assert result["weakest_component"] is None
    assert result["score"] == 100.0


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
        engine, target_id, severity=Severity.CRITICAL, first_seen=utcnow() - timedelta(days=10), state=FindingState.MITIGATED
    )
    _log_transition(
        engine, finding_id, "Open", "Mitigated", created_at=utcnow() - timedelta(days=3)
    )

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    trend = result["components"]["trend"]
    assert trend["prior_weighted_sum"] == 5.0
    assert trend["current_weighted_sum"] == 0.0
    assert trend["direction"] == "improving"
    assert trend["score"] == 100.0


def test_trend_component_uses_the_same_per_finding_weight_as_findings_score(engine):
    """The trend component must weight findings identically to
    findings_score (target criticality x category risk), not the plain
    SEVERITY_WEIGHT it used before that weighting existed -- otherwise the
    two components could tell contradictory stories about the same
    findings. A Critical (weight 5) in a criticality_weight=5 Prod target,
    first_seen 2 days ago (inside the 7-day window): current_weighted_sum
    should be 25 (5*5*1.0 category), not the flat 5 a pre-criticality-
    weighting trend component would have reported. The scan from 10 days ago
    supplies the week-ago baseline the comparison needs."""
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id, criticality_weight=5)
    _make_scan(engine, target_id, started_at=utcnow() - timedelta(days=10))
    _make_finding(engine, target_id, severity=Severity.CRITICAL, first_seen=utcnow() - timedelta(days=2))

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    trend = result["components"]["trend"]
    assert trend["prior_weighted_sum"] == 0.0
    assert trend["current_weighted_sum"] == 25.0
    assert trend["direction"] == "worsening"


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


def test_no_weakest_component_when_nothing_is_weak(engine, monkeypatch):
    """A perfect posture must not name a penalty.

    `weakest_component` was an unconditional min() over the five components,
    so an instance scoring 100 on every one still reported a "weakest" -- and
    the dashboard rendered a red "Score penalty: Open findings score" callout
    with that row highlighted destructive, next to a Grade A. Naming a 100/100
    component as the thing dragging the score down is the same class of
    untruth as rendering a failed fetch as a zero.

    The five component functions are patched rather than a perfect instance
    being constructed: coverage needs a recent scan and trend needs history,
    and what is under test is the reporting rule, not the arithmetic that
    reaches 100.
    """
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)

    for name, weight in (
        ("_findings_score", security_score.FINDINGS_WEIGHT),
        ("_sla_score", security_score.SLA_WEIGHT),
        ("_coverage_score", security_score.COVERAGE_WEIGHT),
        ("_fp_rate_score", security_score.FP_WEIGHT),
        ("_trend_score", security_score.TREND_WEIGHT),
    ):
        monkeypatch.setattr(
            security_score, name, lambda *a, _w=weight, **k: {"score": 100.0, "weight": _w, "measurable": True}
        )

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    assert result["score"] == 100.0
    assert result["weakest_component"] is None, "a perfect posture has no penalty to name"


def test_weakest_component_named_when_one_is_below_perfect(engine, monkeypatch):
    """The converse: anything short of 100 is genuinely costing score."""
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)

    scores = {
        "_findings_score": (100.0, security_score.FINDINGS_WEIGHT),
        "_sla_score": (99.0, security_score.SLA_WEIGHT),
        "_coverage_score": (100.0, security_score.COVERAGE_WEIGHT),
        "_fp_rate_score": (100.0, security_score.FP_WEIGHT),
        "_trend_score": (100.0, security_score.TREND_WEIGHT),
    }
    for name, (value, weight) in scores.items():
        monkeypatch.setattr(
            security_score, name, lambda *a, _v=value, _w=weight, **k: {"score": _v, "weight": _w, "measurable": True}
        )

    with Session(engine) as session:
        result = compute_security_score(session, [target_id])

    assert result["weakest_component"] == "sla"


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


def test_endpoint_multi_target_scope(client, engine):
    """(dashboard scope picker follow-up) target_ids is the multi-select
    sibling of target_id -- scores exactly the chosen repos, not the whole
    workspace."""
    client, uid = _login(client, engine, role=UserRole.ADMIN)
    ws_id = _make_workspace(engine)
    picked_a = _make_target(engine, ws_id)
    picked_b = _make_target(engine, ws_id)
    not_picked = _make_target(engine, ws_id)
    _make_scan(engine, picked_a)
    _make_scan(engine, picked_b)
    _make_finding(engine, not_picked, severity=Severity.CRITICAL)

    res = client.get(f"/api/dashboard/security-score?target_ids={picked_a}&target_ids={picked_b}")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["target_count"] == 2
    # The unpicked target's Critical finding must not appear in this score.
    assert body["components"]["findings"]["open_findings"] == 0


def test_endpoint_multi_target_404_for_any_inaccessible_id(client, engine):
    client, uid = _login(client, engine, role=UserRole.USER)
    my_ws = _make_workspace(engine, name="mine")
    other_ws = _make_workspace(engine, name="other")
    _membership(engine, uid, my_ws, WorkspaceRole.VIEWER)
    my_target = _make_target(engine, my_ws)
    other_target = _make_target(engine, other_ws)

    res = client.get(f"/api/dashboard/security-score?target_ids={my_target}&target_ids={other_target}")
    assert res.status_code == 404


def test_resolve_target_ids_empty_list_scores_nothing(engine):
    """Unit-level, not through the HTTP endpoint: FastAPI's repeated-param
    convention has no way to send "target_ids explicitly empty" separately
    from "omitted" over the wire, but the frontend scope picker's own
    zero-selected-repos state calls this with target_ids=[] directly, and
    that must score zero targets rather than falling through to org-wide."""
    from app.core.security_score import resolve_target_ids_for_scope

    ws_id = _make_workspace(engine)
    _make_target(engine, ws_id)
    with Session(engine) as session:
        result = resolve_target_ids_for_scope(session, None, None, None, target_ids=[])
    assert result == []


def test_endpoint_rejects_target_ids_and_group_id_together(client, engine):
    client, uid = _login(client, engine, role=UserRole.ADMIN)
    res = client.get("/api/dashboard/security-score?target_ids=1&group_id=1")
    assert res.status_code == 400


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
