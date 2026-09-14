"""Tests for GET /api/findings/facets (issue #270): per-value counts for
every filterable dimension of the Findings page at once.

Three things have to hold for a count next to a filter to be worth
printing, and they are what this file pins:

  1. A count reflects every OTHER active filter, but not its own dimension
     -- otherwise selecting Critical would zero out High and you could
     never see what widening would get you.
  2. A count never totals up a row the caller cannot see (#57). A facet
     that leaks "production: 40" from another tenant's workspace is a data
     leak with a friendly font.
  3. A count agrees with the list it sits above. `total` here and `total`
     from GET /api/findings for the same params are the same number, by
     construction (one shared query builder) and by test.

Follows the same in-memory SQLite + dependency_override pattern as
tests/test_findings.py, plus test_workspace_scoped_reads.py's membership
helpers for the scoping cases.
"""
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    CveEnrichment,
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


def _login(client, engine, role=UserRole.ADMIN, email="user@example.com"):
    with Session(engine) as session:
        user = User(email=email, name="Test User", password_hash=hash_password("whatever123"), role=role)
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


def _make_target(engine, workspace_id=None, name="Target A", **overrides) -> int:
    if workspace_id is None:
        workspace_id = _make_workspace(engine, name)
    with Session(engine) as session:
        target = Target(
            workspace_id=workspace_id,
            name=name,
            repo_url="https://example.com/repo.git",
            **overrides,
        )
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


def _make_finding(engine, target_id, **overrides) -> int:
    defaults = dict(
        target_id=target_id,
        dedup_hash=f"hash-{target_id}-{overrides.get('rule_id', 'r')}",
        tool="semgrep",
        rule_id="rule-1",
        title="SQL Injection",
        file_path="app/main.py",
        severity=Severity.HIGH,
        priority_score=50,
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
        session.add(WorkspaceMembership(user_id=user_id, workspace_id=workspace_id, role=role))
        session.commit()


def _facets(client, **params) -> dict:
    resp = client.get("/api/findings/facets", params=params)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _counts(facets: dict, dimension: str) -> dict:
    return {row["value"]: row["count"] for row in facets[dimension]}


# ---------------------------------------------------------------------------
# Shape: every dimension, every option, zeros included
# ---------------------------------------------------------------------------


def test_returns_every_filterable_dimension(client, engine):
    _login(client, engine)
    facets = _facets(client)
    assert set(facets) == {
        "severity",
        "state",
        "tool",
        "fixability",
        "environment",
        "owner",
        "category",
        "total",
    }


def test_closed_enums_list_every_option_even_at_zero(client, engine):
    """"0 Critical" is the good news it looks like; a missing Critical row
    is indistinguishable from a broken filter. Severity, state and
    fixability are closed sets, so every rung is always offered."""
    _login(client, engine)
    target_id = _make_target(engine)
    _make_finding(engine, target_id, rule_id="r1", severity=Severity.LOW)

    facets = _facets(client)
    severity = _counts(facets, "severity")
    assert severity == {"Critical": 0, "High": 0, "Medium": 0, "Low": 1, "Informational": 0}
    assert set(_counts(facets, "state")) == {
        "Open",
        "Accepted Risk",
        "False Positive",
        "Won't Fix",
        "Mitigated",
        "Reopened",
    }
    assert set(_counts(facets, "fixability")) == {"fixable", "no_known_fix", "unknown"}


def test_state_facet_keys_are_member_values_not_member_names(client, engine):
    """`finding.state` is a native `sa.Enum` column labelled with member
    *names* (WONT_FIX), while every API surface speaks member *values*
    ("Won't Fix"). State is the enum where the two diverge hardest --
    ACCEPTED_RISK -> "Accepted Risk", WONT_FIX -> "Won't Fix" -- so any
    name-to-value transform that isn't a lookup through the enum itself
    (a .title(), a .replace("_", " ")) produces keys that match no option
    and therefore vanish into a permanently-zero pill with nothing saying
    so. Severity has the same trap at INFO -> "Informational", pinned by
    test_closed_enums_list_every_option_even_at_zero.

    Pinned against the query params the same endpoint accepts, since those
    are what the pill will send back when someone clicks it.
    """
    _login(client, engine)
    target_id = _make_target(engine)
    _make_finding(engine, target_id, rule_id="r1", state=FindingState.ACCEPTED_RISK)
    _make_finding(engine, target_id, rule_id="r2", state=FindingState.WONT_FIX)
    _make_finding(engine, target_id, rule_id="r3", state=FindingState.FALSE_POSITIVE)

    state = _counts(_facets(client), "state")
    assert state["Accepted Risk"] == 1
    assert state["Won't Fix"] == 1
    assert state["False Positive"] == 1
    assert state["Open"] == 0
    # No name-spelled keys leaked through alongside the values.
    assert not {key for key in state if key.isupper() or "_" in key}
    # And each key round-trips as a filter value on the list endpoint.
    for value, count in state.items():
        listed = client.get("/api/findings", params={"state": value, "page_size": 1}).json()["total"]
        assert listed == count, value


def test_counts_each_severity(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    _make_finding(engine, target_id, rule_id="r1", severity=Severity.CRITICAL)
    _make_finding(engine, target_id, rule_id="r2", severity=Severity.CRITICAL)
    _make_finding(engine, target_id, rule_id="r3", severity=Severity.HIGH)

    severity = _counts(_facets(client), "severity")
    assert severity["Critical"] == 2
    assert severity["High"] == 1
    assert severity["Medium"] == 0


def test_counts_each_tool_and_state(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    _make_finding(engine, target_id, rule_id="r1", tool="semgrep", state=FindingState.OPEN)
    _make_finding(engine, target_id, rule_id="r2", tool="trivy", state=FindingState.OPEN)
    _make_finding(engine, target_id, rule_id="r3", tool="trivy", state=FindingState.MITIGATED)

    facets = _facets(client)
    assert _counts(facets, "tool") == {"semgrep": 1, "trivy": 2}
    state = _counts(facets, "state")
    assert state["Open"] == 2
    assert state["Mitigated"] == 1
    assert state["Reopened"] == 0


def test_category_dimension_matches_the_standalone_categories_endpoint(client, engine):
    """The category tabs and the filter bar are two views of one query, and
    now read from one answer -- they must not be able to disagree."""
    _login(client, engine)
    target_id = _make_target(engine)
    _make_finding(engine, target_id, rule_id="r1", tool="semgrep")
    _make_finding(engine, target_id, rule_id="r2", tool="trivy")

    facets = _counts(_facets(client), "category")
    legacy = {row["category"]: row["count"] for row in client.get("/api/findings/facets/categories").json()}
    assert facets == legacy
    assert facets["SAST"] == 1
    assert facets["SCA"] == 1


# ---------------------------------------------------------------------------
# Rule 1: other filters narrow a dimension; its own filter does not
# ---------------------------------------------------------------------------


def test_counts_respect_another_active_filter(client, engine):
    """The headline of #270: selecting environment=production has to
    re-count Critical/High for production, not just narrow the list."""
    _login(client, engine)
    prod = _make_target(engine, name="prod-repo", environment="production")
    staging = _make_target(engine, name="staging-repo", environment="staging")
    _make_finding(engine, prod, rule_id="r1", severity=Severity.CRITICAL)
    _make_finding(engine, staging, rule_id="r2", severity=Severity.CRITICAL)
    _make_finding(engine, staging, rule_id="r3", severity=Severity.CRITICAL)

    assert _counts(_facets(client), "severity")["Critical"] == 3
    assert _counts(_facets(client, environment="production"), "severity")["Critical"] == 1


def test_counts_respect_an_active_tool_filter(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    _make_finding(engine, target_id, rule_id="r1", tool="semgrep", severity=Severity.CRITICAL)
    _make_finding(engine, target_id, rule_id="r2", tool="trivy", severity=Severity.CRITICAL)

    severity = _counts(_facets(client, tool="semgrep"), "severity")
    assert severity["Critical"] == 1


def test_counts_respect_an_active_search(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    _make_finding(engine, target_id, rule_id="r1", title="SQL injection", severity=Severity.HIGH)
    _make_finding(engine, target_id, rule_id="r2", title="Hardcoded secret", severity=Severity.HIGH)

    assert _counts(_facets(client, search="injection"), "severity")["High"] == 1


def test_counts_respect_the_active_category_tab(client, engine):
    """Category is a tab, not a filter -- the pills live inside it, so it
    narrows every other dimension (but never the category counts)."""
    _login(client, engine)
    target_id = _make_target(engine)
    _make_finding(engine, target_id, rule_id="r1", tool="semgrep", severity=Severity.CRITICAL)
    _make_finding(engine, target_id, rule_id="r2", tool="trivy", severity=Severity.CRITICAL)

    facets = _facets(client, category="SCA")
    assert _counts(facets, "severity")["Critical"] == 1
    # ...and the category dimension itself is still counted across every
    # category, or the tab you are standing on would be the only one with a
    # number next to it.
    assert _counts(facets, "category")["SAST"] == 1


def test_a_dimension_does_not_filter_its_own_counts(client, engine):
    """Selecting Critical must not zero out High: the count next to High is
    exactly the answer to "what would I get if I added it?", and a control
    that hides that is worse than no control."""
    _login(client, engine)
    target_id = _make_target(engine)
    _make_finding(engine, target_id, rule_id="r1", severity=Severity.CRITICAL)
    _make_finding(engine, target_id, rule_id="r2", severity=Severity.HIGH)
    _make_finding(engine, target_id, rule_id="r3", severity=Severity.HIGH)

    severity = _counts(_facets(client, severity="Critical"), "severity")
    assert severity["Critical"] == 1
    assert severity["High"] == 2


def test_state_counts_drop_resolved_too_because_state_overrides_it(client, engine):
    """`resolved` is the state dimension under another name, and in the list
    an explicit `state` wins over it. So the state facet has to drop both:
    counting with `resolved` applied while the list ignores it is how
    `?state=Open&resolved=false` came to report "Mitigated: 0" next to a
    `?state=Mitigated&resolved=false` query that returns a row.

    Not reachable from the UI (the Open view doesn't render Mitigated), but
    /api/findings/facets is a public endpoint and that was a wrong answer.
    """
    _login(client, engine)
    target_id = _make_target(engine)
    _make_finding(engine, target_id, rule_id="r1", state=FindingState.OPEN)
    _make_finding(engine, target_id, rule_id="r2", state=FindingState.REOPENED)
    _make_finding(engine, target_id, rule_id="r3", state=FindingState.MITIGATED)

    params = {"state": "Open", "resolved": "false"}
    state = _counts(_facets(client, **params), "state")
    assert state["Open"] == 1
    assert state["Reopened"] == 1  # own filter dropped
    assert state["Mitigated"] == 1  # ...and so is `resolved`, because:
    listed = client.get("/api/findings", params={**params, "state": "Mitigated"}).json()
    assert listed["total"] == 1  # the list says 1, so the count must not say 0


def test_two_dimensions_narrow_each_other_but_not_themselves(client, engine):
    _login(client, engine)
    prod = _make_target(engine, name="prod-repo", environment="production", owner="platform-team")
    dev = _make_target(engine, name="dev-repo", environment="dev", owner="data-team")
    _make_finding(engine, prod, rule_id="r1", severity=Severity.CRITICAL)
    _make_finding(engine, dev, rule_id="r2", severity=Severity.CRITICAL)

    facets = _facets(client, environment="production", severity="Critical")
    # environment's own counts ignore environment, but obey severity.
    assert _counts(facets, "environment") == {"dev": 1, "production": 1}
    # severity's counts ignore severity, but obey environment.
    assert _counts(facets, "severity")["Critical"] == 1


# ---------------------------------------------------------------------------
# Fixability (#246): derived from CveEnrichment, not a stored column
# ---------------------------------------------------------------------------


def test_fixability_counts(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    _make_finding(engine, target_id, rule_id="r1", cve_id="CVE-2024-0001")
    _make_finding(engine, target_id, rule_id="r2", cve_id="CVE-2024-0002")
    _make_finding(engine, target_id, rule_id="r3")  # no cve_id at all
    with Session(engine) as session:
        session.add(CveEnrichment(cve_id="CVE-2024-0001", osv_found=True, fixed_versions=json.dumps([{"fixed": "1.0"}])))
        session.add(CveEnrichment(cve_id="CVE-2024-0002", osv_found=True, fixed_versions=json.dumps([])))
        session.commit()

    assert _counts(_facets(client), "fixability") == {"fixable": 1, "no_known_fix": 1, "unknown": 1}


def test_fixability_counts_agree_with_the_fixability_filter(client, engine):
    """Same conditions, two callers: whatever the pill says, clicking it
    must return exactly that many findings."""
    _login(client, engine)
    target_id = _make_target(engine)
    for i in range(3):
        _make_finding(engine, target_id, rule_id=f"r{i}", cve_id=f"CVE-2024-000{i}")
    _make_finding(engine, target_id, rule_id="r-nocve")
    with Session(engine) as session:
        session.add(CveEnrichment(cve_id="CVE-2024-0000", osv_found=True, fixed_versions=json.dumps([{"fixed": "1.0"}])))
        session.add(CveEnrichment(cve_id="CVE-2024-0001", osv_found=True, fixed_versions=json.dumps([{"fixed": "2.0"}])))
        session.add(CveEnrichment(cve_id="CVE-2024-0002", osv_found=True, fixed_versions=json.dumps([])))
        session.commit()

    counts = _counts(_facets(client), "fixability")
    for bucket, expected in counts.items():
        listed = client.get("/api/findings", params={"fixability": bucket}).json()["total"]
        assert listed == expected, bucket


# ---------------------------------------------------------------------------
# Rule 3: the counts and the list are the same claim
# ---------------------------------------------------------------------------


# Each dimension and the query param that selects one of its values. The
# whole feature rests on these being the same claim: the number on a pill is
# a promise about what the list returns when you click it.
DIMENSION_PARAM = {
    "severity": "severity",
    "state": "state",
    "tool": "tool",
    "fixability": "fixability",
    "environment": "environment",
    "owner": "owner",
    "category": "category",
}

FILTER_SETS = [
    {},
    {"severity": "Critical"},
    {"resolved": "false"},
    {"resolved": "true"},
    {"environment": "production"},
    {"owner": "platform-team"},
    {"state": "Open"},
    {"tool": "semgrep", "severity": "Critical"},
    {"search": "injection"},
    {"category": "SAST"},
    {"fixability": "unknown", "resolved": "false"},
]


def _seed_mixed_backlog(engine):
    """A backlog that is mixed on every axis at once, so a count that is
    right only because two dimensions happen to coincide still fails."""
    prod = _make_target(engine, name="prod-repo", environment="production", owner="platform-team")
    dev = _make_target(engine, name="dev-repo", environment="dev", owner="data-team")
    # Distinct titles: the default title contains "Injection", and `search`
    # is case-insensitive, so a shared default would make `search=injection`
    # match everything and quietly stop discriminating anything.
    _make_finding(engine, prod, rule_id="r1", tool="semgrep", title="SQL injection", severity=Severity.CRITICAL)
    _make_finding(
        engine, prod, rule_id="r2", tool="trivy", title="Outdated dep",
        severity=Severity.HIGH, state=FindingState.MITIGATED,
    )
    _make_finding(
        engine, prod, rule_id="r3", tool="trivy", title="Weak cipher",
        severity=Severity.LOW, state=FindingState.REOPENED,
    )
    _make_finding(engine, dev, rule_id="r4", tool="semgrep", title="Path traversal", severity=Severity.CRITICAL)
    _make_finding(engine, dev, rule_id="r5", tool="gitleaks", title="AWS key", severity=Severity.LOW)
    _make_finding(
        engine, dev, rule_id="r6", tool="gitleaks", title="Slack token",
        severity=Severity.INFO, state=FindingState.ACCEPTED_RISK,
    )
    _make_finding(
        engine, dev, rule_id="r7", tool="trivy", title="Vulnerable lib",
        severity=Severity.HIGH, cve_id="CVE-2024-0001",
    )
    with Session(engine) as session:
        session.add(
            CveEnrichment(cve_id="CVE-2024-0001", osv_found=True, fixed_versions=json.dumps([{"fixed": "1.0"}]))
        )
        session.commit()


@pytest.mark.parametrize("params", FILTER_SETS)
def test_every_count_matches_the_list_filtered_to_that_value(client, engine, params):
    """The test the whole feature rests on.

    For every dimension and every one of its values, asking the list for
    that value -- on top of whatever else is already filtered -- must return
    exactly the number the pill shows. Deliberately not a comparison of
    `facets["total"]` against the list's `total`: those two are the same two
    lines of code, so parametrizing that comparison only parametrizes an
    identity and can never fail. This applies the value.
    """
    _login(client, engine)
    _seed_mixed_backlog(engine)

    facets = _facets(client, **params)
    for dimension, param in DIMENSION_PARAM.items():
        for row in facets[dimension]:
            # Overwrites this dimension's own value in `params` when it has
            # one, which is the point: a dimension is counted with its own
            # filter dropped, so the list has to be asked the same way.
            listed = client.get(
                "/api/findings",
                params={**params, param: row["value"], "page_size": 1},
            ).json()["total"]
            assert listed == row["count"], f"{dimension}={row['value']!r} under {params}"


@pytest.mark.parametrize("params", FILTER_SETS)
def test_total_matches_the_list_query_for_the_same_filters(client, engine, params):
    """Weaker than the per-value test above (both sides run the same two
    lines), kept as a cheap guard on the one thing it does cover: that
    `total` applies the complete filter set, including `category`, rather
    than some dimension's reduced one."""
    _login(client, engine)
    _seed_mixed_backlog(engine)

    facets = _facets(client, **params)
    listed = client.get("/api/findings", params={**params, "page_size": 1}).json()["total"]
    assert facets["total"] == listed


def test_severity_counts_sum_to_the_unfiltered_total(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    for i, severity in enumerate([Severity.CRITICAL, Severity.HIGH, Severity.HIGH, Severity.INFO]):
        _make_finding(engine, target_id, rule_id=f"r{i}", severity=severity)

    facets = _facets(client)
    assert sum(row["count"] for row in facets["severity"]) == facets["total"] == 4


# ---------------------------------------------------------------------------
# Rule 2: workspace scoping (#57)
# ---------------------------------------------------------------------------


def test_counts_never_include_another_workspace(client, engine):
    ws_a = _make_workspace(engine, "ws-a")
    ws_b = _make_workspace(engine, "ws-b")
    target_a = _make_target(engine, ws_a, name="target-a", environment="production", owner="platform-team")
    target_b = _make_target(engine, ws_b, name="target-b", environment="production", owner="other-team")
    _make_finding(engine, target_a, rule_id="r-a", severity=Severity.CRITICAL, tool="semgrep")
    for i in range(5):
        _make_finding(engine, target_b, rule_id=f"r-b{i}", severity=Severity.CRITICAL, tool="trivy")

    uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    facets = _facets(client)
    assert _counts(facets, "severity")["Critical"] == 1
    assert facets["total"] == 1
    # The other tenant's tool/owner must not even be offered as an option:
    # the option list is a statement about what exists, too.
    assert _counts(facets, "tool") == {"semgrep": 1}
    assert set(_counts(facets, "owner")) == {"platform-team"}
    assert _counts(facets, "environment") == {"production": 1}


def test_caller_with_no_workspace_membership_gets_zeros_not_everything(client, engine):
    ws = _make_workspace(engine, "ws-a")
    target_id = _make_target(engine, ws, name="target-a", environment="production")
    _make_finding(engine, target_id, rule_id="r1", severity=Severity.CRITICAL)

    _login(client, engine, role=UserRole.VIEWER)  # no membership assigned

    facets = _facets(client)
    assert facets["total"] == 0
    assert _counts(facets, "severity")["Critical"] == 0
    assert facets["tool"] == []
    assert facets["environment"] == []
    # The closed enums are still offered: the dimensions exist, they are
    # just empty for this caller.
    assert len(facets["severity"]) == 5


# ---------------------------------------------------------------------------
# Target metadata dimensions (#251)
# ---------------------------------------------------------------------------


def test_environment_and_owner_counts(client, engine):
    _login(client, engine)
    prod = _make_target(engine, name="prod-repo", environment="production", owner="platform-team")
    staging = _make_target(engine, name="staging-repo", environment="staging", owner="platform-team")
    _make_finding(engine, prod, rule_id="r1")
    _make_finding(engine, prod, rule_id="r2")
    _make_finding(engine, staging, rule_id="r3")

    facets = _facets(client)
    assert _counts(facets, "environment") == {"production": 2, "staging": 1}
    assert _counts(facets, "owner") == {"platform-team": 3}


def test_an_environment_with_no_matching_findings_is_zero_not_missing(client, engine):
    _login(client, engine)
    prod = _make_target(engine, name="prod-repo", environment="production")
    _make_target(engine, name="staging-repo", environment="staging")  # no findings at all
    _make_finding(engine, prod, rule_id="r1")

    assert _counts(_facets(client), "environment") == {"production": 1, "staging": 0}


def test_environment_filter_accepts_several_values(client, engine):
    """Multi-select since #270, so the pills behave like their neighbours;
    a single value still means what it always did."""
    _login(client, engine)
    prod = _make_target(engine, name="prod-repo", environment="production")
    staging = _make_target(engine, name="staging-repo", environment="staging")
    dev = _make_target(engine, name="dev-repo", environment="dev")
    _make_finding(engine, prod, rule_id="r1")
    _make_finding(engine, staging, rule_id="r2")
    _make_finding(engine, dev, rule_id="r3")

    both = client.get("/api/findings", params={"environment": ["production", "staging"]}).json()
    assert both["total"] == 2
    one = client.get("/api/findings", params={"environment": "production"}).json()
    assert one["total"] == 1


def test_facets_endpoint_requires_login(client, engine):
    assert client.get("/api/findings/facets").status_code == 401
