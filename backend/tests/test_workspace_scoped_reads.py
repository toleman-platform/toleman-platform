"""Tests for issue #57: GET/list routes on findings and targets (plus the
dashboard aggregates) never filtered by workspace, so any authenticated user (
including a viewer with no WorkspaceMembership at all) could list or
view every workspace's findings and targets. #32 already gated the write
paths; this covers the read-path counterpart added by
app.api.auth.accessible_workspace_ids.

Follows the same in-memory SQLite + TestClient + session-token-login pattern
used in tests/test_workspace_roles.py. `engine`/`client` fixtures and the
`_login`/`_make_workspace`/`_make_target`/`_make_finding`/`_make_pr_scan`/
`_assign` helpers now live in conftest.py (issue #506, once a second and
third test module needed the same pattern) -- imported here, not redefined.
"""
from app.models.models import Severity, UserRole

from .conftest import _assign, _login, _make_finding, _make_pr_scan, _make_target, _make_workspace


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
    """The workspace-key endpoint leaks a secret (api_key), not just data;
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


def test_dashboard_summary_excludes_license_findings(client, engine):
    """A trivy-license finding is a legal/compliance signal, not a
    vulnerability -- same reasoning as security_score.CATEGORY_RISK_WEIGHT.
    It must not inflate GET /api/dashboard/summary's counts."""
    ws_a = _make_workspace(engine, "ws-license")
    target_a = _make_target(engine, ws_a, "target-license")
    _make_finding(engine, target_a, rule_id="r-a")
    _make_finding(engine, target_a, rule_id="license:MIT", tool="trivy-license", dedup_hash="license-1")
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get("/api/dashboard/summary")
    assert res.status_code == 200
    assert res.json()["total"] == 1
    assert res.json()["open"] == 1


def test_dashboard_stats_excludes_license_findings(client, engine):
    ws_a = _make_workspace(engine, "ws-license-stats")
    target_a = _make_target(engine, ws_a, "target-license-stats")
    _make_finding(engine, target_a, rule_id="r-a", severity=Severity.CRITICAL)
    _make_finding(
        engine,
        target_a,
        rule_id="license:MIT",
        tool="trivy-license",
        dedup_hash="license-2",
        severity=Severity.HIGH,
    )
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    body = res.json()
    assert body["open"] == 1
    assert body["by_tool"] == {"semgrep": 1}


def test_dashboard_posture_scoped_to_caller_workspace(client, engine):
    ws_a, ws_b, target_a, target_b, _fa, _fb = _two_workspace_setup(engine)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get("/api/dashboard/posture")
    assert res.status_code == 200
    target_ids = {row["target"]["id"] for row in res.json()}
    assert target_ids == {target_a}


def test_get_pr_guardrail_findings_in_other_workspace_returns_404(client, engine):
    """A viewer with no membership in the scan's workspace must not be able
    to read PR Guardrail findings for it by guessing/incrementing
    pr_scan_id; the read-path counterpart to #57 for this router."""
    ws_a, ws_b, target_a, target_b, _fa, _fb = _two_workspace_setup(engine)
    scan_a = _make_pr_scan(engine, target_a)
    scan_b = _make_pr_scan(engine, target_b)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get(f"/api/pr-guardrail/{scan_b}/findings")
    assert res.status_code == 404

    own = client.get(f"/api/pr-guardrail/{scan_a}/findings")
    assert own.status_code == 200


def test_override_pr_guardrail_scan_in_other_workspace_returns_404(client, engine):
    ws_a, ws_b, target_a, target_b, _fa, _fb = _two_workspace_setup(engine)
    scan_b = _make_pr_scan(engine, target_b)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.post(f"/api/pr-guardrail/{scan_b}/override", json={"reason": "accepted risk"})
    assert res.status_code == 404


def test_pr_guardrail_findings_empty_membership_returns_404(client, engine):
    ws_a, ws_b, target_a, target_b, _fa, _fb = _two_workspace_setup(engine)
    scan_a = _make_pr_scan(engine, target_a)
    client, _uid = _login(client, engine, role=UserRole.VIEWER)  # zero WorkspaceMembership rows

    res = client.get(f"/api/pr-guardrail/{scan_a}/findings")
    assert res.status_code == 404


def test_admin_sees_pr_guardrail_scan_in_any_workspace(client, engine):
    ws_a, ws_b, target_a, target_b, _fa, _fb = _two_workspace_setup(engine)
    scan_b = _make_pr_scan(engine, target_b)
    client, _uid = _login(client, engine, role=UserRole.ADMIN)  # no WorkspaceMembership row at all

    res = client.get(f"/api/pr-guardrail/{scan_b}/findings")
    assert res.status_code == 200
