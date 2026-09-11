"""Tests for the ignore-request/approval workflow on persisted
PRGuardrailFinding rows, and the Severity-enum comment-rendering bug fix."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
import app.api.pr_guardrail as pr_guardrail_api
from app.api.deps import get_session
import app.core.pr_guardrail_executor as pr_guardrail_executor
from app.core.pr_guardrail_executor import _severity_str, recompute_pr_scan_status, render_comment
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    Finding,
    FindingState,
    FindingStateLog,
    IgnoreStatus,
    Organization,
    PRGuardrailFinding,
    PRGuardrailScan,
    PRGuardrailStatus,
    Severity,
    Target,
    User,
    UserRole,
    Workspace,
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
    email = email or f"{role.value}@example.com"
    with Session(engine) as session:
        user = User(email=email, name="Test", password_hash=hash_password("whatever123"), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return client


def _make_target(engine) -> int:
    with Session(engine) as session:
        org = Organization(name="org")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws", api_key="key")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        target = Target(workspace_id=ws.id, name="repo", repo_url="https://github.com/acme/repo")
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


def _make_blocked_scan(engine, target_id: int, severities: list[str]) -> tuple[int, list[int]]:
    with Session(engine) as session:
        scan = PRGuardrailScan(target_id=target_id, pr_number=7, branch="feature", status=PRGuardrailStatus.BLOCKED)
        session.add(scan)
        session.commit()
        session.refresh(scan)

        finding_ids = []
        for i, sev in enumerate(severities):
            finding = PRGuardrailFinding(
                pr_scan_id=scan.id, tool="semgrep", rule_id=f"rule-{i}",
                title=f"finding {i}", file_path="a.py", line_start=10, severity=sev,
            )
            session.add(finding)
            session.commit()
            session.refresh(finding)
            finding_ids.append(finding.id)
        return scan.id, finding_ids


def _make_pr_scan_and_finding(engine) -> tuple[int, int]:
    with Session(engine) as session:
        scan = PRGuardrailScan(target_id=1, pr_number=7, branch="feature", status=PRGuardrailStatus.BLOCKED)
        session.add(scan)
        session.commit()
        session.refresh(scan)

        finding = PRGuardrailFinding(
            pr_scan_id=scan.id, tool="semgrep", rule_id="use-of-md5",
            title="weak crypto", file_path="a.py", line_start=10, severity="High",
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)
        return scan.id, finding.id


def test_severity_str_unwraps_enum_value():
    assert _severity_str(Severity.MEDIUM) == "Medium"
    assert _severity_str("Medium") == "Medium"


def test_render_comment_never_shows_raw_enum_repr():
    scan_id, finding_id = 1, 1
    finding = PRGuardrailFinding(
        id=1, pr_scan_id=1, tool="semgrep", rule_id="r", title="t", file_path="a.py",
        line_start=1, severity=_severity_str(Severity.MEDIUM),
    )
    body = render_comment([finding], [], PRGuardrailStatus.BLOCKED, target_id=1, pr_scan_id=scan_id)
    assert "Severity." not in body
    assert "| Medium |" in body


def test_render_comment_includes_ref_and_ignore_links():
    finding = PRGuardrailFinding(
        id=42, pr_scan_id=1, tool="semgrep", rule_id="r", title="t", file_path="a.py",
        line_start=1, severity="High",
    )
    body = render_comment([finding], [], PRGuardrailStatus.BLOCKED, target_id=5, pr_scan_id=9)
    assert "finding-42" in body
    # The ignore link points at the dedicated /ignore-request page (not
    # /pr-history): that page carries the full dashboard layout and several
    # fetches unrelated to this one action, slow to clear before the click
    # shows any result at all. /ignore-request/{pr_scan_id}/{finding_id}
    # does the one API call it needs and nothing else.
    assert "/ignore-request/9/42" in body


def test_render_comment_includes_new_endpoints_section():
    body = render_comment([], [{"method": "POST", "route": "/admin/reset", "file": "app.py", "line": 12}], PRGuardrailStatus.PASSED, target_id=1, pr_scan_id=1)
    assert "new API endpoint" in body
    assert "/admin/reset" in body


def test_developer_can_request_ignore(client, engine):
    client = _login(client, engine, role=UserRole.DEVELOPER)
    _, finding_id = _make_pr_scan_and_finding(engine)

    res = client.post(f"/api/pr-guardrail/findings/{finding_id}/request-ignore", json={"reason": "false positive, test fixture"})
    assert res.status_code == 200
    body = res.json()
    assert body["ignore_status"] == "requested"
    assert body["ignore_requested_by"] == "developer@example.com"


def test_request_ignore_requires_reason(client, engine):
    client = _login(client, engine, role=UserRole.DEVELOPER)
    _, finding_id = _make_pr_scan_and_finding(engine)

    res = client.post(f"/api/pr-guardrail/findings/{finding_id}/request-ignore", json={"reason": ""})
    assert res.status_code == 400


def test_regular_user_cannot_approve_ignore(client, engine):
    client = _login(client, engine, role=UserRole.USER)
    _, finding_id = _make_pr_scan_and_finding(engine)

    res = client.post(f"/api/pr-guardrail/findings/{finding_id}/approve-ignore")
    assert res.status_code == 403


def test_security_engineer_can_approve_ignore(client, engine):
    _, finding_id = _make_pr_scan_and_finding(engine)
    client = _login(client, engine, role=UserRole.SECURITY_ENGINEER)

    res = client.post(f"/api/pr-guardrail/findings/{finding_id}/approve-ignore")
    assert res.status_code == 200
    body = res.json()
    assert body["ignore_status"] == "approved"
    assert body["ignore_reviewed_by"] == "security_engineer@example.com"


def test_security_engineer_can_reject_ignore(client, engine):
    _, finding_id = _make_pr_scan_and_finding(engine)
    client = _login(client, engine, role=UserRole.SECURITY_ENGINEER)

    res = client.post(f"/api/pr-guardrail/findings/{finding_id}/reject-ignore")
    assert res.status_code == 200
    assert res.json()["ignore_status"] == "rejected"


def test_admin_can_also_approve_ignore(client, engine):
    _, finding_id = _make_pr_scan_and_finding(engine)
    client = _login(client, engine, role=UserRole.ADMIN)

    res = client.post(f"/api/pr-guardrail/findings/{finding_id}/approve-ignore")
    assert res.status_code == 200


def test_pending_queue_only_shows_requested(client, engine):
    _, finding_id = _make_pr_scan_and_finding(engine)
    dev_client = _login(client, engine, role=UserRole.DEVELOPER)
    dev_client.post(f"/api/pr-guardrail/findings/{finding_id}/request-ignore", json={"reason": "fp"})

    sec_client = _login(client, engine, role=UserRole.SECURITY_ENGINEER, email="sec2@example.com")
    res = sec_client.get("/api/pr-guardrail/ignore-requests/pending")
    assert res.status_code == 200
    ids = [f["id"] for f in res.json()]
    assert finding_id in ids


def test_history_shows_approved_and_rejected_but_not_pending(client, engine):
    _, approved_id = _make_pr_scan_and_finding(engine)
    _, rejected_id = _make_pr_scan_and_finding(engine)
    _, still_pending_id = _make_pr_scan_and_finding(engine)

    # _login re-authenticates the same shared TestClient in place, so the
    # dev's request-ignore call must happen before the final sec_client
    # login that the closing GET below relies on (same ordering as
    # test_pending_queue_only_shows_requested above).
    dev_client = _login(client, engine, role=UserRole.DEVELOPER, email="dev2@example.com")
    dev_client.post(f"/api/pr-guardrail/findings/{still_pending_id}/request-ignore", json={"reason": "fp"})

    sec_client = _login(client, engine, role=UserRole.SECURITY_ENGINEER)
    sec_client.post(f"/api/pr-guardrail/findings/{approved_id}/approve-ignore")
    sec_client.post(f"/api/pr-guardrail/findings/{rejected_id}/reject-ignore")

    res = sec_client.get("/api/pr-guardrail/ignore-requests/history")
    assert res.status_code == 200
    body = res.json()
    ids = {f["id"] for f in body}
    assert ids == {approved_id, rejected_id}
    statuses = {f["id"]: f["ignore_status"] for f in body}
    assert statuses[approved_id] == "approved"
    assert statuses[rejected_id] == "rejected"


def test_history_most_recently_reviewed_first(client, engine):
    _, first_id = _make_pr_scan_and_finding(engine)
    _, second_id = _make_pr_scan_and_finding(engine)
    sec_client = _login(client, engine, role=UserRole.SECURITY_ENGINEER)
    sec_client.post(f"/api/pr-guardrail/findings/{first_id}/approve-ignore")
    sec_client.post(f"/api/pr-guardrail/findings/{second_id}/approve-ignore")

    res = sec_client.get("/api/pr-guardrail/ignore-requests/history")
    assert res.status_code == 200
    ids_in_order = [f["id"] for f in res.json()]
    assert ids_in_order[0] == second_id
    assert ids_in_order[1] == first_id


def test_only_security_reviewers_can_read_history(client, engine):
    client = _login(client, engine, role=UserRole.USER)
    res = client.get("/api/pr-guardrail/ignore-requests/history")
    assert res.status_code == 403


def test_list_findings_for_a_scan(client, engine):
    # ADMIN bypasses workspace scoping (accessible_workspace_ids returns
    # None); this test's scan targets target_id=1, which doesn't exist as
    # a real row, so a non-admin caller would 404 on the workspace check.
    client = _login(client, engine, role=UserRole.ADMIN)
    scan_id, finding_id = _make_pr_scan_and_finding(engine)

    res = client.get(f"/api/pr-guardrail/{scan_id}/findings")
    assert res.status_code == 200
    ids = [f["id"] for f in res.json()]
    assert finding_id in ids


# ---------------------------------------------------------------------------
# #112: approving every blocking finding must unblock the scan, not just the
# finding row; previously the whole-PR `override` was the only way out.
# ---------------------------------------------------------------------------


def _patch_github(monkeypatch):
    """Approving the last blocking finding tries to update GitHub's commit
    status, stub both calls so these tests never touch the network, same
    boundary-mocking approach as test_celery_offload.py's eager-mode tests."""
    monkeypatch.setattr(
        pr_guardrail_executor,
        "github_get",
        lambda *a, **k: type("R", (), {"raise_for_status": lambda self: None, "json": lambda self: {"head": {"sha": "abc123"}}})(),
    )
    calls = []
    monkeypatch.setattr(pr_guardrail_executor, "set_commit_status", lambda *a, **k: calls.append(a))
    return calls


def test_approving_sole_blocking_finding_unblocks_scan(engine, monkeypatch):
    commit_status_calls = _patch_github(monkeypatch)
    target_id = _make_target(engine)
    scan_id, (finding_id,) = _make_blocked_scan(engine, target_id, ["High"])

    with Session(engine) as session:
        finding = session.get(PRGuardrailFinding, finding_id)
        finding.ignore_status = IgnoreStatus.APPROVED
        session.add(finding)
        session.commit()

        scan = session.get(PRGuardrailScan, scan_id)
        recompute_pr_scan_status(session, scan)

    with Session(engine) as session:
        scan = session.get(PRGuardrailScan, scan_id)
        assert scan.status == PRGuardrailStatus.PASSED
    assert len(commit_status_calls) == 1
    assert commit_status_calls[0][3] == "success"


def test_approving_one_of_two_blocking_findings_leaves_scan_blocked(engine, monkeypatch):
    _patch_github(monkeypatch)
    target_id = _make_target(engine)
    scan_id, (fid_a, fid_b) = _make_blocked_scan(engine, target_id, ["High", "Critical"])

    with Session(engine) as session:
        finding = session.get(PRGuardrailFinding, fid_a)
        finding.ignore_status = IgnoreStatus.APPROVED
        session.add(finding)
        session.commit()

        scan = session.get(PRGuardrailScan, scan_id)
        recompute_pr_scan_status(session, scan)

    with Session(engine) as session:
        scan = session.get(PRGuardrailScan, scan_id)
        assert scan.status == PRGuardrailStatus.BLOCKED  # fid_b (Critical) still open


def test_recompute_is_noop_for_already_overridden_scan(engine, monkeypatch):
    commit_status_calls = _patch_github(monkeypatch)
    target_id = _make_target(engine)
    scan_id, (finding_id,) = _make_blocked_scan(engine, target_id, ["High"])

    with Session(engine) as session:
        scan = session.get(PRGuardrailScan, scan_id)
        scan.status = PRGuardrailStatus.OVERRIDDEN
        session.add(scan)
        session.commit()

        finding = session.get(PRGuardrailFinding, finding_id)
        finding.ignore_status = IgnoreStatus.APPROVED
        session.add(finding)
        session.commit()

        recompute_pr_scan_status(session, scan)

    with Session(engine) as session:
        scan = session.get(PRGuardrailScan, scan_id)
        assert scan.status == PRGuardrailStatus.OVERRIDDEN  # untouched, not flipped to PASSED
    assert commit_status_calls == []


def test_approve_ignore_endpoint_unblocks_pr_end_to_end(client, engine, monkeypatch):
    """Full HTTP path: approve-ignore on the only blocking finding must flip
    the scan itself, not just the finding row (the actual #112 bug)."""
    _patch_github(monkeypatch)
    target_id = _make_target(engine)
    scan_id, (finding_id,) = _make_blocked_scan(engine, target_id, ["Critical"])
    client = _login(client, engine, role=UserRole.SECURITY_ENGINEER)

    res = client.post(f"/api/pr-guardrail/findings/{finding_id}/approve-ignore")
    assert res.status_code == 200

    with Session(engine) as session:
        scan = session.get(PRGuardrailScan, scan_id)
        assert scan.status == PRGuardrailStatus.PASSED


def _make_main_finding(engine, target_id: int, state=FindingState.OPEN, branch="main", **overrides) -> int:
    fields = dict(
        target_id=target_id, dedup_hash="whatever", tool="semgrep", rule_id="rule-0",
        title="weak crypto", file_path="a.py", line_start=10, severity=Severity.CRITICAL,
        branch=branch, state=state,
    )
    fields.update(overrides)
    with Session(engine) as session:
        finding = Finding(**fields)
        session.add(finding)
        session.commit()
        session.refresh(finding)
        return finding.id


def test_approving_ignore_immediately_accepts_the_matching_main_finding(client, engine, monkeypatch):
    """#... : a reviewer approving a PR Guardrail ignore request is a real
    triage decision. If the same vulnerability already exists as a
    main-table Finding (matched on tool/rule_id/file_path/line_start on the
    target's default branch), it must flip to Accepted Risk right away --
    not sit Open until whatever the next full scan happens to be."""
    _patch_github(monkeypatch)
    target_id = _make_target(engine)
    _, (finding_id,) = _make_blocked_scan(engine, target_id, ["Critical"])
    main_finding_id = _make_main_finding(engine, target_id)
    client = _login(client, engine, role=UserRole.SECURITY_ENGINEER)

    res = client.post(f"/api/pr-guardrail/findings/{finding_id}/approve-ignore")
    assert res.status_code == 200

    with Session(engine) as session:
        main_finding = session.get(Finding, main_finding_id)
        assert main_finding.state == FindingState.ACCEPTED_RISK
        logs = session.exec(select(FindingStateLog).where(FindingStateLog.finding_id == main_finding_id)).all()
        assert len(logs) == 1
        assert logs[0].from_state == FindingState.OPEN
        assert logs[0].to_state == FindingState.ACCEPTED_RISK
        assert logs[0].actor == "security_engineer@example.com"


def test_approving_ignore_patches_the_pr_comment_immediately(client, engine, monkeypatch):
    """#401: approving must not wait for a rescan to reflect on GitHub --
    update_finding_status_in_pr_comment is called with the exact finding
    that was just approved, so the existing comment can be patched in
    place."""
    _patch_github(monkeypatch)
    calls = []
    monkeypatch.setattr(
        pr_guardrail_api,
        "update_finding_status_in_pr_comment",
        lambda session, target, pr_number, finding: calls.append((target.id, pr_number, finding.id)),
    )
    target_id = _make_target(engine)
    scan_id, (finding_id,) = _make_blocked_scan(engine, target_id, ["Critical"])
    with Session(engine) as session:
        pr_number = session.get(PRGuardrailScan, scan_id).pr_number
    client = _login(client, engine, role=UserRole.SECURITY_ENGINEER)

    res = client.post(f"/api/pr-guardrail/findings/{finding_id}/approve-ignore")
    assert res.status_code == 200
    assert calls == [(target_id, pr_number, finding_id)]


def test_approving_ignore_does_not_touch_a_finding_on_a_non_default_branch(client, engine, monkeypatch):
    _patch_github(monkeypatch)
    target_id = _make_target(engine)  # default_branch defaults to "main"
    _, (finding_id,) = _make_blocked_scan(engine, target_id, ["Critical"])
    other_branch_finding_id = _make_main_finding(engine, target_id, branch="some-other-branch")
    client = _login(client, engine, role=UserRole.SECURITY_ENGINEER)

    res = client.post(f"/api/pr-guardrail/findings/{finding_id}/approve-ignore")
    assert res.status_code == 200

    with Session(engine) as session:
        assert session.get(Finding, other_branch_finding_id).state == FindingState.OPEN


def test_approving_ignore_does_not_reopen_an_already_resolved_finding(client, engine, monkeypatch):
    _patch_github(monkeypatch)
    target_id = _make_target(engine)
    _, (finding_id,) = _make_blocked_scan(engine, target_id, ["Critical"])
    resolved_id = _make_main_finding(engine, target_id, state=FindingState.FALSE_POSITIVE)
    client = _login(client, engine, role=UserRole.SECURITY_ENGINEER)

    res = client.post(f"/api/pr-guardrail/findings/{finding_id}/approve-ignore")
    assert res.status_code == 200

    with Session(engine) as session:
        # Left exactly as a human already triaged it, not silently
        # reclassified as Accepted Risk underneath them.
        assert session.get(Finding, resolved_id).state == FindingState.FALSE_POSITIVE


# ---------------------------------------------------------------------------
# revoke-ignore: undoes approve-ignore -- finding back to "none", a synced
# main Finding back to REOPENED, the PR comment's approved row back to a
# live "request ignore" link (unless the PR is already merged), and the scan
# re-evaluated in case this was the one finding keeping it unblocked.
# ---------------------------------------------------------------------------


def test_regular_user_cannot_revoke_ignore(client, engine, monkeypatch):
    _patch_github(monkeypatch)
    target_id = _make_target(engine)
    _, (finding_id,) = _make_blocked_scan(engine, target_id, ["Critical"])
    sec_client = _login(client, engine, role=UserRole.SECURITY_ENGINEER)
    sec_client.post(f"/api/pr-guardrail/findings/{finding_id}/approve-ignore")

    user_client = _login(client, engine, role=UserRole.USER, email="user2@example.com")
    res = user_client.post(f"/api/pr-guardrail/findings/{finding_id}/revoke-ignore")
    assert res.status_code == 403


def test_revoke_ignore_requires_finding_to_be_currently_approved(client, engine):
    _, finding_id = _make_pr_scan_and_finding(engine)
    client = _login(client, engine, role=UserRole.SECURITY_ENGINEER)

    res = client.post(f"/api/pr-guardrail/findings/{finding_id}/revoke-ignore")
    assert res.status_code == 400


def test_security_engineer_can_revoke_ignore(client, engine, monkeypatch):
    _patch_github(monkeypatch)
    target_id = _make_target(engine)
    _, (finding_id,) = _make_blocked_scan(engine, target_id, ["Critical"])
    client = _login(client, engine, role=UserRole.SECURITY_ENGINEER)
    client.post(f"/api/pr-guardrail/findings/{finding_id}/approve-ignore")

    res = client.post(f"/api/pr-guardrail/findings/{finding_id}/revoke-ignore")
    assert res.status_code == 200
    body = res.json()
    assert body["ignore_status"] == "none"
    assert body["ignore_requested_by"] == ""
    assert body["ignore_requested_reason"] == ""
    assert body["ignore_reviewed_by"] == ""
    assert body["ignore_reviewed_at"] is None


def test_revoking_ignore_reopens_the_matching_main_finding(client, engine, monkeypatch):
    _patch_github(monkeypatch)
    target_id = _make_target(engine)
    _, (finding_id,) = _make_blocked_scan(engine, target_id, ["Critical"])
    main_finding_id = _make_main_finding(engine, target_id)
    client = _login(client, engine, role=UserRole.SECURITY_ENGINEER)
    client.post(f"/api/pr-guardrail/findings/{finding_id}/approve-ignore")

    with Session(engine) as session:
        assert session.get(Finding, main_finding_id).state == FindingState.ACCEPTED_RISK

    res = client.post(f"/api/pr-guardrail/findings/{finding_id}/revoke-ignore")
    assert res.status_code == 200

    with Session(engine) as session:
        main_finding = session.get(Finding, main_finding_id)
        assert main_finding.state == FindingState.REOPENED
        logs = session.exec(
            select(FindingStateLog).where(FindingStateLog.finding_id == main_finding_id).order_by(FindingStateLog.id)
        ).all()
        assert len(logs) == 2
        assert logs[1].from_state == FindingState.ACCEPTED_RISK
        assert logs[1].to_state == FindingState.REOPENED
        assert logs[1].actor == "security_engineer@example.com"


def test_revoking_ignore_does_not_touch_a_finding_resolved_some_other_way(client, engine, monkeypatch):
    """A Finding that was ACCEPTED_RISK via this exact approval and then
    separately resolved another way (e.g. an admin later marked it a false
    positive) must not be silently reopened just because the original
    approval is revoked."""
    _patch_github(monkeypatch)
    target_id = _make_target(engine)
    _, (finding_id,) = _make_blocked_scan(engine, target_id, ["Critical"])
    main_finding_id = _make_main_finding(engine, target_id)
    client = _login(client, engine, role=UserRole.SECURITY_ENGINEER)
    client.post(f"/api/pr-guardrail/findings/{finding_id}/approve-ignore")

    with Session(engine) as session:
        main_finding = session.get(Finding, main_finding_id)
        main_finding.state = FindingState.FALSE_POSITIVE
        session.add(main_finding)
        session.commit()

    res = client.post(f"/api/pr-guardrail/findings/{finding_id}/revoke-ignore")
    assert res.status_code == 200

    with Session(engine) as session:
        assert session.get(Finding, main_finding_id).state == FindingState.FALSE_POSITIVE


def test_revoking_ignore_patches_the_pr_comment_when_not_merged(client, engine, monkeypatch):
    _patch_github(monkeypatch)
    calls = []
    monkeypatch.setattr(
        pr_guardrail_api,
        "revoke_finding_status_in_pr_comment",
        lambda session, target, pr_number, finding: calls.append((target.id, pr_number, finding.id)),
    )
    target_id = _make_target(engine)
    scan_id, (finding_id,) = _make_blocked_scan(engine, target_id, ["Critical"])
    with Session(engine) as session:
        pr_number = session.get(PRGuardrailScan, scan_id).pr_number
    client = _login(client, engine, role=UserRole.SECURITY_ENGINEER)
    client.post(f"/api/pr-guardrail/findings/{finding_id}/approve-ignore")

    res = client.post(f"/api/pr-guardrail/findings/{finding_id}/revoke-ignore")
    assert res.status_code == 200
    assert calls == [(target_id, pr_number, finding_id)]


def test_revoking_the_sole_approval_reblocks_a_passed_scan(engine, monkeypatch):
    """The mirror of #112 (test_approving_sole_blocking_finding_unblocks_scan
    above): revoking the one approval that got a scan unblocked must put it
    back to BLOCKED, not leave it reading PASSED (and GitHub green) on a PR
    that is, once again, actually blocking."""
    commit_status_calls = _patch_github(monkeypatch)
    target_id = _make_target(engine)
    scan_id, (finding_id,) = _make_blocked_scan(engine, target_id, ["High"])

    with Session(engine) as session:
        finding = session.get(PRGuardrailFinding, finding_id)
        finding.ignore_status = IgnoreStatus.APPROVED
        session.add(finding)
        session.commit()
        scan = session.get(PRGuardrailScan, scan_id)
        recompute_pr_scan_status(session, scan)

    with Session(engine) as session:
        assert session.get(PRGuardrailScan, scan_id).status == PRGuardrailStatus.PASSED

    with Session(engine) as session:
        finding = session.get(PRGuardrailFinding, finding_id)
        finding.ignore_status = IgnoreStatus.NONE
        session.add(finding)
        session.commit()
        scan = session.get(PRGuardrailScan, scan_id)
        recompute_pr_scan_status(session, scan)

    with Session(engine) as session:
        assert session.get(PRGuardrailScan, scan_id).status == PRGuardrailStatus.BLOCKED
    assert commit_status_calls[-1][3] == "failure"


def test_revoke_ignore_endpoint_reblocks_pr_end_to_end(client, engine, monkeypatch):
    _patch_github(monkeypatch)
    target_id = _make_target(engine)
    scan_id, (finding_id,) = _make_blocked_scan(engine, target_id, ["Critical"])
    client = _login(client, engine, role=UserRole.SECURITY_ENGINEER)
    client.post(f"/api/pr-guardrail/findings/{finding_id}/approve-ignore")

    with Session(engine) as session:
        assert session.get(PRGuardrailScan, scan_id).status == PRGuardrailStatus.PASSED

    res = client.post(f"/api/pr-guardrail/findings/{finding_id}/revoke-ignore")
    assert res.status_code == 200

    with Session(engine) as session:
        assert session.get(PRGuardrailScan, scan_id).status == PRGuardrailStatus.BLOCKED
