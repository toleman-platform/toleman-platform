"""Tests for issue #76: false-positive learning engine.

Covers both halves of the feature:
  1. Triaging a Finding to FALSE_POSITIVE learns a FalsePositiveRule
     (app.api.findings._apply_triage -> app.core.fp_learning.learn_suppression_rule).
  2. ingest_findings auto-suppresses a NEW finding matching a learned rule's
     signature (rule_id + tool + file basename), including across two
     *different* Targets in the same Workspace (the "cross-repo" case the
     issue is about); and does NOT suppress across workspace boundaries,
     or once a rule is expired/deleted.

Plus the management API (GET/PATCH/DELETE /api/fp-rules): workspace
scoping, SECURITY_ENGINEER-gated writes, expire/reactivate/widen/delete.

Follows the same in-memory SQLite + TestClient + session-token-login
pattern used across tests/test_sla_rules.py and
tests/test_user_profile_notifications.py.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.fp_learning import learn_suppression_rule
from app.core.ingestion import ingest_findings
from app.core.security import create_session_token, hash_password
from app.models.models import (
    FalsePositiveRule,
    Finding,
    FindingState,
    FindingStateLog,
    Organization,
    Scan,
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
    from app.main import app

    def override_get_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    original_deps_engine = deps_module.engine
    deps_module.engine = engine

    c = TestClient(app)
    yield c
    app.dependency_overrides.clear()
    deps_module.engine = original_deps_engine


def _login(client, engine, role=UserRole.ADMIN, email="user@example.com", password="whatever123") -> User:
    with Session(engine) as session:
        user = User(email=email, name="Test User", password_hash=hash_password(password), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        token = create_session_token(user.id)
        client.cookies.set("toleman_session", token)
        return user


def _make_org_workspace(engine, name="WS") -> tuple[int, int]:
    with Session(engine) as session:
        org = Organization(name=f"Org-{name}")
        session.add(org)
        session.commit()
        session.refresh(org)
        workspace = Workspace(organization_id=org.id, name=name, api_key=f"key-{name}")
        session.add(workspace)
        session.commit()
        session.refresh(workspace)
        return org.id, workspace.id


def _make_target(engine, workspace_id, name="Target") -> int:
    with Session(engine) as session:
        target = Target(workspace_id=workspace_id, name=name, repo_url=f"https://github.com/a/{name}")
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


def _make_finding(engine, target_id, rule_id="python.hardcoded-secret", tool="semgrep", file_path="src/config.py", state=FindingState.OPEN) -> int:
    with Session(engine) as session:
        finding = Finding(
            target_id=target_id,
            dedup_hash=f"hash-{rule_id}-{file_path}-{target_id}",
            tool=tool,
            rule_id=rule_id,
            title="Hardcoded secret",
            file_path=file_path,
            severity=Severity.HIGH,
            state=state,
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)
        return finding.id


def _parsed_finding(rule_id="python.hardcoded-secret", tool_file_path="src/config.py", severity=Severity.HIGH, title="Hardcoded secret"):
    return {
        "rule_id": rule_id,
        "title": title,
        "description": "desc",
        "file_path": tool_file_path,
        "line_start": 1,
        "line_end": 1,
        "severity": severity,
        "cve_id": None,
        "snippet": "SECRET = 'abc123'",
    }


# ---------------------------------------------------------------------------
# learn_suppression_rule: triaging a finding to FALSE_POSITIVE learns a rule
# ---------------------------------------------------------------------------


def test_triage_to_false_positive_learns_a_rule(client, engine):
    user = _login(client, engine, role=UserRole.ADMIN)
    _, ws_id = _make_org_workspace(engine)
    target_id = _make_target(engine, ws_id)
    finding_id = _make_finding(engine, target_id, rule_id="python.hardcoded-secret", tool="semgrep", file_path="backend/app/core/config.py")

    resp = client.post(f"/api/findings/{finding_id}/triage", params={"to_state": "False Positive", "reason": "test fixture", "actor": "alice"})
    assert resp.status_code == 200

    with Session(engine) as session:
        rules = session.exec(select(FalsePositiveRule).where(FalsePositiveRule.workspace_id == ws_id)).all()
        assert len(rules) == 1
        rule = rules[0]
        assert rule.rule_id == "python.hardcoded-secret"
        assert rule.tool == "semgrep"
        # Basename only, not the full path; see FalsePositiveRule docstring.
        assert rule.file_path_pattern == "config.py"
        assert rule.source_finding_id == finding_id
        assert rule.created_by == "alice"
        assert rule.active is True
        assert rule.match_count == 0


def test_bulk_triage_to_false_positive_learns_a_rule(client, engine):
    _login(client, engine, role=UserRole.ADMIN)
    _, ws_id = _make_org_workspace(engine)
    target_id = _make_target(engine, ws_id)
    finding_id = _make_finding(engine, target_id, rule_id="gitleaks.aws-key", tool="gitleaks", file_path=".env")

    resp = client.post(
        "/api/findings/bulk-triage",
        json={"finding_ids": [finding_id], "to_state": "False Positive", "reason": "known test fixture", "actor": "bob"},
    )
    assert resp.status_code == 200
    assert resp.json()["updated"] == 1

    with Session(engine) as session:
        rule = session.exec(select(FalsePositiveRule).where(FalsePositiveRule.workspace_id == ws_id)).first()
        assert rule is not None
        assert rule.rule_id == "gitleaks.aws-key"
        assert rule.file_path_pattern == ".env"


def test_retriaging_same_shape_upserts_not_duplicates(engine):
    _, ws_id = _make_org_workspace(engine)
    target_id = _make_target(engine, ws_id)
    finding_id_1 = _make_finding(engine, target_id, rule_id="rule-a", tool="semgrep", file_path="x/config.py")
    finding_id_2 = _make_finding(engine, target_id, rule_id="rule-a", tool="semgrep", file_path="y/config.py")

    with Session(engine) as session:
        f1 = session.get(Finding, finding_id_1)
        learn_suppression_rule(session, f1, actor="system")
        session.commit()
        f2 = session.get(Finding, finding_id_2)
        learn_suppression_rule(session, f2, actor="system")
        session.commit()

    with Session(engine) as session:
        rules = session.exec(select(FalsePositiveRule).where(FalsePositiveRule.workspace_id == ws_id)).all()
        # Same rule_id + tool + basename ("config.py" both times) -> one row.
        assert len(rules) == 1
        assert rules[0].source_finding_id == finding_id_2


def test_triaging_to_other_states_does_not_learn_a_rule(client, engine):
    _login(client, engine, role=UserRole.ADMIN)
    _, ws_id = _make_org_workspace(engine)
    target_id = _make_target(engine, ws_id)
    finding_id = _make_finding(engine, target_id)

    resp = client.post(f"/api/findings/{finding_id}/triage", params={"to_state": "Accepted Risk"})
    assert resp.status_code == 200

    with Session(engine) as session:
        rules = session.exec(select(FalsePositiveRule)).all()
        assert rules == []


# ---------------------------------------------------------------------------
# ingest_findings: auto-suppression at ingestion time, including cross-repo
# ---------------------------------------------------------------------------


def test_ingestion_auto_suppresses_matching_finding_in_a_different_target_same_workspace(engine):
    """The core "cross-repo" claim: a rule learned from a FALSE_POSITIVE in
    Target A auto-suppresses a same-shaped new finding in Target B, a
    DIFFERENT repo in the same workspace."""
    _, ws_id = _make_org_workspace(engine)
    target_a = _make_target(engine, ws_id, name="repo-a")
    target_b = _make_target(engine, ws_id, name="repo-b")

    # Learn the rule from a false positive in repo A.
    fp_finding_id = _make_finding(engine, target_a, rule_id="python.hardcoded-secret", tool="semgrep", file_path="repo-a/config.py")
    with Session(engine) as session:
        finding = session.get(Finding, fp_finding_id)
        learn_suppression_rule(session, finding, actor="system")
        session.commit()

    # Ingest a same-shaped (same rule_id+tool+basename), but different-path,
    # finding into repo B; proves basename-based cross-repo generalization,
    # not literal path identity.
    with Session(engine) as session:
        target = session.get(Target, target_b)
        scan = Scan(target_id=target_b, tool="semgrep", branch="main", status="running")
        session.add(scan)
        session.commit()
        session.refresh(scan)
        ingest_findings(
            session, target, scan, "semgrep", "main",
            [_parsed_finding(rule_id="python.hardcoded-secret", tool_file_path="repo-b/nested/config.py")],
        )

    with Session(engine) as session:
        new_finding = session.exec(select(Finding).where(Finding.target_id == target_b)).first()
        assert new_finding is not None
        assert new_finding.state == FindingState.FALSE_POSITIVE
        assert "auto-suppressed" in new_finding.state_reason

        log = session.exec(select(FindingStateLog).where(FindingStateLog.finding_id == new_finding.id)).first()
        assert log is not None
        assert log.to_state == "False Positive"
        assert log.actor == "system"

        rule = session.exec(select(FalsePositiveRule).where(FalsePositiveRule.workspace_id == ws_id)).first()
        assert rule.match_count == 1
        assert rule.last_matched_at is not None


def test_ingestion_does_not_suppress_across_workspace_boundary(engine):
    _, ws_a = _make_org_workspace(engine, name="WS-A")
    _, ws_b = _make_org_workspace(engine, name="WS-B")
    target_a = _make_target(engine, ws_a, name="repo-a")
    target_b = _make_target(engine, ws_b, name="repo-b")

    fp_finding_id = _make_finding(engine, target_a, rule_id="python.hardcoded-secret", tool="semgrep", file_path="config.py")
    with Session(engine) as session:
        finding = session.get(Finding, fp_finding_id)
        learn_suppression_rule(session, finding, actor="system")
        session.commit()

    with Session(engine) as session:
        target = session.get(Target, target_b)
        scan = Scan(target_id=target_b, tool="semgrep", branch="main", status="running")
        session.add(scan)
        session.commit()
        session.refresh(scan)
        ingest_findings(session, target, scan, "semgrep", "main", [_parsed_finding(rule_id="python.hardcoded-secret", tool_file_path="config.py")])

    with Session(engine) as session:
        new_finding = session.exec(select(Finding).where(Finding.target_id == target_b)).first()
        assert new_finding.state == FindingState.OPEN  # not suppressed, different workspace


def test_expired_rule_no_longer_auto_suppresses(engine):
    _, ws_id = _make_org_workspace(engine)
    target_a = _make_target(engine, ws_id, name="repo-a")
    target_b = _make_target(engine, ws_id, name="repo-b")

    fp_finding_id = _make_finding(engine, target_a, rule_id="rule-x", tool="semgrep", file_path="config.py")
    with Session(engine) as session:
        finding = session.get(Finding, fp_finding_id)
        rule = learn_suppression_rule(session, finding, actor="system")
        session.commit()
        rule_id = rule.id

    with Session(engine) as session:
        rule = session.get(FalsePositiveRule, rule_id)
        rule.active = False
        session.add(rule)
        session.commit()

    with Session(engine) as session:
        target = session.get(Target, target_b)
        scan = Scan(target_id=target_b, tool="semgrep", branch="main", status="running")
        session.add(scan)
        session.commit()
        session.refresh(scan)
        ingest_findings(session, target, scan, "semgrep", "main", [_parsed_finding(rule_id="rule-x", tool_file_path="config.py")])

    with Session(engine) as session:
        new_finding = session.exec(select(Finding).where(Finding.target_id == target_b)).first()
        assert new_finding.state == FindingState.OPEN  # rule expired; must not fire


def test_wildcard_rule_matches_any_file_path(engine):
    _, ws_id = _make_org_workspace(engine)
    target_a = _make_target(engine, ws_id, name="repo-a")
    target_b = _make_target(engine, ws_id, name="repo-b")

    fp_finding_id = _make_finding(engine, target_a, rule_id="rule-y", tool="trivy", file_path="anything.py")
    with Session(engine) as session:
        finding = session.get(Finding, fp_finding_id)
        rule = learn_suppression_rule(session, finding, actor="system")
        rule.file_path_pattern = None  # widen to "any file"
        session.add(rule)
        session.commit()

    with Session(engine) as session:
        target = session.get(Target, target_b)
        scan = Scan(target_id=target_b, tool="trivy", branch="main", status="running")
        session.add(scan)
        session.commit()
        session.refresh(scan)
        ingest_findings(
            session, target, scan, "trivy", "main",
            [_parsed_finding(rule_id="rule-y", tool_file_path="completely/different/file.js")],
        )

    with Session(engine) as session:
        new_finding = session.exec(select(Finding).where(Finding.target_id == target_b)).first()
        assert new_finding.state == FindingState.FALSE_POSITIVE


# ---------------------------------------------------------------------------
# Management API: /api/fp-rules
# ---------------------------------------------------------------------------


def test_list_fp_rules_scoped_to_accessible_workspaces(client, engine):
    user = _login(client, engine, role=UserRole.VIEWER)
    _, ws_visible = _make_org_workspace(engine, name="visible")
    _, ws_hidden = _make_org_workspace(engine, name="hidden")
    target_visible = _make_target(engine, ws_visible)
    target_hidden = _make_target(engine, ws_hidden)

    with Session(engine) as session:
        session.add(WorkspaceMembership(user_id=user.id, workspace_id=ws_visible, role=WorkspaceRole.VIEWER))
        session.commit()

    fid1 = _make_finding(engine, target_visible, rule_id="rule-1")
    fid2 = _make_finding(engine, target_hidden, rule_id="rule-2")
    with Session(engine) as session:
        learn_suppression_rule(session, session.get(Finding, fid1), actor="system")
        learn_suppression_rule(session, session.get(Finding, fid2), actor="system")
        session.commit()

    resp = client.get("/api/fp-rules")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["rule_id"] == "rule-1"


def test_patch_fp_rule_requires_security_engineer(client, engine):
    user = _login(client, engine, role=UserRole.DEVELOPER)
    _, ws_id = _make_org_workspace(engine)
    target_id = _make_target(engine, ws_id)
    with Session(engine) as session:
        session.add(WorkspaceMembership(user_id=user.id, workspace_id=ws_id, role=WorkspaceRole.DEVELOPER))
        session.commit()

    fid = _make_finding(engine, target_id)
    with Session(engine) as session:
        rule = learn_suppression_rule(session, session.get(Finding, fid), actor="system")
        session.commit()
        rule_id = rule.id

    # Developer (below security_engineer) is rejected.
    resp = client.patch(f"/api/fp-rules/{rule_id}", json={"active": False})
    assert resp.status_code == 403

    with Session(engine) as session:
        session.exec(select(WorkspaceMembership)).first()
        membership = session.exec(select(WorkspaceMembership).where(WorkspaceMembership.user_id == user.id)).first()
        membership.role = WorkspaceRole.SECURITY_ENGINEER
        session.add(membership)
        session.commit()

    resp = client.patch(f"/api/fp-rules/{rule_id}", json={"active": False})
    assert resp.status_code == 200
    assert resp.json()["active"] is False


def test_patch_fp_rule_can_widen_and_reactivate(client, engine):
    _login(client, engine, role=UserRole.ADMIN)  # admin bypasses workspace-role gate
    _, ws_id = _make_org_workspace(engine)
    target_id = _make_target(engine, ws_id)
    fid = _make_finding(engine, target_id, file_path="specific/path/config.py")
    with Session(engine) as session:
        rule = learn_suppression_rule(session, session.get(Finding, fid), actor="system")
        session.commit()
        rule_id = rule.id
        assert rule.file_path_pattern == "config.py"

    resp = client.patch(f"/api/fp-rules/{rule_id}", json={"clear_file_path_pattern": True})
    assert resp.status_code == 200
    assert resp.json()["file_path_pattern"] is None

    resp = client.patch(f"/api/fp-rules/{rule_id}", json={"active": False})
    assert resp.status_code == 200
    resp = client.patch(f"/api/fp-rules/{rule_id}", json={"active": True})
    assert resp.status_code == 200
    assert resp.json()["active"] is True


def test_delete_fp_rule_removes_it(client, engine):
    _login(client, engine, role=UserRole.ADMIN)
    _, ws_id = _make_org_workspace(engine)
    target_id = _make_target(engine, ws_id)
    fid = _make_finding(engine, target_id)
    with Session(engine) as session:
        rule = learn_suppression_rule(session, session.get(Finding, fid), actor="system")
        session.commit()
        rule_id = rule.id

    resp = client.delete(f"/api/fp-rules/{rule_id}")
    assert resp.status_code == 200

    with Session(engine) as session:
        assert session.get(FalsePositiveRule, rule_id) is None


def test_fp_rule_stats_endpoint(client, engine):
    _login(client, engine, role=UserRole.ADMIN)
    _, ws_id = _make_org_workspace(engine)
    target_a = _make_target(engine, ws_id, name="repo-a")
    target_b = _make_target(engine, ws_id, name="repo-b")
    fid = _make_finding(engine, target_a, rule_id="rule-z", file_path="z.py")
    with Session(engine) as session:
        learn_suppression_rule(session, session.get(Finding, fid), actor="system")
        session.commit()

    with Session(engine) as session:
        target = session.get(Target, target_b)
        scan = Scan(target_id=target_b, tool="semgrep", branch="main", status="running")
        session.add(scan)
        session.commit()
        session.refresh(scan)
        ingest_findings(session, target, scan, "semgrep", "main", [_parsed_finding(rule_id="rule-z", tool_file_path="z.py")])

    resp = client.get(f"/api/fp-rules/stats?workspace_id={ws_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["active_rules"] == 1
    assert body["total_matches"] == 1
