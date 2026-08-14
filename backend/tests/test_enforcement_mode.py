"""Tests for issue #62 (PR Guardrail enforcement mode): the
target -> group(s) -> workspace -> "block" default resolution
(app.core.enforcement.resolve_enforcement_mode), the PATCH endpoints on
Target/Group/Workspace that set it, and how execute_pr_guardrail_scan wires
it in -- "disabled" skips the scan entirely, "alert" still scans/comments
but posts a non-blocking commit status even when real blocking findings
exist, "block" is unchanged.

Follows the same in-memory SQLite + TestClient + session-token-login pattern
used across tests/test_groups.py and tests/test_pr_guardrail_ignore.py.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.enforcement import DEFAULT_ENFORCEMENT_MODE, resolve_enforcement_mode, resolve_enforcement_mode_with_source
from app.core import pr_guardrail_executor
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    Group,
    Organization,
    PRGuardrailStatus,
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
    client.cookies.set("rikugan_session", token)
    return client, uid


def _make_workspace(engine, name="ws", enforcement_mode=None) -> int:
    with Session(engine) as session:
        org = Organization(name=f"org-{name}")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name=name, api_key=f"key-{name}", enforcement_mode=enforcement_mode)
        session.add(ws)
        session.commit()
        session.refresh(ws)
        return ws.id


def _make_target(engine, workspace_id, enforcement_mode=None) -> int:
    with Session(engine) as session:
        t = Target(
            workspace_id=workspace_id,
            name="repo",
            repo_url="https://github.com/acme/repo",
            enforcement_mode=enforcement_mode,
        )
        session.add(t)
        session.commit()
        session.refresh(t)
        return t.id


def _make_group(engine, workspace_id, enforcement_mode=None, name="g") -> int:
    with Session(engine) as session:
        g = Group(workspace_id=workspace_id, name=name, enforcement_mode=enforcement_mode)
        session.add(g)
        session.commit()
        session.refresh(g)
        return g.id


def _assign_group(engine, target_id, group_id):
    with Session(engine) as session:
        session.add(TargetGroup(target_id=target_id, group_id=group_id))
        session.commit()


def _membership(engine, user_id, workspace_id, role):
    with Session(engine) as session:
        session.add(WorkspaceMembership(user_id=user_id, workspace_id=workspace_id, role=role))
        session.commit()


# ---------------------------------------------------------------------------
# Resolver unit tests
# ---------------------------------------------------------------------------

def test_default_is_block_when_nothing_set(engine):
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    with Session(engine) as session:
        target = session.get(Target, target_id)
        assert resolve_enforcement_mode(session, target) == "block"
        assert resolve_enforcement_mode(session, target) == DEFAULT_ENFORCEMENT_MODE


def test_workspace_setting_used_when_nothing_more_specific(engine):
    ws_id = _make_workspace(engine, enforcement_mode="alert")
    target_id = _make_target(engine, ws_id)
    with Session(engine) as session:
        target = session.get(Target, target_id)
        assert resolve_enforcement_mode(session, target) == "alert"


def test_group_setting_wins_over_workspace(engine):
    ws_id = _make_workspace(engine, enforcement_mode="block")
    target_id = _make_target(engine, ws_id)
    group_id = _make_group(engine, ws_id, enforcement_mode="disabled")
    _assign_group(engine, target_id, group_id)
    with Session(engine) as session:
        target = session.get(Target, target_id)
        assert resolve_enforcement_mode(session, target) == "disabled"


def test_target_setting_wins_over_group_and_workspace(engine):
    ws_id = _make_workspace(engine, enforcement_mode="block")
    target_id = _make_target(engine, ws_id, enforcement_mode="alert")
    group_id = _make_group(engine, ws_id, enforcement_mode="disabled")
    _assign_group(engine, target_id, group_id)
    with Session(engine) as session:
        target = session.get(Target, target_id)
        assert resolve_enforcement_mode(session, target) == "alert"


def test_conflicting_multi_group_resolves_most_restrictive(engine):
    """A target with two groups, one set to 'disabled' and one set to
    'block', must resolve to 'block' -- fail closed, not silently pick
    whichever group happened to be joined last."""
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    lenient_group = _make_group(engine, ws_id, enforcement_mode="disabled", name="lenient")
    strict_group = _make_group(engine, ws_id, enforcement_mode="block", name="strict")
    _assign_group(engine, target_id, lenient_group)
    _assign_group(engine, target_id, strict_group)
    with Session(engine) as session:
        target = session.get(Target, target_id)
        assert resolve_enforcement_mode(session, target) == "block"


def test_conflicting_multi_group_alert_vs_disabled_resolves_alert(engine):
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    g1 = _make_group(engine, ws_id, enforcement_mode="disabled", name="g1")
    g2 = _make_group(engine, ws_id, enforcement_mode="alert", name="g2")
    _assign_group(engine, target_id, g1)
    _assign_group(engine, target_id, g2)
    with Session(engine) as session:
        target = session.get(Target, target_id)
        assert resolve_enforcement_mode(session, target) == "alert"


def test_resolve_with_source_reports_where_effective_mode_came_from(engine):
    ws_id = _make_workspace(engine, enforcement_mode="alert")
    target_id = _make_target(engine, ws_id)
    with Session(engine) as session:
        target = session.get(Target, target_id)
        mode, source = resolve_enforcement_mode_with_source(session, target)
        assert mode == "alert"
        assert source == "workspace"

    with Session(engine) as session:
        target = session.get(Target, target_id)
        target.enforcement_mode = "block"
        session.add(target)
        session.commit()
        session.refresh(target)
        mode, source = resolve_enforcement_mode_with_source(session, target)
        assert mode == "block"
        assert source == "target"


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------

def test_patch_target_sets_enforcement_mode(client, engine):
    client, uid = _login(client, engine)
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _membership(engine, uid, ws_id, WorkspaceRole.DEVELOPER)

    res = client.patch(f"/api/targets/{target_id}", json={"enforcement_mode": "alert"})
    assert res.status_code == 200, res.text
    assert res.json()["enforcement_mode"] == "alert"

    detail = client.get(f"/api/targets/{target_id}")
    assert detail.status_code == 200
    assert detail.json()["effective_enforcement_mode"] == "alert"
    assert detail.json()["enforcement_mode_source"] == "target"


def test_patch_target_rejects_invalid_enforcement_mode(client, engine):
    client, uid = _login(client, engine)
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _membership(engine, uid, ws_id, WorkspaceRole.DEVELOPER)

    res = client.patch(f"/api/targets/{target_id}", json={"enforcement_mode": "yolo"})
    assert res.status_code == 422


def test_patch_group_sets_enforcement_mode(client, engine):
    client, uid = _login(client, engine)
    ws_id = _make_workspace(engine)
    group_id = _make_group(engine, ws_id)
    _membership(engine, uid, ws_id, WorkspaceRole.DEVELOPER)

    res = client.patch(f"/api/groups/{group_id}", json={"enforcement_mode": "disabled"})
    assert res.status_code == 200, res.text
    assert res.json()["enforcement_mode"] == "disabled"


def test_patch_workspace_sets_enforcement_mode(client, engine):
    client, uid = _login(client, engine)
    ws_id = _make_workspace(engine)
    _membership(engine, uid, ws_id, WorkspaceRole.DEVELOPER)

    res = client.patch(f"/api/workspaces/{ws_id}", json={"enforcement_mode": "alert"})
    assert res.status_code == 200, res.text
    assert res.json()["enforcement_mode"] == "alert"


def test_patch_target_clears_override_with_explicit_null(client, engine):
    client, uid = _login(client, engine)
    ws_id = _make_workspace(engine, enforcement_mode="alert")
    target_id = _make_target(engine, ws_id, enforcement_mode="block")
    _membership(engine, uid, ws_id, WorkspaceRole.DEVELOPER)

    res = client.patch(f"/api/targets/{target_id}", json={"enforcement_mode": None})
    assert res.status_code == 200, res.text
    assert res.json()["enforcement_mode"] is None

    detail = client.get(f"/api/targets/{target_id}")
    assert detail.json()["effective_enforcement_mode"] == "alert"
    assert detail.json()["enforcement_mode_source"] == "workspace"


# ---------------------------------------------------------------------------
# execute_pr_guardrail_scan wiring
# ---------------------------------------------------------------------------

def test_disabled_mode_skips_scan_entirely(engine, monkeypatch):
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id, enforcement_mode="disabled")

    def _boom_github_get(*a, **k):
        raise AssertionError("github_get should not be called when enforcement_mode=disabled")

    monkeypatch.setattr(pr_guardrail_executor, "github_get", _boom_github_get)

    with Session(engine) as session:
        target = session.get(Target, target_id)
        result = pr_guardrail_executor.execute_pr_guardrail_scan(target, 1, session)

    assert result["status"] == "disabled"
    assert result["pr_scan_id"] is None

    with Session(engine) as session:
        from app.models.models import PRGuardrailScan
        assert session.exec(select(PRGuardrailScan)).all() == []


def _wire_common_scan_mocks(monkeypatch, findings):
    """Mock every external boundary execute_pr_guardrail_scan crosses
    (GitHub API, git clone, scanner subprocess, endpoint discovery, PR
    comment/commit-status HTTP calls) so the test exercises real
    dedup/policy/enforcement logic without any real network or filesystem
    access -- same boundary-mocking shape as tests/test_celery_offload.py."""
    monkeypatch.setattr(
        pr_guardrail_executor,
        "github_get",
        lambda path: type("R", (), {
            "raise_for_status": lambda self: None,
            "json": lambda self: {"head": {"ref": "feature", "sha": "deadbeef"}, "title": "a pr"},
        })(),
    )
    monkeypatch.setattr(pr_guardrail_executor.runner, "clone_repo", lambda *a, **k: "/tmp/fake-repo")
    monkeypatch.setattr(pr_guardrail_executor.runner, "run_tool", lambda tool, repo_path: {})
    monkeypatch.setattr(pr_guardrail_executor, "GUARDRAIL_PARSER", lambda raw: findings)
    monkeypatch.setattr(pr_guardrail_executor.runner, "normalize_file_path", lambda fp, repo_path: fp)
    monkeypatch.setattr(pr_guardrail_executor, "_diff_new_endpoints", lambda session, target, repo_path: [])
    monkeypatch.setattr(pr_guardrail_executor, "_get_installation_token_or_none", lambda session, target: None)

    posted_statuses = []
    monkeypatch.setattr(
        pr_guardrail_executor,
        "set_commit_status",
        lambda session, target, sha, state, description: posted_statuses.append((state, description)),
    )
    posted_comments = []
    monkeypatch.setattr(
        pr_guardrail_executor,
        "post_pr_comment",
        lambda session, target, pr_number, body: posted_comments.append(body),
    )
    return posted_statuses, posted_comments


def _critical_finding():
    return {
        "rule_id": "sql-injection",
        "title": "SQL Injection",
        "file_path": "app.py",
        "line_start": 42,
        "severity": "Critical",
        "snippet": "execute(query)",
    }


def test_alert_mode_posts_comment_but_non_blocking_status_despite_real_findings(engine, monkeypatch):
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id, enforcement_mode="alert")
    posted_statuses, posted_comments = _wire_common_scan_mocks(monkeypatch, [_critical_finding()])

    with Session(engine) as session:
        target = session.get(Target, target_id)
        result = pr_guardrail_executor.execute_pr_guardrail_scan(target, 1, session)

    # Real blocking finding -> the persisted scan's own status still reflects
    # that (BLOCKED), but alert mode means the commit status sent to GitHub
    # is non-blocking.
    assert result["status"] == PRGuardrailStatus.BLOCKED
    assert result["new_findings_count"] == 1
    assert len(posted_comments) == 1  # comment still posted, same as block mode
    assert len(posted_statuses) == 1
    state, description = posted_statuses[0]
    assert state == "success"  # non-blocking, not "failure"
    assert "alert" in description.lower()


def test_block_mode_posts_blocking_status_for_real_findings(engine, monkeypatch):
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id, enforcement_mode="block")
    posted_statuses, posted_comments = _wire_common_scan_mocks(monkeypatch, [_critical_finding()])

    with Session(engine) as session:
        target = session.get(Target, target_id)
        result = pr_guardrail_executor.execute_pr_guardrail_scan(target, 1, session)

    assert result["status"] == PRGuardrailStatus.BLOCKED
    assert len(posted_comments) == 1
    state, description = posted_statuses[0]
    assert state == "failure"


def test_block_mode_is_default_when_nothing_configured(engine, monkeypatch):
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)  # no override anywhere
    posted_statuses, _ = _wire_common_scan_mocks(monkeypatch, [_critical_finding()])

    with Session(engine) as session:
        target = session.get(Target, target_id)
        result = pr_guardrail_executor.execute_pr_guardrail_scan(target, 1, session)

    assert result["status"] == PRGuardrailStatus.BLOCKED
    assert posted_statuses[0][0] == "failure"


def test_passed_scan_reports_success_status_regardless_of_mode(engine, monkeypatch):
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id, enforcement_mode="alert")
    posted_statuses, _ = _wire_common_scan_mocks(monkeypatch, [])  # no findings at all

    with Session(engine) as session:
        target = session.get(Target, target_id)
        result = pr_guardrail_executor.execute_pr_guardrail_scan(target, 1, session)

    assert result["status"] == PRGuardrailStatus.PASSED
    state, description = posted_statuses[0]
    assert state == "success"
    assert "alert" not in description.lower()
