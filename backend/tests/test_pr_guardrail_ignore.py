"""Tests for the ignore-request/approval workflow on persisted
PRGuardrailFinding rows, and the Severity-enum comment-rendering bug fix."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.pr_guardrail_executor import _severity_str, render_comment
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import IgnoreStatus, PRGuardrailFinding, PRGuardrailScan, PRGuardrailStatus, Severity, User, UserRole


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
    client.cookies.set("rikugan_session", token)
    return client


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
    body = render_comment([finding], [], PRGuardrailStatus.BLOCKED, target_id=5, pr_scan_id=1)
    assert "finding-42" in body
    assert "ignore_finding=42" in body


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


def test_list_findings_for_a_scan(client, engine):
    # ADMIN bypasses workspace scoping (accessible_workspace_ids returns
    # None) -- this test's scan targets target_id=1, which doesn't exist as
    # a real row, so a non-admin caller would 404 on the workspace check.
    client = _login(client, engine, role=UserRole.ADMIN)
    scan_id, finding_id = _make_pr_scan_and_finding(engine)

    res = client.get(f"/api/pr-guardrail/{scan_id}/findings")
    assert res.status_code == 200
    ids = [f["id"] for f in res.json()]
    assert finding_id in ids
