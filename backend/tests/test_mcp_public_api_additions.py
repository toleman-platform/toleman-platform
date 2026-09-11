"""Tests for the public-API additions backing the Toleman MCP server's new
capabilities (issue #108 follow-up):

  - POST /api/public/v1/findings/{id}/suggest-fix and /raise-pr: the exact
    same autofix split app/api/findings.py already exposes to the frontend
    (see tests/test_autofix.py), mirrored onto the Bearer-token-
    authenticated public API so an MCP client gets the same capability.
  - POST/GET /api/public/v1/scan-snippet: an ephemeral "find vulns while
    it's being written" check, no Target required. Dispatch tests mock
    run_snippet_scan.delay (same two-layer approach as
    tests/test_celery_offload.py); a separate task-level test exercises
    app.tasks.snippet_scan_tasks.run_snippet_scan directly with
    app.scanners.runner._execute mocked, since no real semgrep/gitleaks
    binary is available in this test environment.
"""
import itertools
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
import app.api.public_api as public_api_module
from app.api.deps import get_session
from app.core.security import create_session_token, generate_api_token, hash_password
from app.main import app
from app.models.models import (
    ApiToken,
    ApiTokenScope,
    Finding,
    Organization,
    Severity,
    SnippetScanRun,
    Target,
    User,
    UserRole,
    Workspace,
    WorkspaceMembership,
    WorkspaceRole,
)
from app.scanners import runner
from app.tasks.snippet_scan_tasks import run_snippet_scan


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


_email_counter = itertools.count()


def _login(client, engine, role=UserRole.DEVELOPER) -> tuple[TestClient, int]:
    email = f"{role.value}-{next(_email_counter)}@example.com"
    with Session(engine) as session:
        user = User(email=email, name="Test", password_hash=hash_password("whatever123"), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        uid = user.id
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return client, uid


def _make_workspace_and_target(engine) -> tuple[int, int]:
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
        return ws.id, target.id


def _assign(engine, user_id: int, workspace_id: int, role: WorkspaceRole = WorkspaceRole.DEVELOPER):
    with Session(engine) as session:
        session.add(WorkspaceMembership(user_id=user_id, workspace_id=workspace_id, role=role))
        session.commit()


def _make_token_for_user(engine, user_id: int, scope: ApiTokenScope = ApiTokenScope.READ) -> str:
    plaintext, token_hash, token_prefix = generate_api_token()
    with Session(engine) as session:
        session.add(ApiToken(user_id=user_id, name="t", token_hash=token_hash, token_prefix=token_prefix, scope=scope))
        session.commit()
    return plaintext


def _make_finding(engine, target_id: int, **overrides) -> int:
    defaults = dict(
        target_id=target_id, dedup_hash="hash-1", tool="trivy", rule_id="r1", title="t",
        file_path="requirements.txt", severity=Severity.HIGH,
    )
    defaults.update(overrides)
    with Session(engine) as session:
        finding = Finding(**defaults)
        session.add(finding)
        session.commit()
        session.refresh(finding)
        return finding.id


# ---------------------------------------------------------------------------
# suggest-fix / raise-pr
# ---------------------------------------------------------------------------


def test_public_suggest_fix_returns_recommendation(client, engine, monkeypatch):
    ws_id, target_id = _make_workspace_and_target(engine)
    client, uid = _login(client, engine)
    _assign(engine, uid, ws_id)
    token = _make_token_for_user(engine, uid, scope=ApiTokenScope.READ)
    finding_id = _make_finding(engine, target_id)

    monkeypatch.setattr(
        public_api_module,
        "suggest_fix",
        lambda session, finding: {"recommendation": "Upgrade the package.", "strategy": None, "diff": None,
                                    "file_path": None, "new_content": None, "ref": None, "explanation": None},
    )

    res = client.post(
        f"/api/public/v1/findings/{finding_id}/suggest-fix", headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    assert res.json()["recommendation"] == "Upgrade the package."


def test_public_suggest_fix_404s_outside_workspace(client, engine):
    ws_id, target_id = _make_workspace_and_target(engine)
    client, uid = _login(client, engine)
    # Deliberately not assigned.
    token = _make_token_for_user(engine, uid)
    finding_id = _make_finding(engine, target_id)

    res = client.post(
        f"/api/public/v1/findings/{finding_id}/suggest-fix", headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 404


def test_public_raise_pr_requires_write_scope(client, engine):
    ws_id, target_id = _make_workspace_and_target(engine)
    client, uid = _login(client, engine)
    _assign(engine, uid, ws_id)
    token = _make_token_for_user(engine, uid, scope=ApiTokenScope.READ)
    finding_id = _make_finding(engine, target_id)

    res = client.post(
        f"/api/public/v1/findings/{finding_id}/raise-pr",
        headers={"Authorization": f"Bearer {token}"},
        json={"file_path": "requirements.txt", "new_content": "x==2.0\n", "ref": "main", "strategy": "deterministic_sca"},
    )
    assert res.status_code == 403


def test_public_raise_pr_opens_pr_for_the_supplied_patch(client, engine, monkeypatch):
    ws_id, target_id = _make_workspace_and_target(engine)
    client, uid = _login(client, engine)
    _assign(engine, uid, ws_id)
    token = _make_token_for_user(engine, uid, scope=ApiTokenScope.READ_WRITE)
    finding_id = _make_finding(engine, target_id)

    captured = {}

    def fake_open_fix_pr(session, target, finding, patch):
        captured["patch"] = patch
        return {"pr_url": "https://github.com/acme/repo/pull/1", "pr_number": 1, "branch": "toleman/fix-1"}

    monkeypatch.setattr(public_api_module, "open_fix_pr", fake_open_fix_pr)

    res = client.post(
        f"/api/public/v1/findings/{finding_id}/raise-pr",
        headers={"Authorization": f"Bearer {token}"},
        json={"file_path": "requirements.txt", "new_content": "x==2.0\n", "ref": "main", "strategy": "deterministic_sca"},
    )
    assert res.status_code == 200
    assert res.json()["pr_number"] == 1
    assert captured["patch"].new_content == "x==2.0\n"


def test_public_raise_pr_rejects_file_path_mismatch(client, engine):
    ws_id, target_id = _make_workspace_and_target(engine)
    client, uid = _login(client, engine)
    _assign(engine, uid, ws_id)
    token = _make_token_for_user(engine, uid, scope=ApiTokenScope.READ_WRITE)
    finding_id = _make_finding(engine, target_id)

    res = client.post(
        f"/api/public/v1/findings/{finding_id}/raise-pr",
        headers={"Authorization": f"Bearer {token}"},
        json={"file_path": "some/other/file.txt", "new_content": "x", "ref": "main", "strategy": "deterministic_sca"},
    )
    assert res.status_code == 400


def test_public_raise_pr_surfaces_autofix_error_as_502(client, engine, monkeypatch):
    ws_id, target_id = _make_workspace_and_target(engine)
    client, uid = _login(client, engine)
    _assign(engine, uid, ws_id)
    token = _make_token_for_user(engine, uid, scope=ApiTokenScope.READ_WRITE)
    finding_id = _make_finding(engine, target_id)

    from app.core.autofix import AutofixError

    def boom(session, target, finding, patch):
        raise AutofixError("no GitHub App installed")

    monkeypatch.setattr(public_api_module, "open_fix_pr", boom)

    res = client.post(
        f"/api/public/v1/findings/{finding_id}/raise-pr",
        headers={"Authorization": f"Bearer {token}"},
        json={"file_path": "requirements.txt", "new_content": "x==2.0\n", "ref": "main", "strategy": "deterministic_sca"},
    )
    assert res.status_code == 502
    assert "no GitHub App installed" in res.json()["detail"]


# ---------------------------------------------------------------------------
# scan-snippet: dispatch + validation
# ---------------------------------------------------------------------------


def test_scan_snippet_dispatches_and_returns_running(client, engine, monkeypatch):
    client, uid = _login(client, engine)
    token = _make_token_for_user(engine, uid)
    captured = {}
    monkeypatch.setattr(
        "app.api.public_api.run_snippet_scan.delay", lambda **kwargs: captured.update(kwargs)
    )

    res = client.post(
        "/api/public/v1/scan-snippet",
        headers={"Authorization": f"Bearer {token}"},
        json={"filename": "app.py", "content": "import os\nos.system(cmd)\n"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "running"
    assert captured["filename"] == "app.py"
    assert captured["tools"] == ["semgrep", "gitleaks"]

    with Session(engine) as session:
        run = session.get(SnippetScanRun, body["run_id"])
        assert run.user_id == uid
        assert run.status == "running"


def test_scan_snippet_accepts_a_custom_tool_list(client, engine, monkeypatch):
    client, uid = _login(client, engine)
    token = _make_token_for_user(engine, uid)
    captured = {}
    monkeypatch.setattr(
        "app.api.public_api.run_snippet_scan.delay", lambda **kwargs: captured.update(kwargs)
    )

    res = client.post(
        "/api/public/v1/scan-snippet",
        headers={"Authorization": f"Bearer {token}"},
        json={"filename": "main.tf", "content": "resource \"x\" {}\n", "tools": ["checkov", "tfsec"]},
    )
    assert res.status_code == 200
    assert captured["tools"] == ["checkov", "tfsec"]


def test_scan_snippet_rejects_unknown_tool(client, engine):
    client, uid = _login(client, engine)
    token = _make_token_for_user(engine, uid)

    res = client.post(
        "/api/public/v1/scan-snippet",
        headers={"Authorization": f"Bearer {token}"},
        json={"filename": "app.py", "content": "x = 1\n", "tools": ["trivy"]},
    )
    assert res.status_code == 400


def test_scan_snippet_rejects_path_traversal_filename(client, engine):
    client, uid = _login(client, engine)
    token = _make_token_for_user(engine, uid)

    res = client.post(
        "/api/public/v1/scan-snippet",
        headers={"Authorization": f"Bearer {token}"},
        json={"filename": "../../etc/passwd", "content": "x"},
    )
    assert res.status_code == 400


def test_scan_snippet_rejects_oversized_content(client, engine):
    client, uid = _login(client, engine)
    token = _make_token_for_user(engine, uid)

    res = client.post(
        "/api/public/v1/scan-snippet",
        headers={"Authorization": f"Bearer {token}"},
        json={"filename": "app.py", "content": "x" * (public_api_module.MAX_SNIPPET_CONTENT_BYTES + 1)},
    )
    assert res.status_code == 400


def test_scan_snippet_does_not_require_write_scope(client, engine, monkeypatch):
    """Read-scoped: this never touches a real target/repo."""
    client, uid = _login(client, engine)
    token = _make_token_for_user(engine, uid, scope=ApiTokenScope.READ)
    monkeypatch.setattr("app.api.public_api.run_snippet_scan.delay", lambda **kwargs: None)

    res = client.post(
        "/api/public/v1/scan-snippet",
        headers={"Authorization": f"Bearer {token}"},
        json={"filename": "app.py", "content": "x = 1\n"},
    )
    assert res.status_code == 200


# ---------------------------------------------------------------------------
# scan-snippet: polling
# ---------------------------------------------------------------------------


def test_get_scan_snippet_returns_findings_once_completed(client, engine):
    client, uid = _login(client, engine)
    token = _make_token_for_user(engine, uid)

    with Session(engine) as session:
        run = SnippetScanRun(
            user_id=uid, filename="app.py", status="completed",
            findings_json=json.dumps([{"tool": "semgrep", "rule_id": "r1", "title": "t", "description": "d",
                                        "file_path": "app.py", "line_start": 1, "line_end": 1,
                                        "severity": "High", "snippet": "os.system(cmd)"}]),
        )
        session.add(run)
        session.commit()
        session.refresh(run)
        run_id = run.id

    res = client.get(f"/api/public/v1/scan-snippet/{run_id}", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "completed"
    assert len(body["findings"]) == 1
    assert body["findings"][0]["rule_id"] == "r1"


def test_get_scan_snippet_is_owner_scoped(client, engine):
    client, uid = _login(client, engine)
    token = _make_token_for_user(engine, uid)

    with Session(engine) as session:
        other = User(email="other@e.com", name="O", password_hash=hash_password("whatever123"))
        session.add(other)
        session.commit()
        session.refresh(other)
        run = SnippetScanRun(user_id=other.id, filename="app.py", status="running")
        session.add(run)
        session.commit()
        session.refresh(run)
        run_id = run.id

    res = client.get(f"/api/public/v1/scan-snippet/{run_id}", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 404


def test_get_scan_snippet_404s_for_unknown_id(client, engine):
    client, uid = _login(client, engine)
    token = _make_token_for_user(engine, uid)
    res = client.get("/api/public/v1/scan-snippet/99999", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# run_snippet_scan (Celery task), runner._execute mocked -- no real
# semgrep/gitleaks binary needed
# ---------------------------------------------------------------------------


def test_run_snippet_scan_persists_parsed_findings(engine, monkeypatch):
    import app.tasks.snippet_scan_tasks as snippet_scan_tasks_module

    monkeypatch.setattr(snippet_scan_tasks_module, "engine", engine)

    with Session(engine) as session:
        org = Organization(name="o")
        session.add(org)
        session.commit()
        session.refresh(org)
        user = User(email="u@e.com", name="U", password_hash=hash_password("whatever123"))
        session.add(user)
        session.commit()
        session.refresh(user)
        run = SnippetScanRun(user_id=user.id, filename="app.py", status="running")
        session.add(run)
        session.commit()
        session.refresh(run)
        run_id = run.id

    def fake_execute(tool, cmd, repo_path):
        if tool == "semgrep":
            return {"results": [{
                "check_id": "python.lang.security.audit.dangerous-system-call",
                "path": str(repo_path / "app.py"),
                "start": {"line": 2}, "end": {"line": 2},
                "extra": {"message": "Dangerous system call", "severity": "ERROR", "lines": "os.system(cmd)"},
            }]}
        return []

    monkeypatch.setattr(runner, "_execute", fake_execute)

    result = run_snippet_scan(run_id=run_id, filename="app.py", content="import os\nos.system(cmd)\n", tools=["semgrep", "gitleaks"])
    assert result["status"] == "completed"

    with Session(engine) as session:
        run = session.get(SnippetScanRun, run_id)
        assert run.status == "completed"
        findings = json.loads(run.findings_json)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "python.lang.security.audit.dangerous-system-call"
        assert findings[0]["tool"] == "semgrep"
        assert findings[0]["severity"] == "High"


def test_run_snippet_scan_marks_failed_on_exception(engine, monkeypatch):
    import app.tasks.snippet_scan_tasks as snippet_scan_tasks_module

    monkeypatch.setattr(snippet_scan_tasks_module, "engine", engine)

    with Session(engine) as session:
        user = User(email="u2@e.com", name="U", password_hash=hash_password("whatever123"))
        session.add(user)
        session.commit()
        session.refresh(user)
        run = SnippetScanRun(user_id=user.id, filename="app.py", status="running")
        session.add(run)
        session.commit()
        session.refresh(run)
        run_id = run.id

    def boom(tool, cmd, repo_path):
        raise RuntimeError("semgrep exploded")

    monkeypatch.setattr(runner, "_execute", boom)

    result = run_snippet_scan(run_id=run_id, filename="app.py", content="x = 1\n", tools=["semgrep"])
    assert result["status"] == "failed"

    with Session(engine) as session:
        run = session.get(SnippetScanRun, run_id)
        assert run.status == "failed"
        assert "semgrep exploded" in run.error


def test_run_snippet_scan_rejects_path_traversal_defensively(engine, monkeypatch):
    """Defense in depth: even if a caller somehow bypassed the API's own
    filename validation, the task itself must never write outside its temp
    dir."""
    import app.tasks.snippet_scan_tasks as snippet_scan_tasks_module

    monkeypatch.setattr(snippet_scan_tasks_module, "engine", engine)

    with Session(engine) as session:
        user = User(email="u3@e.com", name="U", password_hash=hash_password("whatever123"))
        session.add(user)
        session.commit()
        session.refresh(user)
        run = SnippetScanRun(user_id=user.id, filename="../../etc/passwd", status="running")
        session.add(run)
        session.commit()
        session.refresh(run)
        run_id = run.id

    result = run_snippet_scan(run_id=run_id, filename="../../etc/passwd", content="x", tools=["semgrep"])
    assert result["status"] == "failed"
    with Session(engine) as session:
        run = session.get(SnippetScanRun, run_id)
        assert "unsafe filename" in run.error
