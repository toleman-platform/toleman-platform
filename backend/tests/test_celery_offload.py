"""Tests for issue #59: POST /api/scans/run, POST /api/discovery/{target_id},
and POST /api/sbom/{target_id} must dispatch a Celery task (.delay()) and
return immediately instead of running clone+scan synchronously inside the
request handler.

Two layers, following the same in-memory SQLite + TestClient +
session-token-login pattern used in tests/test_workspace_roles.py:

  1. Dispatch tests: mock each task's `.delay()` to prove the endpoint
     creates the tracking row (Scan/DiscoveryRun/SbomRun) and dispatches the
     task instead of blocking on clone+scan, without ever touching git or a
     scanner subprocess.

  2. End-to-end eager-mode tests: flip Celery's `task_always_eager` on (the
     task then runs synchronously in-process instead of needing a real
     broker/worker) and monkeypatch only the boundary that actually shells
     out (runner.clone_repo / runner.run_tool / discover_endpoints), proving
     the full dispatch -> execution -> DB-row-transitions-to-completed path
     genuinely works, not just that `.delay()` was called.
"""
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    DiscoveryRun,
    Organization,
    Scan,
    SbomRun,
    Target,
    User,
    UserRole,
    Workspace,
    WorkspaceMembership,
    WorkspaceRole,
)
from app.tasks import discovery_tasks, sbom_tasks, scan_tasks
from app.tasks.celery_app import celery_app


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


def _login(client, engine, role=UserRole.DEVELOPER, email=None):
    email = email or f"{role.value}-{id(object())}@example.com"
    with Session(engine) as session:
        user = User(email=email, name="Test", password_hash=hash_password("whatever123"), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        uid = user.id
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("osp_session", token)
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


def _make_target(engine, workspace_id: int, name="target") -> int:
    with Session(engine) as session:
        target = Target(workspace_id=workspace_id, name=name, repo_url="https://github.com/acme/repo")
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


def _assign(engine, user_id: int, workspace_id: int, role: WorkspaceRole):
    with Session(engine) as session:
        m = WorkspaceMembership(user_id=user_id, workspace_id=workspace_id, role=role)
        session.add(m)
        session.commit()


def _dev_client_with_target(client, engine):
    ws = _make_workspace(engine)
    target_id = _make_target(engine, ws)
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws, WorkspaceRole.DEVELOPER)
    return client, target_id


# ---------------------------------------------------------------------------
# 1. Dispatch tests: .delay() is mocked, no git/subprocess is ever touched.
# ---------------------------------------------------------------------------


def test_scans_run_creates_running_row_and_dispatches_delay_without_blocking(client, engine, monkeypatch):
    client, target_id = _dev_client_with_target(client, engine)

    mock_delay = MagicMock()
    monkeypatch.setattr(scan_tasks.run_scan, "delay", mock_delay)

    res = client.post("/api/scans/run", params={"target_id": target_id, "tool": "semgrep"})

    assert res.status_code == 202
    body = res.json()
    assert body["status"] == "running"
    assert isinstance(body["scan_id"], int)

    mock_delay.assert_called_once_with(target_id=target_id, tool="semgrep", scan_id=body["scan_id"])

    with Session(engine) as session:
        scan = session.get(Scan, body["scan_id"])
        assert scan is not None
        assert scan.status == "running"
        assert scan.tool == "semgrep"

    # GET /api/scans/{id} is what the frontend polls -- prove it reflects the row.
    poll = client.get(f"/api/scans/{body['scan_id']}")
    assert poll.status_code == 200
    assert poll.json()["status"] == "running"


def test_discovery_run_creates_running_row_and_dispatches_delay_without_blocking(client, engine, monkeypatch):
    client, target_id = _dev_client_with_target(client, engine)

    mock_delay = MagicMock()
    monkeypatch.setattr(discovery_tasks.run_discovery, "delay", mock_delay)

    res = client.post(f"/api/discovery/{target_id}")

    assert res.status_code == 202
    body = res.json()
    assert body["status"] == "running"
    run_id = body["run_id"]

    mock_delay.assert_called_once_with(target_id=target_id, run_id=run_id)

    with Session(engine) as session:
        run = session.get(DiscoveryRun, run_id)
        assert run is not None
        assert run.status == "running"

    poll = client.get(f"/api/discovery/{target_id}/runs/{run_id}")
    assert poll.status_code == 200
    assert poll.json()["status"] == "running"
    # Still running -- no endpoints payload yet (that only appears once complete).
    assert "endpoints" not in poll.json()


def test_sbom_generate_creates_running_row_and_dispatches_delay_without_blocking(client, engine, monkeypatch):
    client, target_id = _dev_client_with_target(client, engine)

    mock_delay = MagicMock()
    monkeypatch.setattr(sbom_tasks.run_sbom_generation, "delay", mock_delay)

    res = client.post(f"/api/sbom/{target_id}")

    assert res.status_code == 202
    body = res.json()
    assert body["status"] == "running"
    run_id = body["run_id"]

    mock_delay.assert_called_once_with(target_id=target_id, run_id=run_id)

    with Session(engine) as session:
        run = session.get(SbomRun, run_id)
        assert run is not None
        assert run.status == "running"

    poll = client.get(f"/api/sbom/{target_id}/runs/{run_id}")
    assert poll.status_code == 200
    assert poll.json()["status"] == "running"
    assert "components" not in poll.json()


# ---------------------------------------------------------------------------
# 2. End-to-end eager-mode tests: real dispatch -> real task execution ->
#    real DB row transitioning to "completed", using Celery's
#    task_always_eager so no broker/worker process is needed, but nothing
#    about the dispatch path itself is mocked.
# ---------------------------------------------------------------------------


@pytest.fixture()
def eager_celery():
    original_eager = celery_app.conf.task_always_eager
    original_propagates = celery_app.conf.task_eager_propagates
    celery_app.conf.task_always_eager = True
    celery_app.conf.task_eager_propagates = True
    yield
    celery_app.conf.task_always_eager = original_eager
    celery_app.conf.task_eager_propagates = original_propagates


def _fake_clone_repo(repo_url, branch, github_token="", scan_id=None):
    # Stand-in checkout dir -- real clone_repo/git is never invoked in tests.
    return Path("/tmp")


def test_scan_dispatch_runs_eagerly_end_to_end_and_completes(client, engine, monkeypatch, eager_celery):
    client, target_id = _dev_client_with_target(client, engine)

    monkeypatch.setattr(scan_tasks, "engine", engine)
    monkeypatch.setattr(scan_tasks.runner, "clone_repo", _fake_clone_repo)
    monkeypatch.setattr(scan_tasks.runner, "run_tool", lambda tool, repo_path: {})
    monkeypatch.setattr(scan_tasks.runner, "normalize_file_path", lambda file_path, repo_path: file_path)

    res = client.post("/api/scans/run", params={"target_id": target_id, "tool": "semgrep"})
    assert res.status_code == 202
    scan_id = res.json()["scan_id"]

    # Eager mode means the task already ran synchronously by the time
    # .delay() returned above -- no polling loop needed, but we still go
    # through the real GET endpoint to prove the row is genuinely updated.
    poll = client.get(f"/api/scans/{scan_id}")
    assert poll.status_code == 200
    body = poll.json()
    assert body["status"] == "completed"
    assert body["findings_count"] == 0
    assert body["completed_at"] is not None


def test_discovery_dispatch_runs_eagerly_end_to_end_and_completes(client, engine, monkeypatch, eager_celery):
    client, target_id = _dev_client_with_target(client, engine)

    monkeypatch.setattr(discovery_tasks, "engine", engine)
    monkeypatch.setattr(discovery_tasks.runner, "clone_repo", _fake_clone_repo)
    monkeypatch.setattr(
        discovery_tasks,
        "discover_endpoints",
        lambda repo_path: [{"framework": "fastapi", "method": "GET", "route": "/health", "file": "main.py", "line": 1}],
    )

    res = client.post(f"/api/discovery/{target_id}")
    assert res.status_code == 202
    run_id = res.json()["run_id"]

    poll = client.get(f"/api/discovery/{target_id}/runs/{run_id}")
    assert poll.status_code == 200
    body = poll.json()
    assert body["status"] == "completed"
    assert body["count"] == 1
    assert body["new_count"] == 1
    assert body["endpoints"][0]["route"] == "/health"
    assert body["endpoints"][0]["is_new"] is True


def test_sbom_dispatch_runs_eagerly_end_to_end_and_completes(client, engine, monkeypatch, eager_celery):
    client, target_id = _dev_client_with_target(client, engine)

    monkeypatch.setattr(sbom_tasks, "engine", engine)
    monkeypatch.setattr(sbom_tasks.runner, "clone_repo", _fake_clone_repo)
    monkeypatch.setattr(sbom_tasks.runner, "run_tool", lambda tool, repo_path: {})
    monkeypatch.setattr(
        sbom_tasks,
        "parse_trivy_sbom",
        lambda raw: [{"name": "anthropic", "version": "0.121.0", "package_type": "pip", "purl": "pkg:pypi/anthropic@0.121.0"}],
    )

    res = client.post(f"/api/sbom/{target_id}")
    assert res.status_code == 202
    run_id = res.json()["run_id"]

    poll = client.get(f"/api/sbom/{target_id}/runs/{run_id}")
    assert poll.status_code == 200
    body = poll.json()
    assert body["status"] == "completed"
    assert body["count"] == 1
    assert body["new_count"] == 1
    assert body["components"][0]["name"] == "anthropic"
    assert body["components"][0]["is_new"] is True


def test_scan_dispatch_marks_row_failed_on_clone_error(client, engine, monkeypatch, eager_celery):
    """Proves the failure path also actually runs end to end -- not just the
    happy path -- and that the row transitions to "failed" rather than
    hanging in "running" forever."""
    client, target_id = _dev_client_with_target(client, engine)

    monkeypatch.setattr(scan_tasks, "engine", engine)

    def _boom(repo_url, branch, github_token="", scan_id=None):
        from app.scanners.runner import RepoCloneError

        raise RepoCloneError("bad repo url")

    monkeypatch.setattr(scan_tasks.runner, "clone_repo", _boom)

    res = client.post("/api/scans/run", params={"target_id": target_id, "tool": "semgrep"})
    assert res.status_code == 202
    scan_id = res.json()["scan_id"]

    poll = client.get(f"/api/scans/{scan_id}")
    assert poll.json()["status"] == "failed"
