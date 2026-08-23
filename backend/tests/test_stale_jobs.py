"""Tests for issue #153: a Scan/DiscoveryRun/PipelineIntegrationBatch row
left "running" past `settings.stale_job_timeout_seconds` (its Celery task
never reached a worker, or the worker died mid-task) must flip to "failed"
with a reason on the next poll, instead of leaving the frontend spinning on
an indefinite "running" status forever -- caught live when a misconfigured
local worker left 27 real jobs stuck this way.

Same in-memory SQLite + TestClient + session-token-login pattern as
tests/test_celery_offload.py.
"""
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.config import settings
from app.core.security import create_session_token, hash_password
from app.core.staleness import mark_stale_if_needed
from app.main import app
from app.models.models import (
    DiscoveryRun,
    Organization,
    PipelineIntegrationBatch,
    Scan,
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


def _login(client, engine, role=UserRole.DEVELOPER):
    email = f"{role.value}-{id(object())}@example.com"
    with Session(engine) as session:
        user = User(email=email, name="Test", password_hash=hash_password("whatever123"), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        uid = user.id
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("rikugan_session", token)
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
        target = Target(workspace_id=ws.id, name="target", repo_url="https://github.com/acme/repo")
        session.add(target)
        session.commit()
        session.refresh(target)
        return ws.id, target.id


def STALE_STARTED_AT() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=settings.stale_job_timeout_seconds + 60)


# ---------------------------------------------------------------------------
# Unit tests: mark_stale_if_needed itself
# ---------------------------------------------------------------------------


def test_mark_stale_if_needed_leaves_fresh_running_row_untouched(engine):
    with Session(engine) as session:
        _, target_id = _make_workspace_and_target(engine)
        scan = Scan(target_id=target_id, tool="semgrep", branch="main", status="running")
        session.add(scan)
        session.commit()
        session.refresh(scan)

        assert mark_stale_if_needed(session, scan) is False
        assert scan.status == "running"


def test_mark_stale_if_needed_fails_old_running_scan_with_reason(engine):
    with Session(engine) as session:
        _, target_id = _make_workspace_and_target(engine)
        scan = Scan(
            target_id=target_id, tool="semgrep", branch="main", status="running", started_at=STALE_STARTED_AT()
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)

        assert mark_stale_if_needed(session, scan) is True
        assert scan.status == "failed"
        assert scan.completed_at is not None
        assert "timed out" in scan.error.lower()


def test_mark_stale_if_needed_ignores_already_settled_rows(engine):
    with Session(engine) as session:
        _, target_id = _make_workspace_and_target(engine)
        scan = Scan(
            target_id=target_id,
            tool="semgrep",
            branch="main",
            status="completed",
            started_at=STALE_STARTED_AT(),
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)

        assert mark_stale_if_needed(session, scan) is False
        assert scan.status == "completed"


def test_mark_stale_if_needed_handles_row_with_no_error_field(engine):
    """PipelineIntegrationBatch has no `error` column -- must not blow up."""
    with Session(engine) as session:
        user = User(email="admin@example.com", name="Admin", password_hash=hash_password("x"), role=UserRole.ADMIN)
        session.add(user)
        session.commit()
        session.refresh(user)
        batch = PipelineIntegrationBatch(
            created_by_user_id=user.id, status="running", total=1, started_at=STALE_STARTED_AT()
        )
        session.add(batch)
        session.commit()
        session.refresh(batch)

        assert mark_stale_if_needed(session, batch) is True
        assert batch.status == "failed"
        assert batch.completed_at is not None


# ---------------------------------------------------------------------------
# Integration: GET endpoints flip a stale row on the next poll
# ---------------------------------------------------------------------------


def test_get_scan_flips_stale_running_scan_to_failed(client, engine):
    ws_id, target_id = _make_workspace_and_target(engine)
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    with Session(engine) as session:
        session.add(WorkspaceMembership(user_id=uid, workspace_id=ws_id, role=WorkspaceRole.DEVELOPER))
        session.commit()
        scan = Scan(
            target_id=target_id, tool="semgrep", branch="main", status="running", started_at=STALE_STARTED_AT()
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        scan_id = scan.id

    resp = client.get(f"/api/scans/{scan_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "failed"
    assert "timed out" in body["error_message"].lower()


def test_get_discovery_run_flips_stale_running_row_to_failed(client, engine):
    ws_id, target_id = _make_workspace_and_target(engine)
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    with Session(engine) as session:
        session.add(WorkspaceMembership(user_id=uid, workspace_id=ws_id, role=WorkspaceRole.DEVELOPER))
        session.commit()
        run = DiscoveryRun(target_id=target_id, branch="main", status="running", started_at=STALE_STARTED_AT())
        session.add(run)
        session.commit()
        session.refresh(run)
        run_id = run.id

    resp = client.get(f"/api/discovery/{target_id}/runs/{run_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "failed"
    assert "timed out" in body["error"].lower()
