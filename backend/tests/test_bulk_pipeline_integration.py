"""Tests for issue #68: multi-select "Add Pipeline", the bulk wrapper
around #66's per-target pipeline integration mechanism
(POST /api/targets/{id}/pipeline-integrate).

Same two-layer approach as tests/test_celery_offload.py (#59):

  1. Dispatch tests: mock run_pipeline_integration_batch.delay() to prove
     POST /api/targets/bulk-pipeline-integrate creates the batch + one item
     per eligible target and dispatches instead of blocking the request
     thread on N real GitHub API calls.

  2. End-to-end eager-mode tests: flip Celery's task_always_eager on and
     monkeypatch only open_pipeline_pr (the actual GitHub-API boundary,
     same as #66's own tests monkeypatch it), proving the full
     dispatch -> sequential per-item processing -> batch "completed" path
     genuinely works; including the already-integrated skip and the
     per-item failure isolation (#68's scope requirements).
"""
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
import app.api.targets as targets_module
from app.api.deps import get_session
from app.core.pipeline_pr import PipelinePrError
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    Organization,
    PipelineIntegrationBatch,
    PipelineIntegrationBatchItem,
    Target,
    User,
    UserRole,
    Workspace,
    WorkspaceMembership,
    WorkspaceRole,
)
from app.tasks import pipeline_tasks
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


def _make_target(engine, workspace_id: int, name="target", pipeline_integrated=False) -> int:
    with Session(engine) as session:
        target = Target(
            workspace_id=workspace_id,
            name=name,
            repo_url=f"https://github.com/acme/{name}",
            pipeline_integrated=pipeline_integrated,
            pipeline_pr_url="https://github.com/acme/repo/pull/1" if pipeline_integrated else None,
        )
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


def _assign(engine, user_id: int, workspace_id: int, role: WorkspaceRole):
    with Session(engine) as session:
        m = WorkspaceMembership(user_id=user_id, workspace_id=workspace_id, role=role)
        session.add(m)
        session.commit()


def _dev_client_with_targets(client, engine, n=3):
    ws = _make_workspace(engine)
    target_ids = [_make_target(engine, ws, name=f"t{i}") for i in range(n)]
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws, WorkspaceRole.DEVELOPER)
    return client, target_ids


# ---------------------------------------------------------------------------
# 1. Dispatch tests
# ---------------------------------------------------------------------------


def test_bulk_integrate_creates_batch_and_items_and_dispatches_without_blocking(client, engine, monkeypatch):
    client, target_ids = _dev_client_with_targets(client, engine, n=3)

    mock_delay = MagicMock()
    monkeypatch.setattr(targets_module.run_pipeline_integration_batch, "delay", mock_delay)

    res = client.post("/api/targets/bulk-pipeline-integrate", json={"target_ids": target_ids})

    assert res.status_code == 202
    body = res.json()
    assert body["status"] == "running"
    assert body["total"] == 3
    batch_id = body["batch_id"]

    mock_delay.assert_called_once_with(batch_id=batch_id)

    from sqlmodel import select

    with Session(engine) as session:
        batch = session.get(PipelineIntegrationBatch, batch_id)
        assert batch is not None
        assert batch.total == 3
        items = session.exec(
            select(PipelineIntegrationBatchItem).where(PipelineIntegrationBatchItem.batch_id == batch_id)
        ).all()
        assert len(items) == 3
        assert {i.target_id for i in items} == set(target_ids)
        assert all(i.status == "pending" for i in items)


def test_bulk_integrate_requires_at_least_one_target(client, engine):
    client, _ = _dev_client_with_targets(client, engine, n=1)
    res = client.post("/api/targets/bulk-pipeline-integrate", json={"target_ids": []})
    assert res.status_code == 400


def test_bulk_integrate_drops_targets_caller_cannot_access(client, engine, monkeypatch):
    # A target in a workspace the caller has no membership in must be
    # silently dropped from the batch, not leak a 403/404 for that one id
    # or get processed.
    client, target_ids = _dev_client_with_targets(client, engine, n=1)
    other_ws = _make_workspace(engine, name="other")
    foreign_target_id = _make_target(engine, other_ws, name="foreign")

    mock_delay = MagicMock()
    monkeypatch.setattr(targets_module.run_pipeline_integration_batch, "delay", mock_delay)

    res = client.post(
        "/api/targets/bulk-pipeline-integrate", json={"target_ids": target_ids + [foreign_target_id]}
    )
    assert res.status_code == 202
    assert res.json()["total"] == 1

    with Session(engine) as session:
        from sqlmodel import select

        items = session.exec(
            select(PipelineIntegrationBatchItem).where(
                PipelineIntegrationBatchItem.batch_id == res.json()["batch_id"]
            )
        ).all()
        assert [i.target_id for i in items] == target_ids


def test_bulk_integrate_all_targets_inaccessible_returns_403(client, engine):
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    ws = _make_workspace(engine)
    target_id = _make_target(engine, ws)
    # No WorkspaceMembership assigned -> zero accessible workspaces.
    res = client.post("/api/targets/bulk-pipeline-integrate", json={"target_ids": [target_id]})
    assert res.status_code == 403


def test_bulk_integrate_requires_developer_role_per_target(client, engine, monkeypatch):
    ws = _make_workspace(engine)
    target_id = _make_target(engine, ws)
    client, uid = _login(client, engine, role=UserRole.USER)
    _assign(engine, uid, ws, WorkspaceRole.VIEWER)

    mock_delay = MagicMock()
    monkeypatch.setattr(targets_module.run_pipeline_integration_batch, "delay", mock_delay)

    res = client.post("/api/targets/bulk-pipeline-integrate", json={"target_ids": [target_id]})
    assert res.status_code == 403
    mock_delay.assert_not_called()


def test_get_batch_status_running(client, engine, monkeypatch):
    client, target_ids = _dev_client_with_targets(client, engine, n=2)
    monkeypatch.setattr(targets_module.run_pipeline_integration_batch, "delay", MagicMock())

    res = client.post("/api/targets/bulk-pipeline-integrate", json={"target_ids": target_ids})
    batch_id = res.json()["batch_id"]

    poll = client.get(f"/api/targets/bulk-pipeline-integrate/{batch_id}")
    assert poll.status_code == 200
    body = poll.json()
    assert body["status"] == "running"
    assert body["total"] == 2
    assert len(body["items"]) == 2
    assert all(i["status"] == "pending" for i in body["items"])


def test_get_batch_status_404_for_missing_batch(client, engine):
    client, _ = _dev_client_with_targets(client, engine, n=1)
    res = client.get("/api/targets/bulk-pipeline-integrate/9999")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# 2. End-to-end eager-mode tests
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


def test_batch_processes_all_targets_and_reports_mixed_outcomes(client, engine, monkeypatch, eager_celery):
    """One target already integrated (skipped, not re-run), one succeeds,
    one fails; proves the batch finishes "completed" with an accurate
    per-item breakdown instead of stopping/crashing on the failure."""
    ws = _make_workspace(engine)
    already_id = _make_target(engine, ws, name="already", pipeline_integrated=True)
    ok_id = _make_target(engine, ws, name="ok")
    fail_id = _make_target(engine, ws, name="fail")

    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws, WorkspaceRole.DEVELOPER)

    monkeypatch.setattr(pipeline_tasks, "engine", engine)
    monkeypatch.setattr(pipeline_tasks, "INTER_ITEM_DELAY_SECONDS", 0)

    def fake_open_pipeline_pr(session, target):
        if target.id == ok_id:
            return {"pr_url": f"https://github.com/acme/{target.name}/pull/7", "pr_number": 7, "branch": "osp/x"}
        raise PipelinePrError("GitHub App needs permission re-approval (403)")

    monkeypatch.setattr(pipeline_tasks, "open_pipeline_pr", fake_open_pipeline_pr)

    res = client.post(
        "/api/targets/bulk-pipeline-integrate", json={"target_ids": [already_id, ok_id, fail_id]}
    )
    assert res.status_code == 202
    batch_id = res.json()["batch_id"]

    # eager mode -> task already ran synchronously by the time .delay() returned.
    poll = client.get(f"/api/targets/bulk-pipeline-integrate/{batch_id}")
    assert poll.status_code == 200
    body = poll.json()
    assert body["status"] == "completed"
    assert body["already_integrated"] == 1
    assert body["succeeded"] == 1
    assert body["failed"] == 1

    by_target = {i["target_id"]: i for i in body["items"]}
    assert by_target[already_id]["status"] == "already_integrated"
    assert by_target[ok_id]["status"] == "succeeded"
    assert by_target[ok_id]["pr_url"] == f"https://github.com/acme/ok/pull/7"
    assert by_target[fail_id]["status"] == "failed"
    assert "403" in by_target[fail_id]["error"]

    with Session(engine) as session:
        ok_target = session.get(Target, ok_id)
        assert ok_target.pipeline_integrated is True
        assert ok_target.pipeline_pr_url == "https://github.com/acme/ok/pull/7"

        fail_target = session.get(Target, fail_id)
        assert fail_target.pipeline_integrated is False


def test_batch_reports_actionable_message_on_encryption_key_mismatch(client, engine, monkeypatch, eager_celery):
    """If the GitHub App credentials can't be decrypted (PLATFORM_ENCRYPTION_KEY
    mismatch - see app.core.crypto), the item should get a clear, actionable
    error instead of a raw 'unexpected error: ...' traceback string."""
    from app.core.crypto import SecretDecryptionError

    ws = _make_workspace(engine)
    target_id = _make_target(engine, ws, name="mismatched")

    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws, WorkspaceRole.DEVELOPER)

    monkeypatch.setattr(pipeline_tasks, "engine", engine)
    monkeypatch.setattr(pipeline_tasks, "INTER_ITEM_DELAY_SECONDS", 0)

    def fake_open_pipeline_pr(session, target):
        raise SecretDecryptionError("Failed to decrypt secret - PLATFORM_ENCRYPTION_KEY is missing, wrong, or was rotated since this value was encrypted.")

    monkeypatch.setattr(pipeline_tasks, "open_pipeline_pr", fake_open_pipeline_pr)

    res = client.post("/api/targets/bulk-pipeline-integrate", json={"target_ids": [target_id]})
    assert res.status_code == 202
    batch_id = res.json()["batch_id"]

    poll = client.get(f"/api/targets/bulk-pipeline-integrate/{batch_id}")
    body = poll.json()
    assert body["failed"] == 1
    item = body["items"][0]
    assert item["status"] == "failed"
    assert "PLATFORM_ENCRYPTION_KEY mismatch" in item["error"]
    assert "Admin > Global Integrations" in item["error"]
    assert "unexpected error" not in item["error"]


def test_batch_missing_target_row_does_not_crash_batch(client, engine, monkeypatch):
    """Defensive case: a target row deleted between item-creation and task
    execution shouldn't leave the batch stuck at "running"."""
    ws = _make_workspace(engine)
    ok_id = _make_target(engine, ws, name="ok")

    with Session(engine) as session:
        user = User(email="dev@example.com", name="Dev", password_hash=hash_password("whatever123"), role=UserRole.DEVELOPER)
        session.add(user)
        session.commit()
        session.refresh(user)

        batch = PipelineIntegrationBatch(created_by_user_id=user.id, total=1, status="running")
        session.add(batch)
        session.commit()
        session.refresh(batch)
        session.add(PipelineIntegrationBatchItem(batch_id=batch.id, target_id=ok_id, status="pending"))
        session.commit()
        batch_id = batch.id

        target = session.get(Target, ok_id)
        session.delete(target)
        session.commit()

    monkeypatch.setattr(pipeline_tasks, "engine", engine)
    monkeypatch.setattr(pipeline_tasks, "INTER_ITEM_DELAY_SECONDS", 0)

    # Runs the task function directly (not through Celery/.delay) against a
    # batch whose sole item's target row no longer exists.
    pipeline_tasks.run_pipeline_integration_batch(batch_id=batch_id)

    with Session(engine) as session:
        refreshed = session.get(PipelineIntegrationBatch, batch_id)
        assert refreshed.status == "completed"
        assert refreshed.failed == 1
