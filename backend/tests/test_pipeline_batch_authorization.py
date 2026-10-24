"""Batch summaries require access to their entire scope before any read-side write."""
from datetime import timedelta

import pytest
from sqlmodel import Session, select

from tests.conftest import _assign, _login, _make_target, _make_workspace
from app.core.time import utcnow
from app.models.models import (
    PipelineIntegrationBatch,
    PipelineIntegrationBatchItem,
    PipelineWorkflowTemplate,
    Target,
    UserRole,
    WorkspaceMembership,
    WorkspaceRole,
)


def _batch(engine, owner_id, target_ids, **overrides):
    with Session(engine) as session:
        batch = PipelineIntegrationBatch(
            created_by_user_id=owner_id, total=len(target_ids),
            scope_label="Workspace: private-payments-prod", **overrides,
        )
        session.add(batch)
        session.commit()
        session.refresh(batch)
        batch_id = batch.id
        for target_id in target_ids:
            session.add(PipelineIntegrationBatchItem(
                batch_id=batch_id, target_id=target_id, status="pending",
                pr_url="https://github.com/private/repo/pull/1",
            ))
        session.commit()
        return batch_id


def test_outsider_cannot_read_or_expire_private_batch(client, engine):
    workspace_id = _make_workspace(engine)
    target_id = _make_target(engine, workspace_id)
    _, owner_id = _login(client, engine, email="owner@example.com")
    batch_id = _batch(engine, owner_id, [target_id], started_at=utcnow() - timedelta(days=1))
    _login(client, engine, email="outsider@example.com")

    assert client.get(f"/api/targets/{target_id}").status_code == 404
    response = client.get(f"/api/targets/bulk-pipeline-integrate/{batch_id}")
    assert response.status_code == 404
    assert response.json() == {"detail": "batch not found"}
    with Session(engine) as session:
        batch = session.get(PipelineIntegrationBatch, batch_id)
        assert batch.status == "running"
        assert batch.completed_at is None


def test_partial_workspace_access_does_not_disclose_batch_aggregates(client, engine):
    workspace_a = _make_workspace(engine, "a")
    workspace_b = _make_workspace(engine, "b")
    target_a = _make_target(engine, workspace_a)
    target_b = _make_target(engine, workspace_b)
    _, uid = _login(client, engine)
    _assign(engine, uid, workspace_a, WorkspaceRole.VIEWER)
    batch_id = _batch(engine, uid, [target_a, target_b])
    assert client.get(f"/api/targets/bulk-pipeline-integrate/{batch_id}").status_code == 404


def test_revoked_creator_cannot_read_batch(client, engine):
    workspace_id = _make_workspace(engine)
    target_id = _make_target(engine, workspace_id)
    _, uid = _login(client, engine)
    _assign(engine, uid, workspace_id, WorkspaceRole.DEVELOPER)
    batch_id = _batch(engine, uid, [target_id])
    assert client.get(f"/api/targets/bulk-pipeline-integrate/{batch_id}").status_code == 200
    with Session(engine) as session:
        membership = session.exec(select(WorkspaceMembership).where(WorkspaceMembership.user_id == uid)).one()
        session.delete(membership)
        session.commit()
    assert client.get(f"/api/targets/bulk-pipeline-integrate/{batch_id}").status_code == 404


def test_viewer_with_full_scope_can_read_another_users_batch(client, engine):
    workspace_id = _make_workspace(engine)
    target_id = _make_target(engine, workspace_id)
    _, owner_id = _login(client, engine, email="owner@example.com")
    batch_id = _batch(engine, owner_id, [target_id])
    _, viewer_id = _login(client, engine, email="viewer@example.com")
    _assign(engine, viewer_id, workspace_id, WorkspaceRole.VIEWER)
    response = client.get(f"/api/targets/bulk-pipeline-integrate/{batch_id}")
    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["target_id"] == target_id


def test_template_workspace_is_part_of_batch_scope(client, engine):
    workspace_id = _make_workspace(engine)
    private_workspace_id = _make_workspace(engine, "private-template")
    target_id = _make_target(engine, workspace_id)
    _, uid = _login(client, engine)
    _assign(engine, uid, workspace_id, WorkspaceRole.VIEWER)
    with Session(engine) as session:
        template = PipelineWorkflowTemplate(
            workspace_id=private_workspace_id, name="private", steps=[], created_by_user_id=uid,
        )
        session.add(template)
        session.commit()
        session.refresh(template)
        template_id = template.id
    batch_id = _batch(engine, uid, [target_id], workflow_template_id=template_id)
    assert client.get(f"/api/targets/bulk-pipeline-integrate/{batch_id}").status_code == 404


@pytest.mark.parametrize("missing_target", [False, True])
def test_unresolvable_scope_fails_closed_for_nonadmin(client, engine, missing_target):
    workspace_id = _make_workspace(engine)
    target_id = _make_target(engine, workspace_id)
    _, uid = _login(client, engine)
    _assign(engine, uid, workspace_id, WorkspaceRole.VIEWER)
    batch_id = _batch(engine, uid, [target_id] if missing_target else [])
    if missing_target:
        with Session(engine) as session:
            session.delete(session.get(Target, target_id))
            session.commit()
    assert client.get(f"/api/targets/bulk-pipeline-integrate/{batch_id}").status_code == 404


def test_admin_can_read_and_expire_empty_batch(client, engine):
    _, uid = _login(client, engine, role=UserRole.ADMIN)
    batch_id = _batch(engine, uid, [], started_at=utcnow() - timedelta(days=1))
    response = client.get(f"/api/targets/bulk-pipeline-integrate/{batch_id}")
    assert response.status_code == 200
    assert response.json()["status"] == "failed"


def test_batch_status_requires_authentication(client, engine):
    _, uid = _login(client, engine)
    batch_id = _batch(engine, uid, [])
    client.cookies.clear()
    assert client.get(f"/api/targets/bulk-pipeline-integrate/{batch_id}").status_code == 401
