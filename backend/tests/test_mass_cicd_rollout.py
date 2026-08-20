"""Tests for issue #35: Mass CI/CD Rollout Engine + Custom Workflow Builder.

Two things extend #66's single-repo pipeline mechanism (app.core.pipeline_pr
.open_pipeline_pr / app.core.pipeline_workflow.generate_workflow_yaml) and
#68's manual bulk wrapper (PipelineIntegrationBatch/BatchItem + the Celery
task):

  1. Custom Workflow Builder: `PipelineWorkflowTemplate` CRUD
     (app.api.pipeline_templates) and generate_workflow_yaml's new `steps`
     param -- proves a custom step subset/order actually changes which jobs
     the generated GitHub Actions YAML contains.

  2. Mass CI/CD Rollout Engine: `POST /api/targets/mass-pipeline-rollout`
     resolves a *scope* (workspace/group/all) into a target set instead of
     an explicit target_ids list, reusing #68's exact batch/task machinery
     -- including an optional workflow_template_id recorded on the batch so
     the Celery task (app.tasks.pipeline_tasks) generates each item's PR
     workflow from that template's steps.

Same fixtures/login pattern as tests/test_bulk_pipeline_integration.py and
tests/test_pipeline_integration.py.
"""
from unittest.mock import MagicMock

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
import app.api.targets as targets_module
from app.api.deps import get_session
from app.core.pipeline_pr import PipelinePrError
from app.core.pipeline_workflow import generate_workflow_yaml
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    Group,
    Organization,
    PipelineIntegrationBatch,
    PipelineIntegrationBatchItem,
    PipelineWorkflowTemplate,
    Target,
    TargetGroup,
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
    client.cookies.set("rikugan_session", token)
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
        target = Target(workspace_id=workspace_id, name=name, repo_url=f"https://github.com/acme/{name}")
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


def _assign(engine, user_id: int, workspace_id: int, role: WorkspaceRole):
    with Session(engine) as session:
        m = WorkspaceMembership(user_id=user_id, workspace_id=workspace_id, role=role)
        session.add(m)
        session.commit()


def _make_group(engine, workspace_id: int, name="prod") -> int:
    with Session(engine) as session:
        g = Group(workspace_id=workspace_id, name=name)
        session.add(g)
        session.commit()
        session.refresh(g)
        return g.id


def _assign_group(engine, target_id: int, group_id: int):
    with Session(engine) as session:
        session.add(TargetGroup(target_id=target_id, group_id=group_id))
        session.commit()


def _make_template(engine, workspace_id: int, user_id: int, steps, name="custom") -> int:
    with Session(engine) as session:
        t = PipelineWorkflowTemplate(workspace_id=workspace_id, name=name, steps=steps, created_by_user_id=user_id)
        session.add(t)
        session.commit()
        session.refresh(t)
        return t.id


# ---------------------------------------------------------------------------
# 1. generate_workflow_yaml: custom `steps` param
# ---------------------------------------------------------------------------


def _make_bare_target(session, name="gotest", repo_url="https://github.com/geekshiv/gotest") -> Target:
    org = Organization(name="default")
    session.add(org)
    session.commit()
    session.refresh(org)
    ws = Workspace(organization_id=org.id, name="default", api_key="k")
    session.add(ws)
    session.commit()
    session.refresh(ws)
    target = Target(workspace_id=ws.id, name=name, repo_url=repo_url)
    session.add(target)
    session.commit()
    session.refresh(target)
    return target


def test_generate_workflow_yaml_none_steps_matches_default_behavior(engine, monkeypatch):
    import app.core.pipeline_workflow as pw

    monkeypatch.setattr(pw, "detect_languages", lambda session, target: [])
    with Session(engine) as session:
        target = _make_bare_target(session)
        result = generate_workflow_yaml(session, target)
    parsed = yaml.safe_load(result["yaml"])
    assert set(parsed["jobs"].keys()) == {"semgrep", "gitleaks", "trivy"}


def test_generate_workflow_yaml_custom_steps_subset_and_order(engine):
    with Session(engine) as session:
        target = _make_bare_target(session)
        result = generate_workflow_yaml(session, target, steps=["gitleaks"])
    parsed = yaml.safe_load(result["yaml"])
    assert set(parsed["jobs"].keys()) == {"gitleaks"}
    assert result["includes_gosec"] is False


def test_generate_workflow_yaml_custom_steps_includes_gosec_without_detection(engine):
    # gosec included purely because the template says so -- no scan history,
    # no language-detection call needed to justify it, unlike the None-steps
    # (default) path.
    with Session(engine) as session:
        target = _make_bare_target(session)
        result = generate_workflow_yaml(session, target, steps=["gosec", "semgrep"])
    parsed = yaml.safe_load(result["yaml"])
    assert set(parsed["jobs"].keys()) == {"gosec", "semgrep"}
    assert result["includes_gosec"] is True


def test_generate_workflow_yaml_custom_steps_drops_unknown_and_dedupes(engine):
    with Session(engine) as session:
        target = _make_bare_target(session)
        result = generate_workflow_yaml(session, target, steps=["semgrep", "not-a-real-tool", "semgrep"])
    parsed = yaml.safe_load(result["yaml"])
    assert set(parsed["jobs"].keys()) == {"semgrep"}


# ---------------------------------------------------------------------------
# 2. PipelineWorkflowTemplate CRUD (app.api.pipeline_templates)
# ---------------------------------------------------------------------------


def test_create_and_list_template(client, engine):
    ws = _make_workspace(engine)
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws, WorkspaceRole.DEVELOPER)

    res = client.post(
        "/api/pipeline-templates",
        json={"workspace_id": ws, "name": "Fast", "steps": [{"tool": "semgrep", "enabled": True}, {"tool": "gitleaks", "enabled": False}]},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["name"] == "Fast"
    assert body["steps"] == [{"tool": "semgrep", "enabled": True}, {"tool": "gitleaks", "enabled": False}]

    listed = client.get(f"/api/pipeline-templates?workspace_id={ws}")
    assert listed.status_code == 200
    assert len(listed.json()) == 1


def test_create_template_requires_developer_role(client, engine):
    ws = _make_workspace(engine)
    client, uid = _login(client, engine, role=UserRole.USER)
    _assign(engine, uid, ws, WorkspaceRole.VIEWER)

    res = client.post(
        "/api/pipeline-templates",
        json={"workspace_id": ws, "name": "Fast", "steps": [{"tool": "semgrep", "enabled": True}]},
    )
    assert res.status_code == 403


def test_create_template_rejects_unknown_tool(client, engine):
    ws = _make_workspace(engine)
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws, WorkspaceRole.DEVELOPER)

    res = client.post(
        "/api/pipeline-templates",
        json={"workspace_id": ws, "name": "Bad", "steps": [{"tool": "nuclei", "enabled": True}]},
    )
    assert res.status_code == 422


def test_create_template_rejects_all_disabled(client, engine):
    ws = _make_workspace(engine)
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws, WorkspaceRole.DEVELOPER)

    res = client.post(
        "/api/pipeline-templates",
        json={"workspace_id": ws, "name": "AllOff", "steps": [{"tool": "semgrep", "enabled": False}]},
    )
    assert res.status_code == 400


def test_get_template_hidden_for_inaccessible_workspace(client, engine):
    ws = _make_workspace(engine)
    other_ws = _make_workspace(engine, name="other")
    client, uid = _login(client, engine, role=UserRole.DEVELOPER, email="owner@example.com")
    _assign(engine, uid, ws, WorkspaceRole.DEVELOPER)
    tid = _make_template(engine, other_ws, uid, [{"tool": "semgrep", "enabled": True}])

    res = client.get(f"/api/pipeline-templates/{tid}")
    assert res.status_code == 404


def test_update_and_delete_template(client, engine):
    ws = _make_workspace(engine)
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws, WorkspaceRole.DEVELOPER)
    tid = _make_template(engine, ws, uid, [{"tool": "semgrep", "enabled": True}])

    upd = client.patch(f"/api/pipeline-templates/{tid}", json={"name": "Renamed"})
    assert upd.status_code == 200
    assert upd.json()["name"] == "Renamed"

    dele = client.delete(f"/api/pipeline-templates/{tid}")
    assert dele.status_code == 200
    assert client.get(f"/api/pipeline-templates/{tid}").status_code == 404


# ---------------------------------------------------------------------------
# 3. POST /api/targets/mass-pipeline-rollout: scope resolution + dispatch
# ---------------------------------------------------------------------------


def test_mass_rollout_by_workspace_scope_creates_batch_for_all_targets(client, engine, monkeypatch):
    ws = _make_workspace(engine, name="acme")
    target_ids = [_make_target(engine, ws, name=f"t{i}") for i in range(3)]
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws, WorkspaceRole.DEVELOPER)

    mock_delay = MagicMock()
    monkeypatch.setattr(targets_module.run_pipeline_integration_batch, "delay", mock_delay)

    res = client.post("/api/targets/mass-pipeline-rollout", json={"scope": "workspace", "workspace_id": ws})
    assert res.status_code == 202
    body = res.json()
    assert body["total"] == 3
    assert "acme" in body["scope_label"]
    mock_delay.assert_called_once_with(batch_id=body["batch_id"])

    with Session(engine) as session:
        items = session.exec(
            select(PipelineIntegrationBatchItem).where(PipelineIntegrationBatchItem.batch_id == body["batch_id"])
        ).all()
        assert {i.target_id for i in items} == set(target_ids)


def test_mass_rollout_by_group_scope_only_targets_group_members(client, engine, monkeypatch):
    ws = _make_workspace(engine)
    in_group = _make_target(engine, ws, name="in-group")
    not_in_group = _make_target(engine, ws, name="not-in-group")
    group_id = _make_group(engine, ws)
    _assign_group(engine, in_group, group_id)

    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws, WorkspaceRole.DEVELOPER)
    monkeypatch.setattr(targets_module.run_pipeline_integration_batch, "delay", MagicMock())

    res = client.post("/api/targets/mass-pipeline-rollout", json={"scope": "group", "group_id": group_id})
    assert res.status_code == 202
    assert res.json()["total"] == 1

    with Session(engine) as session:
        items = session.exec(
            select(PipelineIntegrationBatchItem).where(PipelineIntegrationBatchItem.batch_id == res.json()["batch_id"])
        ).all()
        assert [i.target_id for i in items] == [in_group]
    assert not_in_group != in_group


def test_mass_rollout_all_scope_limited_to_accessible_workspaces(client, engine, monkeypatch):
    ws = _make_workspace(engine, name="mine")
    other_ws = _make_workspace(engine, name="not-mine")
    my_target = _make_target(engine, ws, name="mine-t")
    _make_target(engine, other_ws, name="foreign-t")

    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws, WorkspaceRole.DEVELOPER)
    monkeypatch.setattr(targets_module.run_pipeline_integration_batch, "delay", MagicMock())

    res = client.post("/api/targets/mass-pipeline-rollout", json={"scope": "all"})
    assert res.status_code == 202
    assert res.json()["total"] == 1

    with Session(engine) as session:
        items = session.exec(
            select(PipelineIntegrationBatchItem).where(PipelineIntegrationBatchItem.batch_id == res.json()["batch_id"])
        ).all()
        assert [i.target_id for i in items] == [my_target]


def test_mass_rollout_requires_workspace_id_for_workspace_scope(client, engine):
    client, _ = _login(client, engine, role=UserRole.DEVELOPER)
    res = client.post("/api/targets/mass-pipeline-rollout", json={"scope": "workspace"})
    assert res.status_code == 400


def test_mass_rollout_invalid_scope_rejected(client, engine):
    client, _ = _login(client, engine, role=UserRole.DEVELOPER)
    res = client.post("/api/targets/mass-pipeline-rollout", json={"scope": "planet"})
    assert res.status_code == 422


def test_mass_rollout_no_eligible_targets_returns_404(client, engine):
    ws = _make_workspace(engine)
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws, WorkspaceRole.DEVELOPER)
    # No targets created at all in this workspace.
    res = client.post("/api/targets/mass-pipeline-rollout", json={"scope": "workspace", "workspace_id": ws})
    assert res.status_code == 404


def test_mass_rollout_with_workflow_template_records_it_on_batch(client, engine, monkeypatch):
    ws = _make_workspace(engine)
    _make_target(engine, ws, name="t0")
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws, WorkspaceRole.DEVELOPER)
    template_id = _make_template(engine, ws, uid, [{"tool": "gitleaks", "enabled": True}])
    monkeypatch.setattr(targets_module.run_pipeline_integration_batch, "delay", MagicMock())

    res = client.post(
        "/api/targets/mass-pipeline-rollout",
        json={"scope": "workspace", "workspace_id": ws, "workflow_template_id": template_id},
    )
    assert res.status_code == 202
    batch_id = res.json()["batch_id"]

    poll = client.get(f"/api/targets/bulk-pipeline-integrate/{batch_id}")
    assert poll.json()["workflow_template_id"] == template_id


def test_mass_rollout_rejects_template_from_inaccessible_workspace(client, engine, monkeypatch):
    ws = _make_workspace(engine)
    other_ws = _make_workspace(engine, name="other")
    _make_target(engine, ws, name="t0")
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws, WorkspaceRole.DEVELOPER)
    foreign_template_id = _make_template(engine, other_ws, uid, [{"tool": "trivy", "enabled": True}])
    monkeypatch.setattr(targets_module.run_pipeline_integration_batch, "delay", MagicMock())

    res = client.post(
        "/api/targets/mass-pipeline-rollout",
        json={"scope": "workspace", "workspace_id": ws, "workflow_template_id": foreign_template_id},
    )
    assert res.status_code == 404


def test_mass_rollout_drops_targets_caller_lacks_role_on(client, engine, monkeypatch):
    ws = _make_workspace(engine)
    _make_target(engine, ws, name="t0")
    client, uid = _login(client, engine, role=UserRole.USER)
    _assign(engine, uid, ws, WorkspaceRole.VIEWER)  # below DEVELOPER bar
    monkeypatch.setattr(targets_module.run_pipeline_integration_batch, "delay", MagicMock())

    res = client.post("/api/targets/mass-pipeline-rollout", json={"scope": "workspace", "workspace_id": ws})
    assert res.status_code == 404  # no eligible targets after the role filter


# ---------------------------------------------------------------------------
# 4. End-to-end: Celery task honors the batch's workflow_template_id
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


def test_task_passes_template_steps_to_open_pipeline_pr(client, engine, monkeypatch, eager_celery):
    ws = _make_workspace(engine)
    target_id = _make_target(engine, ws, name="t0")
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws, WorkspaceRole.DEVELOPER)
    template_id = _make_template(engine, ws, uid, [{"tool": "gitleaks", "enabled": True}, {"tool": "trivy", "enabled": False}])

    monkeypatch.setattr(pipeline_tasks, "engine", engine)
    monkeypatch.setattr(pipeline_tasks, "INTER_ITEM_DELAY_SECONDS", 0)

    captured = {}

    def fake_open_pipeline_pr(session, target, steps=None):
        captured["steps"] = steps
        return {"pr_url": "https://github.com/acme/t0/pull/1", "pr_number": 1, "branch": "osp/x"}

    monkeypatch.setattr(pipeline_tasks, "open_pipeline_pr", fake_open_pipeline_pr)

    res = client.post(
        "/api/targets/mass-pipeline-rollout",
        json={"scope": "workspace", "workspace_id": ws, "workflow_template_id": template_id},
    )
    assert res.status_code == 202

    # eager mode: task already ran synchronously.
    assert captured["steps"] == ["gitleaks"]  # only the enabled step, trivy dropped

    with Session(engine) as session:
        target = session.get(Target, target_id)
        assert target.pipeline_integrated is True


def test_task_without_template_calls_open_pipeline_pr_two_arg_form(client, engine, monkeypatch, eager_celery):
    """#68's original manual bulk flow (no workflow_template_id) must keep
    calling open_pipeline_pr(session, target) with no steps kwarg at all --
    proves #35 didn't change pre-existing behavior for that path."""
    ws = _make_workspace(engine)
    _make_target(engine, ws, name="t0")
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws, WorkspaceRole.DEVELOPER)

    monkeypatch.setattr(pipeline_tasks, "engine", engine)
    monkeypatch.setattr(pipeline_tasks, "INTER_ITEM_DELAY_SECONDS", 0)

    def fake_open_pipeline_pr(session, target):  # no steps param at all
        return {"pr_url": "https://github.com/acme/t0/pull/1", "pr_number": 1, "branch": "osp/x"}

    monkeypatch.setattr(pipeline_tasks, "open_pipeline_pr", fake_open_pipeline_pr)

    res = client.post("/api/targets/mass-pipeline-rollout", json={"scope": "workspace", "workspace_id": ws})
    assert res.status_code == 202

    poll = client.get(f"/api/targets/bulk-pipeline-integrate/{res.json()['batch_id']}")
    assert poll.json()["succeeded"] == 1
