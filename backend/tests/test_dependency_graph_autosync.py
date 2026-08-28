"""Tests for issue #330: a target's GitHub Dependency Graph is imported
automatically when the target is created, and the outcome is recorded on
the Target row instead of being lost with the Celery result.

Same two layers as tests/test_celery_offload.py:

  1. Dispatch tests: mock sync_dependency_graph.delay() to prove
     POST /api/targets queues the import and marks the row "pending",
     and that a non-github.com repo_url queues nothing at all.

  2. Eager-mode tests: run the task in-process with only
     fetch_dependency_graph monkeypatched, proving each outcome lands in
     the row. The unavailable case is the one that matters: GitHub
     declining to answer must never be recorded as an empty inventory.
"""
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.github_dependency_graph import DependencyGraphUnavailable
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    Organization,
    SbomComponent,
    Target,
    User,
    UserRole,
    Workspace,
    WorkspaceMembership,
    WorkspaceRole,
)
from app.tasks import sbom_tasks


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


def _dev_client(client, engine):
    with Session(engine) as session:
        org = Organization(name="org")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws", api_key="key")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        ws_id = ws.id
        user = User(
            email="dev@example.com", name="Dev",
            password_hash=hash_password("whatever123"), role=UserRole.DEVELOPER,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        session.add(WorkspaceMembership(user_id=user.id, workspace_id=ws_id, role=WorkspaceRole.DEVELOPER))
        session.commit()
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return client, ws_id


def _make_target(engine, workspace_id: int, repo_url="https://github.com/acme/repo") -> int:
    with Session(engine) as session:
        target = Target(workspace_id=workspace_id, name="t", repo_url=repo_url)
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


# ---------------------------------------------------------------------------
# 1. Dispatch
# ---------------------------------------------------------------------------


def test_create_target_queues_graph_sync_and_marks_pending(client, engine, monkeypatch):
    client, ws_id = _dev_client(client, engine)
    mock_delay = MagicMock()
    monkeypatch.setattr(sbom_tasks.sync_dependency_graph, "delay", mock_delay)

    response = client.post("/api/targets", json={
        "workspace_id": ws_id, "name": "repo", "repo_url": "https://github.com/acme/repo",
    })

    assert response.status_code == 200
    body = response.json()
    assert body["dependency_sync_status"] == "pending"
    mock_delay.assert_called_once_with(body["id"])


def test_queue_skips_a_non_github_target(engine, monkeypatch):
    """POST /api/targets already rejects a non-github.com repo_url, so this
    gate is reached through _sync_repos and through rows created before that
    validator existed. It must leave the status NULL, not "unavailable":
    nothing was attempted, so nothing is known."""
    mock_delay = MagicMock()
    monkeypatch.setattr(sbom_tasks.sync_dependency_graph, "delay", mock_delay)
    with Session(engine) as session:
        org = Organization(name="org-gl")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws-gl", api_key="key-gl")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        target = Target(workspace_id=ws.id, name="t", repo_url="https://gitlab.com/acme/repo")
        session.add(target)
        session.commit()
        session.refresh(target)

        assert sbom_tasks.queue_dependency_graph_sync(session, target) is False
        assert target.dependency_sync_status is None
    mock_delay.assert_not_called()


def test_broker_failure_does_not_leave_the_target_stuck_pending(engine, monkeypatch):
    """Nothing will ever pick up a "pending" row whose dispatch never
    reached the broker, so the row records the dispatch failure instead of
    claiming an import is in flight. Target creation itself still succeeds:
    the target is a usable row with or without its inventory."""
    def _broker_down(_target_id):
        raise OSError("Connection refused")

    monkeypatch.setattr(sbom_tasks.sync_dependency_graph, "delay", _broker_down)
    with Session(engine) as session:
        org = Organization(name="org-b")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws-b", api_key="key-b")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        target = Target(workspace_id=ws.id, name="t", repo_url="https://github.com/acme/repo")
        session.add(target)
        session.commit()
        session.refresh(target)

        assert sbom_tasks.queue_dependency_graph_sync(session, target) is False
        assert target.dependency_sync_status == "failed"
        assert "Connection refused" in target.dependency_sync_error


def test_lookalike_host_is_not_treated_as_github():
    assert sbom_tasks._is_github_repo("https://github.com/acme/repo") is True
    assert sbom_tasks._is_github_repo("https://github.com.evil.test/acme/repo") is False
    assert sbom_tasks._is_github_repo("https://github.com/acme") is False
    # Not every *.github.com host serves repos; gist paths are not owner/repo.
    assert sbom_tasks._is_github_repo("https://gist.github.com/acme/repo") is False


# ---------------------------------------------------------------------------
# 2. Task execution
# ---------------------------------------------------------------------------


def test_sync_records_ok_and_persists_components(engine, monkeypatch):
    monkeypatch.setattr(deps_module, "engine", engine)
    monkeypatch.setattr(sbom_tasks, "engine", engine)
    monkeypatch.setattr(sbom_tasks, "resolve_github_token", lambda *a, **k: None)
    monkeypatch.setattr(sbom_tasks, "fetch_dependency_graph", lambda *a, **k: [
        {"name": "requests", "version": "2.31.0", "package_type": "pypi", "purl": "pkg:pypi/requests@2.31.0"},
    ])
    with Session(engine) as session:
        org = Organization(name="org")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws", api_key="key")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        ws_id = ws.id
    target_id = _make_target(engine, ws_id)

    result = sbom_tasks.sync_dependency_graph(target_id)

    assert result["status"] == "ok"
    with Session(engine) as session:
        target = session.get(Target, target_id)
        assert target.dependency_sync_status == "ok"
        assert target.dependency_component_count == 1
        assert target.dependency_sync_error is None
        assert target.dependency_sync_at is not None
        components = session.query(SbomComponent).filter(SbomComponent.target_id == target_id).all()
        assert [c.name for c in components] == ["requests"]
        assert components[0].source == "github"


def test_unavailable_graph_is_not_recorded_as_an_empty_inventory(engine, monkeypatch):
    monkeypatch.setattr(sbom_tasks, "engine", engine)
    monkeypatch.setattr(sbom_tasks, "resolve_github_token", lambda *a, **k: None)

    def _unavailable(*a, **k):
        raise DependencyGraphUnavailable("GitHub returned 403")

    monkeypatch.setattr(sbom_tasks, "fetch_dependency_graph", _unavailable)
    with Session(engine) as session:
        org = Organization(name="org2")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws2", api_key="key2")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        ws_id = ws.id
    target_id = _make_target(engine, ws_id)

    result = sbom_tasks.sync_dependency_graph(target_id)

    assert result["status"] == "unavailable"
    with Session(engine) as session:
        target = session.get(Target, target_id)
        assert target.dependency_sync_status == "unavailable"
        # The count stays NULL. A 0 here would render as "no dependencies",
        # which is the false all-clear this whole path exists to avoid.
        assert target.dependency_component_count is None
        assert "403" in target.dependency_sync_error


def test_unexpected_error_is_recorded_as_failed(engine, monkeypatch):
    monkeypatch.setattr(sbom_tasks, "engine", engine)
    monkeypatch.setattr(sbom_tasks, "resolve_github_token", lambda *a, **k: None)

    def _boom(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(sbom_tasks, "fetch_dependency_graph", _boom)
    with Session(engine) as session:
        org = Organization(name="org3")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws3", api_key="key3")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        ws_id = ws.id
    target_id = _make_target(engine, ws_id)

    result = sbom_tasks.sync_dependency_graph(target_id)

    assert result["status"] == "failed"
    with Session(engine) as session:
        target = session.get(Target, target_id)
        assert target.dependency_sync_status == "failed"
        assert target.dependency_component_count is None
        assert "kaboom" in target.dependency_sync_error


def test_refuses_a_session_holding_unflushed_work(engine, monkeypatch):
    """The "pending" write has to be committed before .delay() hands the id
    to a worker in another process, so this function commits the caller's
    session. Both current callers commit right before calling it, so that
    commit covers only this function's own write. A caller that still had
    rows queued would have them flushed too, silently and early; refuse
    instead of doing it."""
    mock_delay = MagicMock()
    monkeypatch.setattr(sbom_tasks.sync_dependency_graph, "delay", mock_delay)
    with Session(engine) as session:
        org = Organization(name="org-g")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws-g", api_key="key-g")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        target = Target(workspace_id=ws.id, name="t", repo_url="https://github.com/acme/repo")
        session.add(target)
        session.commit()
        session.refresh(target)

        # A row the caller is still assembling, not yet meant to be visible.
        session.add(Target(workspace_id=ws.id, name="half-built", repo_url="https://github.com/acme/other"))

        with pytest.raises(RuntimeError, match="no other pending inserts or deletes"):
            sbom_tasks.queue_dependency_graph_sync(session, target)
    mock_delay.assert_not_called()
