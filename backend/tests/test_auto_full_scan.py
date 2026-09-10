"""Tests for GH-07's other half: a target's default-branch baseline should
not depend on someone happening to click Scan.

Two pieces:
  - app.tasks.scan_tasks.queue_full_scan: dispatch one Scan per
    on_demand_scan-enabled tool against a target's default branch.
  - app.api.github_app._sync_repos calls it for every newly-imported repo,
    so a GitHub App sync leaves each new target with a real scan in flight
    instead of "no baseline yet" being a permanent state.

The 24h beat schedule itself (app.tasks.scan_tasks.run_scheduled_full_scans)
is covered by test_celery_task_routing.py's registration check plus the
beat_schedule assertion below; its per-target dispatch loop is exactly
queue_full_scan, already covered.
"""
from unittest.mock import MagicMock

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from app.core.crypto import encrypt_secret
from app.models.models import GitHubAppConfig, GitHubInstallation, Organization, Scan, Target, Workspace
from app.tasks import scan_tasks
from app.tasks.celery_app import celery_app


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    return eng


def _make_workspace(session) -> Workspace:
    org = Organization(name="org")
    session.add(org)
    session.commit()
    session.refresh(org)
    ws = Workspace(organization_id=org.id, name="ws", api_key="k")
    session.add(ws)
    session.commit()
    session.refresh(ws)
    return ws


# ---------------------------------------------------------------------------
# queue_full_scan
# ---------------------------------------------------------------------------


def test_queue_full_scan_dispatches_one_scan_per_enabled_tool(engine, monkeypatch):
    monkeypatch.setattr(scan_tasks, "tools_for_surface", lambda session, workspace_id, surface: ["semgrep", "trivy"])
    mock_delay = MagicMock()
    monkeypatch.setattr(scan_tasks.run_scan, "delay", mock_delay)

    with Session(engine) as session:
        ws = _make_workspace(session)
        target = Target(workspace_id=ws.id, name="repo", repo_url="https://github.com/acme/repo", default_branch="main")
        session.add(target)
        session.commit()
        session.refresh(target)

        scan_ids = scan_tasks.queue_full_scan(session, target)

        assert len(scan_ids) == 2
        assert mock_delay.call_count == 2
        dispatched_tools = {c.kwargs["tool"] for c in mock_delay.call_args_list}
        assert dispatched_tools == {"semgrep", "trivy"}
        for call in mock_delay.call_args_list:
            assert call.kwargs["target_id"] == target.id
            assert call.kwargs["scan_id"] in scan_ids


def test_queue_full_scan_is_a_silent_noop_with_nothing_enabled(engine, monkeypatch):
    """No tools enabled for on_demand_scan is a legitimate workspace state
    (mirrors the frontend's scan-buttons.tsx rendering nothing), not an
    error -- must not raise, fall back to a default tool, or dispatch
    anything."""
    monkeypatch.setattr(scan_tasks, "tools_for_surface", lambda session, workspace_id, surface: [])
    mock_delay = MagicMock()
    monkeypatch.setattr(scan_tasks.run_scan, "delay", mock_delay)

    with Session(engine) as session:
        ws = _make_workspace(session)
        target = Target(workspace_id=ws.id, name="repo", repo_url="https://github.com/acme/repo")
        session.add(target)
        session.commit()
        session.refresh(target)

        assert scan_tasks.queue_full_scan(session, target) == []
    mock_delay.assert_not_called()


def test_queue_full_scan_uses_the_targets_default_branch(engine, monkeypatch):
    monkeypatch.setattr(scan_tasks, "tools_for_surface", lambda session, workspace_id, surface: ["semgrep"])
    monkeypatch.setattr(scan_tasks.run_scan, "delay", MagicMock())

    with Session(engine) as session:
        ws = _make_workspace(session)
        target = Target(
            workspace_id=ws.id, name="repo", repo_url="https://github.com/acme/repo", default_branch="develop",
        )
        session.add(target)
        session.commit()
        session.refresh(target)

        scan_tasks.queue_full_scan(session, target)

        rows = session.exec(select(Scan).where(Scan.target_id == target.id)).all()
        assert len(rows) == 1
        assert rows[0].branch == "develop"
        assert rows[0].status == "running"


# ---------------------------------------------------------------------------
# GitHub App sync triggers it for every newly-imported repo
# ---------------------------------------------------------------------------


def _make_config(session) -> GitHubAppConfig:
    cfg = GitHubAppConfig(
        app_id="1", slug="toleman-app", client_id="cid", client_secret="csecret",
        private_key_pem="pem", webhook_secret=encrypt_secret(""), html_url="https://github.com/apps/toleman-app",
    )
    session.add(cfg)
    session.commit()
    session.refresh(cfg)
    return cfg


def test_github_sync_queues_a_full_scan_for_every_new_target(engine, monkeypatch):
    import app.api.github_app as github_app_module

    monkeypatch.setattr(github_app_module, "get_installation_token", lambda config, installation_id: "tok")
    monkeypatch.setattr(
        github_app_module, "list_installation_repos",
        lambda token: [{"name": "widgets", "clone_url": "https://github.com/acme/widgets.git", "default_branch": "main", "private": False}],
    )
    mock_queue_full_scan = MagicMock(return_value=[])
    monkeypatch.setattr(github_app_module, "queue_full_scan", mock_queue_full_scan)
    monkeypatch.setattr(github_app_module, "queue_dependency_graph_sync", lambda session, target: False)

    with Session(engine) as session:
        ws = _make_workspace(session)
        cfg = _make_config(session)
        inst = GitHubInstallation(
            installation_id=1, account_login="acme", account_type="Organization",
            workspace_id=ws.id, github_app_config_id=cfg.id,
        )
        session.add(inst)
        session.commit()

        created = github_app_module._sync_repos(session)

        assert created == 1
        mock_queue_full_scan.assert_called_once()
        called_target = mock_queue_full_scan.call_args[0][1]
        assert called_target.repo_url == "https://github.com/acme/widgets.git"


# ---------------------------------------------------------------------------
# Beat schedule wiring
# ---------------------------------------------------------------------------


def test_scheduled_full_scan_task_is_registered_in_beat_schedule():
    entry = celery_app.conf.beat_schedule["run-scheduled-full-scans"]
    assert entry["task"] == "app.tasks.scan_tasks.run_scheduled_full_scans"
