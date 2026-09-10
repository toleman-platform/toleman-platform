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


def test_repo_sync_task_is_registered_in_beat_schedule():
    """The reliable backstop for installation_repositories (see
    celery_app.py's comment): that webhook event turned out not to be
    something this deployment could actually get GitHub to deliver, so a
    periodic poll is the real guarantee that a newly-granted repo gets a
    Target within a bounded time regardless."""
    entry = celery_app.conf.beat_schedule["sync-github-repos"]
    assert entry["task"] == "app.tasks.github_sync_tasks.sync_repos_task"


# ---------------------------------------------------------------------------
# Startup catch-up: Beat's 24h schedule alone leaves a target with no
# baseline stuck that way for up to 24h after every deploy (a fresh
# timedelta schedule's first tick isn't immediately due -- Beat records the
# schedule's own creation time as "last run"). queue_full_scan_for_targets_
# missing_a_baseline, dispatched once on worker_ready, closes that gap.
# ---------------------------------------------------------------------------


def test_has_completed_scan_false_with_no_scan_at_all(engine):
    with Session(engine) as session:
        ws = _make_workspace(session)
        target = Target(workspace_id=ws.id, name="repo", repo_url="https://github.com/acme/repo")
        session.add(target)
        session.commit()
        session.refresh(target)

        assert scan_tasks._has_completed_scan(session, target) is False


def test_has_completed_scan_true_once_one_exists(engine):
    with Session(engine) as session:
        ws = _make_workspace(session)
        target = Target(workspace_id=ws.id, name="repo", repo_url="https://github.com/acme/repo", default_branch="main")
        session.add(target)
        session.commit()
        session.refresh(target)
        session.add(Scan(target_id=target.id, tool="semgrep", branch="main", status="completed"))
        session.commit()

        assert scan_tasks._has_completed_scan(session, target) is True


def test_has_completed_scan_ignores_a_still_running_scan(engine):
    """A "running" row means a scan is in flight, not that one has ever
    finished; treating it as a baseline would let the catch-up pass and the
    real scan race each other into believing the other already handled it."""
    with Session(engine) as session:
        ws = _make_workspace(session)
        target = Target(workspace_id=ws.id, name="repo", repo_url="https://github.com/acme/repo", default_branch="main")
        session.add(target)
        session.commit()
        session.refresh(target)
        session.add(Scan(target_id=target.id, tool="semgrep", branch="main", status="running"))
        session.commit()

        assert scan_tasks._has_completed_scan(session, target) is False


def test_catch_up_only_queues_targets_missing_a_baseline(engine, monkeypatch):
    monkeypatch.setattr(scan_tasks, "tools_for_surface", lambda session, workspace_id, surface: ["semgrep"])
    mock_delay = MagicMock()
    monkeypatch.setattr(scan_tasks.run_scan, "delay", mock_delay)

    with Session(engine) as session:
        ws = _make_workspace(session)
        has_baseline = Target(workspace_id=ws.id, name="has-baseline", repo_url="https://github.com/acme/a", default_branch="main")
        missing_baseline = Target(workspace_id=ws.id, name="missing-baseline", repo_url="https://github.com/acme/b", default_branch="main")
        session.add(has_baseline)
        session.add(missing_baseline)
        session.commit()
        session.refresh(has_baseline)
        session.refresh(missing_baseline)
        session.add(Scan(target_id=has_baseline.id, tool="semgrep", branch="main", status="completed"))
        session.commit()

        queued = scan_tasks.queue_full_scan_for_targets_missing_a_baseline(session)

        assert len(queued) == 1
        mock_delay.assert_called_once()
        assert mock_delay.call_args.kwargs["target_id"] == missing_baseline.id


def test_catch_up_is_a_noop_when_every_target_already_has_a_baseline(engine, monkeypatch):
    monkeypatch.setattr(scan_tasks, "tools_for_surface", lambda session, workspace_id, surface: ["semgrep"])
    mock_delay = MagicMock()
    monkeypatch.setattr(scan_tasks.run_scan, "delay", mock_delay)

    with Session(engine) as session:
        ws = _make_workspace(session)
        target = Target(workspace_id=ws.id, name="repo", repo_url="https://github.com/acme/repo", default_branch="main")
        session.add(target)
        session.commit()
        session.refresh(target)
        session.add(Scan(target_id=target.id, tool="semgrep", branch="main", status="completed"))
        session.commit()

        assert scan_tasks.queue_full_scan_for_targets_missing_a_baseline(session) == []
    mock_delay.assert_not_called()


def test_catch_up_does_not_abort_on_one_targets_dispatch_failure(engine, monkeypatch):
    """One target's tools_for_surface (or dispatch) blowing up must not stop
    the catch-up pass from reaching every other target missing a baseline --
    same "one bad target can't block another" property run_scheduled_full_
    scans already has for its own loop."""
    call_count = {"n": 0}

    def _flaky(session, workspace_id, surface):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("boom")
        return ["semgrep"]

    monkeypatch.setattr(scan_tasks, "tools_for_surface", _flaky)
    mock_delay = MagicMock()
    monkeypatch.setattr(scan_tasks.run_scan, "delay", mock_delay)

    with Session(engine) as session:
        ws = _make_workspace(session)
        session.add(Target(workspace_id=ws.id, name="a", repo_url="https://github.com/acme/a"))
        session.add(Target(workspace_id=ws.id, name="b", repo_url="https://github.com/acme/b"))
        session.commit()

        # Must not raise.
        queued = scan_tasks.queue_full_scan_for_targets_missing_a_baseline(session)

    assert len(queued) == 1
    mock_delay.assert_called_once()


def test_worker_ready_triggers_the_catch_up_pass(monkeypatch):
    """The signal handler itself: calling it must reach the catch-up pass
    (not just that the pass works when called directly, the tests above).
    The patched pass never touches its session argument, so the real
    (unconfigured, in this test environment) engine the handler opens a
    Session against is never actually connected to."""
    import app.tasks.celery_app as celery_app_module

    called = {}
    monkeypatch.setattr(
        scan_tasks, "queue_full_scan_for_targets_missing_a_baseline",
        lambda session: called.setdefault("ran", True) or [],
    )

    celery_app_module._queue_missing_baseline_scans()

    assert called.get("ran") is True


def test_worker_ready_handler_does_not_raise_if_the_catch_up_pass_blows_up(monkeypatch):
    """Startup must never crash the worker over this; it's a best-effort
    catch-up, not a required boot step."""
    import app.tasks.celery_app as celery_app_module

    def _boom(session):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(scan_tasks, "queue_full_scan_for_targets_missing_a_baseline", _boom)

    celery_app_module._queue_missing_baseline_scans()  # must not raise


def test_worker_ready_also_triggers_a_repo_sync(monkeypatch):
    """Same first-tick gap as the baseline catch-up above, for
    sync-github-repos: without this, a fresh deploy waits up to 24h for the
    first repo-sync pass."""
    import app.tasks.celery_app as celery_app_module
    import app.tasks.github_sync_tasks as github_sync_tasks_module

    monkeypatch.setattr(
        scan_tasks, "queue_full_scan_for_targets_missing_a_baseline", lambda session: []
    )
    called = {}
    monkeypatch.setattr(
        github_sync_tasks_module, "sync_repos_task", lambda: called.setdefault("ran", True)
    )

    celery_app_module._queue_missing_baseline_scans()

    assert called.get("ran") is True


def test_worker_ready_handler_does_not_raise_if_the_repo_sync_pass_blows_up(monkeypatch):
    """Same never-crash-the-worker guarantee as the baseline catch-up, for
    the repo-sync catch-up."""
    import app.tasks.celery_app as celery_app_module
    import app.tasks.github_sync_tasks as github_sync_tasks_module

    monkeypatch.setattr(
        scan_tasks, "queue_full_scan_for_targets_missing_a_baseline", lambda session: []
    )

    def _boom():
        raise RuntimeError("kaboom")

    monkeypatch.setattr(github_sync_tasks_module, "sync_repos_task", _boom)

    celery_app_module._queue_missing_baseline_scans()  # must not raise
