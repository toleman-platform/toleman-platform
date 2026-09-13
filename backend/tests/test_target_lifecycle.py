"""Target deactivate / delete (#273).

Before this, a registered target was permanent: `backend/app/api/targets.py`
had GET/POST/PATCH, workspace-key and pipeline-integration routes but no
`DELETE /api/targets/{id}` at all (the only DELETE touching a target removed
it from a *group*), and no flag to stop scanning short of removing it.

What these tests pin, in order of how badly each would fail silently:

1. **Deactivate is enforced at every dispatch point, not in the UI.** A
   target-level "off" that only the frontend honours is not off. Each of the
   ten-ish places a scan can start gets its own test, because the failure
   mode is one forgotten path quietly cloning a repo the operator believes
   is switched off -- and nothing surfaces that.
2. **Soft delete, not cascade.** `Finding`, `Scan` and `PRGuardrailScan` all
   foreign-key to `target_id`. This is a security tool, so "someone deleted
   the record of a finding" has to stay answerable; the rows survive and the
   target disappears from every list, aggregate and dispatch path instead.
   The test that matters most here is the one asserting the Finding rows are
   still in the database afterwards.
3. **Both actions are audited.** Via `log_auth_event`/`AuthAuditLog`, the
   same write path every other destructive platform action uses, and only on
   a real state transition (no duplicate row for a no-op re-POST).
"""

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.main import app as fastapi_app
from app.models.models import (
    ApiToken,
    ApiTokenScope,
    AuthAuditLog,
    AuthEventType,
    DiscoveryRun,
    Finding,
    FindingState,
    Organization,
    PRGuardrailScan,
    PRGuardrailStatus,
    SbomComponent,
    SbomRun,
    Scan,
    Severity,
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
    def override():
        with Session(engine) as session:
            yield session

    fastapi_app.dependency_overrides[get_session] = override
    original = deps_module.engine
    deps_module.engine = engine
    c = TestClient(fastapi_app)
    yield c
    fastapi_app.dependency_overrides.clear()
    deps_module.engine = original


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _workspace(engine) -> int:
    """Each call makes its own Organization + Workspace with a distinct
    api_key. Distinct because the workspace-scoping tests create two, and a
    shared key would make require_workspace resolve either of them -- the
    test would pass for the wrong reason."""
    with Session(engine) as session:
        org = Organization(name="org")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws", api_key="placeholder")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        ws.api_key = f"ws-key-{ws.id}"
        session.add(ws)
        session.commit()
        return ws.id


def _workspace_key(engine, workspace_id: int) -> str:
    with Session(engine) as session:
        return session.get(Workspace, workspace_id).api_key


def _target(engine, workspace_id: int, name: str = "repo", **kw) -> int:
    with Session(engine) as session:
        t = Target(
            workspace_id=workspace_id,
            name=name,
            repo_url=f"https://github.com/acme/{name}",
            default_branch="main",
            **kw,
        )
        session.add(t)
        session.commit()
        session.refresh(t)
        return t.id


def _login(client, engine, *, role=UserRole.ADMIN, workspace_id=None, workspace_role=None, email="a@example.com"):
    with Session(engine) as session:
        user = User(email=email, name="A", password_hash=hash_password("whatever123"), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        if workspace_id is not None and workspace_role is not None:
            session.add(
                WorkspaceMembership(user_id=user.id, workspace_id=workspace_id, role=workspace_role)
            )
            session.commit()
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return client


def _finding(engine, target_id: int, **kw) -> int:
    with Session(engine) as session:
        f = Finding(
            target_id=target_id,
            dedup_hash=f"hash-{target_id}-{kw.get('rule_id', 'r1')}",
            tool="semgrep",
            rule_id=kw.pop("rule_id", "r1"),
            title="hardcoded secret",
            file_path="app/main.py",
            severity=Severity.CRITICAL,
            state=FindingState.OPEN,
            branch="main",
            **kw,
        )
        session.add(f)
        session.commit()
        session.refresh(f)
        return f.id


def _api_token(engine, *, scope=ApiTokenScope.READ_WRITE, email="tok@example.com") -> str:
    """A Bearer token for the public API, plus the admin user behind it.
    Same shape as test_public_api.py's own helper."""
    from app.core.security import generate_api_token

    plaintext, token_hash, token_prefix = generate_api_token()
    with Session(engine) as session:
        user = User(email=email, name="T", password_hash=hash_password("whatever123"), role=UserRole.ADMIN)
        session.add(user)
        session.commit()
        session.refresh(user)
        session.add(
            ApiToken(user_id=user.id, name="t", token_hash=token_hash, token_prefix=token_prefix, scope=scope)
        )
        session.commit()
    return plaintext


def _deactivate(engine, target_id: int) -> None:
    """Flip the flag directly, for tests whose subject is a dispatch path
    rather than the endpoint that sets it."""
    from app.core import target_lifecycle

    with Session(engine) as session:
        target_lifecycle.deactivate(session.get(Target, target_id))
        session.commit()


def _soft_delete(engine, target_id: int) -> None:
    from app.core import target_lifecycle

    with Session(engine) as session:
        target_lifecycle.soft_delete(session.get(Target, target_id))
        session.commit()


def _audit_rows(engine, event_type: AuthEventType) -> list[AuthAuditLog]:
    with Session(engine) as session:
        return list(session.exec(select(AuthAuditLog).where(AuthAuditLog.event_type == event_type)).all())


def _reload(engine, target_id: int) -> Target:
    with Session(engine) as session:
        return session.get(Target, target_id)


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------


class TestDefaults:
    def test_a_new_target_is_active_and_live(self, engine):
        """No backfill, no migration guesswork: NULL means "not in that
        state", so every target that existed before #273 is active and
        live, which is exactly what they were."""
        tid = _target(engine, _workspace(engine))
        target = _reload(engine, tid)
        assert target.deactivated_at is None
        assert target.deleted_at is None

    def test_is_active_is_served_derived_not_stored(self, client, engine):
        """The API exposes `is_active` but the database stores only a
        timestamp -- a stored boolean beside it would be a second copy of
        the same fact, free to drift."""
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)
        body = client.get(f"/api/targets/{tid}").json()
        assert body["is_active"] is True
        assert body["deactivated_at"] is None


# ---------------------------------------------------------------------------
# Deactivate / reactivate
# ---------------------------------------------------------------------------


class TestDeactivate:
    def test_deactivate_sets_the_flag_and_keeps_the_target_visible(self, client, engine):
        """The whole difference between deactivate and delete: the target
        is still there, still listed, still filterable -- just not scanned."""
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)

        res = client.post(f"/api/targets/{tid}/deactivate")
        assert res.status_code == 200, res.text
        assert res.json()["is_active"] is False
        assert res.json()["deactivated_at"] is not None

        listed = client.get("/api/targets").json()
        assert [t["id"] for t in listed] == [tid]
        assert listed[0]["is_active"] is False

    def test_reactivate_restores_scanning(self, client, engine):
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)
        client.post(f"/api/targets/{tid}/deactivate")

        res = client.post(f"/api/targets/{tid}/reactivate")
        assert res.status_code == 200, res.text
        assert res.json()["is_active"] is True
        assert res.json()["deactivated_at"] is None
        assert _reload(engine, tid).deactivated_at is None

    def test_deactivating_retains_findings(self, client, engine):
        ws = _workspace(engine)
        tid = _target(engine, ws)
        fid = _finding(engine, tid)
        _login(client, engine)
        client.post(f"/api/targets/{tid}/deactivate")

        with Session(engine) as session:
            assert session.get(Finding, fid) is not None
        # ...and they keep counting: a deactivated target is still part of
        # the estate, which is why someone would deactivate rather than
        # delete in the first place.
        assert client.get("/api/dashboard/stats").json()["open"] == 1


class TestLifecycleAudit:
    def test_deactivate_writes_an_audit_row_naming_the_target(self, client, engine):
        ws = _workspace(engine)
        tid = _target(engine, ws, name="payments-api")
        _login(client, engine)
        client.post(f"/api/targets/{tid}/deactivate")

        rows = _audit_rows(engine, AuthEventType.TARGET_DEACTIVATED)
        assert len(rows) == 1
        assert rows[0].actor == "a@example.com"
        # The repo_url matters as much as the name: a name can be edited
        # before the action, the clone URL is what identifies the repo after.
        assert f"target #{tid}" in rows[0].detail
        assert "payments-api" in rows[0].detail
        assert "https://github.com/acme/payments-api" in rows[0].detail

    def test_reactivate_writes_its_own_event_type(self, client, engine):
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)
        client.post(f"/api/targets/{tid}/deactivate")
        client.post(f"/api/targets/{tid}/reactivate")

        assert len(_audit_rows(engine, AuthEventType.TARGET_REACTIVATED)) == 1

    def test_a_noop_repost_does_not_manufacture_a_second_row(self, client, engine):
        """Only a real state transition is an event. Two audit rows for one
        deactivation would make the trail say it happened twice."""
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)
        client.post(f"/api/targets/{tid}/deactivate")
        client.post(f"/api/targets/{tid}/deactivate")

        assert len(_audit_rows(engine, AuthEventType.TARGET_DEACTIVATED)) == 1

    def test_delete_writes_an_audit_row(self, client, engine):
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)
        client.delete(f"/api/targets/{tid}")

        rows = _audit_rows(engine, AuthEventType.TARGET_DELETED)
        assert len(rows) == 1
        assert rows[0].actor == "a@example.com"
        assert f"target #{tid}" in rows[0].detail


# ---------------------------------------------------------------------------
# Deactivation blocks every dispatch path
#
# One test per path. These are deliberately not parametrised into a single
# loop: each one exercises a different entry point with a different refusal
# convention, and the point of the section is that no path was missed.
# ---------------------------------------------------------------------------


class TestDeactivationBlocksScanDispatch:
    def test_on_demand_scan_is_refused(self, client, engine, monkeypatch):
        from app.api import scans as scans_module

        mock_delay = MagicMock()
        monkeypatch.setattr(scans_module.run_scan, "delay", mock_delay)
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)
        client.post(f"/api/targets/{tid}/deactivate")

        res = client.post(f"/api/scans/run?target_id={tid}&tool=semgrep")
        assert res.status_code == 200
        assert "deactivated" in res.json()["error"]
        mock_delay.assert_not_called()

    def test_active_api_scan_is_refused(self, client, engine):
        ws = _workspace(engine)
        tid = _target(engine, ws, api_base_url="https://api.example.com")
        _login(client, engine)
        client.post(f"/api/targets/{tid}/deactivate")

        res = client.post(f"/api/api-scan/{tid}")
        assert res.status_code == 409
        assert "deactivated" in res.json()["detail"]

    def test_ci_push_ingestion_is_refused(self, client, engine):
        """The CI half. A repo's own workflow file keeps running and keeps
        pushing SARIF after someone deactivates the target here -- nothing
        in this database can stop it, so refusing the push is the only place
        the decision can actually be enforced."""
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)
        client.post(f"/api/targets/{tid}/deactivate")

        res = client.post(
            f"/api/ingest/{tid}",
            json={"runs": []},
            headers={"X-API-Key": _workspace_key(engine, ws)},
        )
        assert res.status_code == 200
        assert "deactivated" in res.json()["error"]

    def test_on_demand_pr_guardrail_scan_is_refused(self, client, engine):
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)
        client.post(f"/api/targets/{tid}/deactivate")

        res = client.post(f"/api/pr-guardrail/scan?target_id={tid}&pr_number=7")
        assert res.status_code == 409
        assert "deactivated" in res.json()["detail"]

    def test_api_discovery_is_refused(self, client, engine):
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)
        client.post(f"/api/targets/{tid}/deactivate")

        assert client.post(f"/api/discovery/{tid}").status_code == 409

    def test_sbom_generation_is_refused(self, client, engine):
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)
        client.post(f"/api/targets/{tid}/deactivate")

        assert client.post(f"/api/sbom/{tid}").status_code == 409

    def test_queue_full_scan_dispatches_nothing(self, engine, monkeypatch):
        """The chokepoint every fan-out caller goes through: GitHub App
        import, the push/PR-merged webhooks, the beat schedule and the
        startup baseline catch-up."""
        from app.tasks import scan_tasks

        monkeypatch.setattr(
            scan_tasks, "tools_for_surface", lambda session, workspace_id, surface: ["semgrep", "trivy"]
        )
        mock_delay = MagicMock()
        monkeypatch.setattr(scan_tasks.run_scan, "delay", mock_delay)

        ws = _workspace(engine)
        tid = _target(engine, ws)
        with Session(engine) as session:
            target = session.get(Target, tid)
            from app.core import target_lifecycle

            target_lifecycle.deactivate(target)
            session.add(target)
            session.commit()
            session.refresh(target)

            assert scan_tasks.queue_full_scan(session, target) == []
        mock_delay.assert_not_called()

    def test_the_beat_scheduled_full_scan_skips_deactivated_targets(self, engine, monkeypatch):
        """The worst version of this bug: a nightly job that quietly undoes
        every deactivation, with nobody having clicked anything."""
        from app.core import db as db_module
        from app.core import target_lifecycle
        from app.tasks import scan_tasks

        monkeypatch.setattr(db_module, "engine", engine)
        monkeypatch.setattr(scan_tasks, "engine", engine)
        monkeypatch.setattr(
            scan_tasks, "tools_for_surface", lambda session, workspace_id, surface: ["semgrep"]
        )
        mock_delay = MagicMock()
        monkeypatch.setattr(scan_tasks.run_scan, "delay", mock_delay)

        ws = _workspace(engine)
        off_id = _target(engine, ws, name="switched-off")
        on_id = _target(engine, ws, name="still-on")
        with Session(engine) as session:
            target_lifecycle.deactivate(session.get(Target, off_id))
            session.commit()

        scan_tasks.run_scheduled_full_scans()

        dispatched = {c.kwargs["target_id"] for c in mock_delay.call_args_list}
        assert dispatched == {on_id}

    def test_the_worker_re_checks_before_cloning(self, engine, monkeypatch):
        """Defence in depth for the queued-task window: a target deactivated
        between "click Scan" and "a worker picks it up" must not be cloned.
        The Scan row is settled as failed with the reason rather than left
        spinning forever."""
        from app.core import db as db_module
        from app.core import target_lifecycle
        from app.tasks import scan_tasks

        monkeypatch.setattr(db_module, "engine", engine)
        monkeypatch.setattr(scan_tasks, "engine", engine)
        clone = MagicMock()
        monkeypatch.setattr(scan_tasks.runner, "clone_repo", clone)

        ws = _workspace(engine)
        tid = _target(engine, ws)
        with Session(engine) as session:
            scan = Scan(target_id=tid, tool="semgrep", branch="main", status="running")
            session.add(scan)
            target_lifecycle.deactivate(session.get(Target, tid))
            session.commit()
            session.refresh(scan)
            scan_id = scan.id

        scan_tasks.run_scan.apply(kwargs={"target_id": tid, "tool": "semgrep", "scan_id": scan_id}).get()

        clone.assert_not_called()
        with Session(engine) as session:
            settled = session.get(Scan, scan_id)
            assert settled.status == "failed"
            assert "deactivated" in settled.error

    def test_pr_guardrail_execution_stops_before_any_github_call(self, engine, monkeypatch):
        """Checked in the shared executor, not just in the two entry points:
        the Celery task re-loads the target by id minutes after the webhook
        decided it was fine."""
        from app.core import pr_guardrail_executor, target_lifecycle

        github_get = MagicMock()
        monkeypatch.setattr(pr_guardrail_executor, "github_get", github_get)

        ws = _workspace(engine)
        tid = _target(engine, ws)
        with Session(engine) as session:
            target = session.get(Target, tid)
            target_lifecycle.deactivate(target)
            session.commit()
            session.refresh(target)

            result = pr_guardrail_executor.execute_pr_guardrail_scan(target, 7, session)

        assert result["status"] == "skipped"
        assert "deactivated" in result["skipped"]
        assert result["pr_scan_id"] is None
        github_get.assert_not_called()

    def test_the_pull_request_webhook_creates_no_placeholder_row(self, engine, monkeypatch):
        """A deactivated target must not end up with a PRGuardrailScan row
        stuck RUNNING, or a "pending" commit status on GitHub's PR checks
        list that nothing will ever resolve."""
        from app.api import webhooks
        from app.core import target_lifecycle
        from app.models.models import PRGuardrailScan

        set_status = MagicMock()
        monkeypatch.setattr(webhooks, "set_commit_status", set_status)

        ws = _workspace(engine)
        tid = _target(engine, ws, name="repo")
        with Session(engine) as session:
            target_lifecycle.deactivate(session.get(Target, tid))
            session.commit()

            result = webhooks._handle_pull_request(
                session,
                {
                    "action": "opened",
                    "number": 7,
                    "pull_request": {"title": "t", "head": {"ref": "feat", "sha": "abc"}},
                    "repository": {"clone_url": "https://github.com/acme/repo"},
                },
            )
            assert result["skipped"] == "target deactivated"
            assert session.exec(select(PRGuardrailScan)).all() == []
        set_status.assert_not_called()

    def test_the_push_webhook_does_not_queue_a_scan(self, engine, monkeypatch):
        from app.api import webhooks
        from app.core import target_lifecycle
        from app.tasks import scan_tasks

        mock_delay = MagicMock()
        monkeypatch.setattr(scan_tasks.queue_full_scan_for_target_task, "delay", mock_delay)

        ws = _workspace(engine)
        tid = _target(engine, ws, name="repo")
        with Session(engine) as session:
            target_lifecycle.deactivate(session.get(Target, tid))
            session.commit()

            result = webhooks._handle_push(
                session,
                {
                    "ref": "refs/heads/main",
                    "repository": {"clone_url": "https://github.com/acme/repo"},
                },
            )
        assert result["skipped"] == "target deactivated"
        mock_delay.assert_not_called()

    def test_mass_pipeline_rollout_excludes_deactivated_targets(self, client, engine, monkeypatch):
        """The fleet-wide path: one missed predicate here would pipeline
        every deactivated repo in an org at once."""
        from app.api import targets as targets_module

        monkeypatch.setattr(targets_module.run_pipeline_integration_batch, "delay", MagicMock())
        ws = _workspace(engine)
        off_id = _target(engine, ws, name="switched-off")
        on_id = _target(engine, ws, name="still-on")
        _login(client, engine)
        client.post(f"/api/targets/{off_id}/deactivate")

        res = client.post("/api/targets/mass-pipeline-rollout", json={"scope": "workspace", "workspace_id": ws})
        assert res.status_code == 202, res.text
        assert res.json()["total"] == 1

        batch = client.get(f"/api/targets/bulk-pipeline-integrate/{res.json()['batch_id']}").json()
        assert [i["target_id"] for i in batch["items"]] == [on_id]

    def test_single_target_pipeline_integration_is_refused(self, client, engine):
        """A workflow file committed to the repo would outlive any flag in
        this database."""
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)
        client.post(f"/api/targets/{tid}/deactivate")

        assert client.post(f"/api/targets/{tid}/pipeline-integrate").status_code == 409


class TestDeactivationBlocksFindingProducingWrites:
    """The SBOM / dependency-inventory half of the product.

    None of these clone a repo or spawn a subprocess, which is exactly why
    the first pass missed them -- "does it run a scanner" was the wrong
    test. The one that matters is "can this make a deactivated target
    acquire new findings", and all four can: each reaches
    check_and_ingest_malware, which persists Critical `Finding` rows and
    fans out to Jira, SIEM and notifications.
    """

    def test_malware_recheck_is_refused(self, client, engine):
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)
        client.post(f"/api/targets/{tid}/deactivate")

        res = client.post(f"/api/sbom/{tid}/malware-check")
        assert res.status_code == 409
        assert "deactivated" in res.json()["detail"]

    def test_github_dependency_sync_is_refused(self, client, engine):
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)
        client.post(f"/api/targets/{tid}/deactivate")

        assert client.post(f"/api/sbom/{tid}/github-sync").status_code == 409

    def test_sbom_upload_is_refused(self, client, engine):
        """The exact analogue of POST /api/ingest/{id}: an outside party
        handing us scan-derived data for a target whose scanning is off."""
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)
        client.post(f"/api/targets/{tid}/deactivate")

        res = client.post(
            f"/api/sbom/{tid}/upload",
            files={"file": ("sbom.json", b'{"components": []}', "application/json")},
        )
        assert res.status_code == 409
        assert "deactivated" in res.json()["detail"]

    def test_no_finding_is_created_by_a_refused_malware_check(self, engine, client, monkeypatch):
        """The assertion that actually matters: not just the status code,
        but that nothing was written. A 409 with a Critical finding already
        persisted behind it would be worse than no gate at all."""
        from app.api import sbom as sbom_module

        ingest = MagicMock()
        monkeypatch.setattr(sbom_module, "check_and_ingest_malware", ingest)
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)
        client.post(f"/api/targets/{tid}/deactivate")

        client.post(f"/api/sbom/{tid}/malware-check")
        ingest.assert_not_called()
        with Session(engine) as session:
            assert session.exec(select(Finding)).all() == []


class TestWorkerLevelReChecks:
    """A route-level 409 only closes the door at dispatch. Each of these
    tasks re-loads the target by id, potentially minutes later, and clones
    the repo -- so a deactivation landing inside that window has to be
    honoured by the worker too."""

    def test_discovery_worker_refuses_before_cloning(self, engine, monkeypatch):
        from app.core import db as db_module
        from app.tasks import discovery_tasks

        monkeypatch.setattr(db_module, "engine", engine)
        monkeypatch.setattr(discovery_tasks, "engine", engine)
        clone = MagicMock()
        monkeypatch.setattr(discovery_tasks.runner, "clone_repo", clone)

        ws = _workspace(engine)
        tid = _target(engine, ws)
        with Session(engine) as session:
            run = DiscoveryRun(target_id=tid, branch="main", status="running")
            session.add(run)
            session.commit()
            session.refresh(run)
            run_id = run.id
        _deactivate(engine, tid)

        discovery_tasks.run_discovery.apply(kwargs={"target_id": tid, "run_id": run_id}).get()

        clone.assert_not_called()
        with Session(engine) as session:
            settled = session.get(DiscoveryRun, run_id)
            assert settled.status == "failed"
            assert "deactivated" in settled.error

    def test_sbom_worker_refuses_before_cloning(self, engine, monkeypatch):
        from app.core import db as db_module
        from app.tasks import sbom_tasks

        monkeypatch.setattr(db_module, "engine", engine)
        monkeypatch.setattr(sbom_tasks, "engine", engine)
        clone = MagicMock()
        monkeypatch.setattr(sbom_tasks.runner, "clone_repo", clone)
        fetch = MagicMock()
        monkeypatch.setattr(sbom_tasks, "fetch_dependency_graph", fetch)

        ws = _workspace(engine)
        tid = _target(engine, ws)
        with Session(engine) as session:
            run = SbomRun(target_id=tid, branch="main", status="running")
            session.add(run)
            session.commit()
            session.refresh(run)
            run_id = run.id
        _deactivate(engine, tid)

        sbom_tasks.run_sbom_generation.apply(kwargs={"target_id": tid, "run_id": run_id}).get()

        clone.assert_not_called()
        fetch.assert_not_called()
        with Session(engine) as session:
            settled = session.get(SbomRun, run_id)
            assert settled.status == "failed"
            assert "deactivated" in settled.error

    def test_api_scan_worker_refuses_before_probing(self, engine, monkeypatch):
        """The highest-consequence window of the four: this one sends real
        traffic at a real deployed host."""
        from app.core import db as db_module
        from app.tasks import api_scan_tasks

        monkeypatch.setattr(db_module, "engine", engine)
        monkeypatch.setattr(api_scan_tasks, "engine", engine)
        nuclei = MagicMock()
        monkeypatch.setattr(api_scan_tasks.runner, "run_nuclei", nuclei)

        ws = _workspace(engine)
        tid = _target(engine, ws, api_base_url="https://api.example.com")
        with Session(engine) as session:
            scan = Scan(target_id=tid, tool="api-scan", branch="main", status="running")
            session.add(scan)
            session.commit()
            session.refresh(scan)
            scan_id = scan.id
        _deactivate(engine, tid)

        api_scan_tasks.run_api_scan.apply(kwargs={"target_id": tid, "scan_id": scan_id}).get()

        nuclei.assert_not_called()
        with Session(engine) as session:
            settled = session.get(Scan, scan_id)
            assert settled.status == "failed"
            assert "deactivated" in settled.error


class TestRemainingDispatchPaths:
    def test_public_api_scan_trigger_is_refused(self, client, engine, monkeypatch):
        """A public API token must not be a way around a decision made in
        the workspace's own configuration."""
        from app.api import public_api as public_api_module

        mock_delay = MagicMock()
        monkeypatch.setattr(public_api_module.run_scan, "delay", mock_delay)
        ws = _workspace(engine)
        tid = _target(engine, ws)
        token = _api_token(engine)
        _deactivate(engine, tid)

        res = client.post(
            f"/api/public/v1/scans?target_id={tid}&tool=semgrep",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 409, res.text
        assert "deactivated" in res.json()["detail"]
        mock_delay.assert_not_called()

    def test_public_api_scan_trigger_404s_a_deleted_target(self, client, engine):
        ws = _workspace(engine)
        tid = _target(engine, ws)
        token = _api_token(engine)
        _soft_delete(engine, tid)

        res = client.post(
            f"/api/public/v1/scans?target_id={tid}&tool=semgrep",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 404

    def test_public_api_target_list_excludes_deleted(self, client, engine):
        ws = _workspace(engine)
        gone = _target(engine, ws, name="gone")
        kept = _target(engine, ws, name="kept")
        token = _api_token(engine)
        _soft_delete(engine, gone)

        res = client.get("/api/public/v1/targets", headers={"Authorization": f"Bearer {token}"})
        assert [t["id"] for t in res.json()] == [kept]

    def test_bulk_pipeline_integrate_drops_deactivated_targets(self, client, engine, monkeypatch):
        """Dropped from the selection rather than failing the batch: the
        caller sent a list of ids, possibly from a stale page, and one
        switched-off repo should not cancel the rollout for the rest."""
        from app.api import targets as targets_module

        monkeypatch.setattr(targets_module.run_pipeline_integration_batch, "delay", MagicMock())
        ws = _workspace(engine)
        off_id = _target(engine, ws, name="switched-off")
        on_id = _target(engine, ws, name="still-on")
        _login(client, engine)
        client.post(f"/api/targets/{off_id}/deactivate")

        res = client.post(
            "/api/targets/bulk-pipeline-integrate", json={"target_ids": [off_id, on_id]}
        )
        assert res.status_code == 202, res.text
        assert res.json()["total"] == 1

        batch = client.get(f"/api/targets/bulk-pipeline-integrate/{res.json()['batch_id']}").json()
        assert [i["target_id"] for i in batch["items"]] == [on_id]

    def test_bulk_pipeline_integrate_403s_when_only_deactivated_were_selected(self, client, engine):
        """Nothing eligible left is the existing 403, not a 202 for an
        empty batch that would report success having done nothing."""
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)
        client.post(f"/api/targets/{tid}/deactivate")

        res = client.post("/api/targets/bulk-pipeline-integrate", json={"target_ids": [tid]})
        assert res.status_code == 403

    def test_startup_baseline_catchup_skips_deactivated_targets(self, engine, monkeypatch):
        """A worker restart must not become a way to scan a deactivated
        target once."""
        from app.tasks import scan_tasks

        monkeypatch.setattr(
            scan_tasks, "tools_for_surface", lambda session, workspace_id, surface: ["semgrep"]
        )
        mock_delay = MagicMock()
        monkeypatch.setattr(scan_tasks.run_scan, "delay", mock_delay)

        ws = _workspace(engine)
        off_id = _target(engine, ws, name="switched-off")
        on_id = _target(engine, ws, name="still-on")
        _deactivate(engine, off_id)

        with Session(engine) as session:
            scan_tasks.queue_full_scan_for_targets_missing_a_baseline(session)

        dispatched = {c.kwargs["target_id"] for c in mock_delay.call_args_list}
        assert dispatched == {on_id}

    def test_the_pr_merged_webhook_does_not_queue_a_scan(self, engine, monkeypatch):
        from app.api import webhooks
        from app.tasks import scan_tasks

        mock_delay = MagicMock()
        monkeypatch.setattr(scan_tasks.queue_full_scan_for_target_task, "delay", mock_delay)

        ws = _workspace(engine)
        tid = _target(engine, ws, name="repo")
        _deactivate(engine, tid)

        with Session(engine) as session:
            result = webhooks._handle_pull_request(
                session,
                {
                    "action": "closed",
                    "number": 7,
                    "pull_request": {"merged": True, "base": {"ref": "main"}, "head": {"ref": "f", "sha": "a"}},
                    "repository": {"clone_url": "https://github.com/acme/repo"},
                },
            )
        assert result["skipped"] == "target deactivated"
        mock_delay.assert_not_called()


class TestReactivateRestoresDispatch:
    def test_scanning_resumes_after_reactivate(self, client, engine, monkeypatch):
        from app.api import scans as scans_module

        mock_delay = MagicMock()
        monkeypatch.setattr(scans_module.run_scan, "delay", mock_delay)
        monkeypatch.setattr(
            scans_module, "tools_for_surface", lambda session, workspace_id, surface: ["semgrep"]
        )
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)
        client.post(f"/api/targets/{tid}/deactivate")
        client.post(f"/api/targets/{tid}/reactivate")

        res = client.post(f"/api/scans/run?target_id={tid}&tool=semgrep")
        assert res.status_code == 202, res.text
        mock_delay.assert_called_once()


# ---------------------------------------------------------------------------
# Delete: soft, audit-preserving
# ---------------------------------------------------------------------------


class TestDeleteIsSoft:
    def test_delete_marks_the_row_without_destroying_it(self, client, engine):
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)

        res = client.delete(f"/api/targets/{tid}")
        assert res.status_code == 200, res.text
        assert res.json()["deleted_at"] is not None

        # The row is still there. That is the whole design decision.
        assert _reload(engine, tid) is not None

    def test_findings_survive_and_the_response_says_so(self, client, engine):
        """"Someone deleted the record of a finding" has to stay answerable,
        so the rows are kept -- and the caller is told, rather than left to
        discover it from a docs page."""
        ws = _workspace(engine)
        tid = _target(engine, ws)
        fid = _finding(engine, tid)
        _login(client, engine)

        res = client.delete(f"/api/targets/{tid}")
        assert res.json()["retained_findings"] == 1

        with Session(engine) as session:
            assert session.get(Finding, fid) is not None

    def test_scan_history_survives(self, client, engine):
        ws = _workspace(engine)
        tid = _target(engine, ws)
        with Session(engine) as session:
            session.add(Scan(target_id=tid, tool="semgrep", branch="main", status="completed"))
            session.commit()
        _login(client, engine)
        client.delete(f"/api/targets/{tid}")

        with Session(engine) as session:
            assert len(session.exec(select(Scan).where(Scan.target_id == tid)).all()) == 1

    def test_deleting_does_not_clear_the_deactivation_timestamp(self, client, engine):
        """The two are separate facts. Flattening them would lose what a
        restore needs to know: a target deactivated in March and deleted in
        June should come back deactivated, not silently scanning."""
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)
        client.post(f"/api/targets/{tid}/deactivate")
        client.delete(f"/api/targets/{tid}")

        target = _reload(engine, tid)
        assert target.deleted_at is not None
        assert target.deactivated_at is not None


class TestDeletedTargetsDisappear:
    def test_gone_from_the_target_list(self, client, engine):
        ws = _workspace(engine)
        gone = _target(engine, ws, name="gone")
        kept = _target(engine, ws, name="kept")
        _login(client, engine)
        client.delete(f"/api/targets/{gone}")

        assert [t["id"] for t in client.get("/api/targets").json()] == [kept]

    def test_detail_404s_like_a_target_that_never_existed(self, client, engine):
        """Not a 410. The difference between "gone" and "never existed" would
        be a side channel telling anyone probing ids that something used to
        live here."""
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)
        client.delete(f"/api/targets/{tid}")

        assert client.get(f"/api/targets/{tid}").status_code == 404

    def test_gone_from_the_targets_summary(self, client, engine):
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _finding(engine, tid)
        _login(client, engine)
        client.delete(f"/api/targets/{tid}")

        assert str(tid) not in client.get("/api/targets/summary").json()

    def test_findings_stop_counting_toward_the_dashboard(self, client, engine):
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _finding(engine, tid)
        _login(client, engine)
        assert client.get("/api/dashboard/stats").json()["open"] == 1

        client.delete(f"/api/targets/{tid}")
        assert client.get("/api/dashboard/stats").json()["open"] == 0
        assert client.get("/api/dashboard/summary").json()["total"] == 0

    def test_findings_stop_appearing_in_the_findings_list(self, client, engine):
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _finding(engine, tid)
        _login(client, engine)
        client.delete(f"/api/targets/{tid}")

        assert client.get("/api/findings").json()["total"] == 0

    def test_gone_from_the_security_score_scope(self, client, engine):
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)
        client.delete(f"/api/targets/{tid}")

        score = client.get("/api/dashboard/security-score").json()
        assert score["target_count"] == 0
        # ...and asking for it by id is a 404, not a score for a repo that
        # is no longer part of the estate.
        assert client.get(f"/api/dashboard/security-score?target_id={tid}").status_code == 404

    def test_gone_from_reports(self, client, engine):
        """A compliance/audit report is a statement about the estate as it
        is. A repo that was removed is not part of it."""
        ws = _workspace(engine)
        tid = _target(engine, ws, name="payments-api")
        _finding(engine, tid)
        _login(client, engine)

        before = client.get("/api/reports/posture")
        assert before.status_code == 200, before.text
        assert "payments-api" in before.text

        client.delete(f"/api/targets/{tid}")
        after = client.get("/api/reports/posture")
        assert after.status_code == 200, after.text
        assert "payments-api" not in after.text

    def test_gone_from_global_search(self, client, engine):
        """Every link search rendered for a deleted target would 404."""
        ws = _workspace(engine)
        tid = _target(engine, ws, name="findme")
        _login(client, engine)
        client.delete(f"/api/targets/{tid}")

        assert client.get("/api/search?q=findme").json()["targets"] == []

    def test_scan_dispatch_reports_not_found(self, client, engine):
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)
        client.delete(f"/api/targets/{tid}")

        assert client.post(f"/api/scans/run?target_id={tid}&tool=semgrep").json()["error"] == "target not found"
        assert client.post(f"/api/api-scan/{tid}").status_code == 404

    def test_webhooks_stop_matching_the_repository(self, engine):
        """GitHub keeps delivering events regardless of what we did in our
        own database, so "deleted" has to be enforced on the receiving side."""
        from app.api import webhooks
        from app.core import target_lifecycle

        ws = _workspace(engine)
        tid = _target(engine, ws, name="repo")
        with Session(engine) as session:
            target_lifecycle.soft_delete(session.get(Target, tid))
            session.commit()

            result = webhooks._handle_push(
                session,
                {"ref": "refs/heads/main", "repository": {"clone_url": "https://github.com/acme/repo"}},
            )
        assert result["skipped"] == "no matching target"

    def test_the_repo_can_be_registered_again_afterwards(self, client, engine):
        """The soft-deleted row still holds that repo_url. If it counted as
        "already imported", a repository someone deleted could never come
        back -- app.api.github_app._sync_repos would skip it forever while
        the operator saw nothing appear and no error explaining why.

        Asserted against the exact expression _sync_repos builds its
        already-imported set from, so this fails if that filter is dropped.
        """
        from app.core import target_lifecycle

        ws = _workspace(engine)
        tid = _target(engine, ws, name="repo")
        _login(client, engine)
        client.delete(f"/api/targets/{tid}")

        with Session(engine) as session:
            existing_urls = {
                t.repo_url
                for t in session.exec(target_lifecycle.live_targets(select(Target))).all()
            }
        assert "https://github.com/acme/repo" not in existing_urls


class TestAggregatesExcludeDeletedTargets:
    """Per-aggregate, not sampled: each of these is a separately-written
    query with its own scoping shape, so one passing says nothing about the
    next.

    Several exercise the admin path (`ws_ids=None`) specifically. To be
    precise about why, since an earlier version of this comment overstated
    it: a workspace-scoped test detects a *missing* predicate perfectly
    well, because the workspace join filters on `workspace_id`, not on
    `deleted_at`. What the admin path uniquely catches is a plausible
    *wrong fix* -- hanging the soft-delete predicate off the workspace join
    instead of applying it independently. That version passes every scoped
    test and silently leaks deleted targets to admins, and it is tempting
    enough that four comments in this PR exist to warn against it.
    """

    def test_the_live_scan_activity_widget_drops_them(self, engine):
        """The twin of GET /api/scans/active's filter. This resolver builds
        its own query, and _target_names() correctly refuses to resolve a
        deleted target -- so without the filter the widget renders the
        literal fallback string "target #47" instead of a name."""
        from app.core import widgets

        ws = _workspace(engine)
        gone = _target(engine, ws, name="gone")
        kept = _target(engine, ws, name="kept")
        with Session(engine) as session:
            session.add(Scan(target_id=gone, tool="semgrep", branch="main", status="running"))
            session.add(Scan(target_id=kept, tool="semgrep", branch="main", status="running"))
            session.commit()
        _soft_delete(engine, gone)

        with Session(engine) as session:
            # ws_ids=None is the admin path: no Target join at all, so a
            # predicate wrongly attached to that join would do nothing here.
            data = widgets.resolve_live_scan_activity(session, None, {})

        assert {item["target_id"] for item in data["items"]} == {kept}
        assert data["count"] == 1
        # The fallback string is what a missed filter would have rendered.
        assert all("target #" not in item["target_name"] for item in data["items"])

    def test_findings_facets_drop_a_deleted_targets_values(self, client, engine):
        ws = _workspace(engine)
        gone = _target(engine, ws, name="gone", owner="ghost-team", environment="retired")
        _target(engine, ws, name="kept", owner="platform-team", environment="production")
        _login(client, engine)
        client.delete(f"/api/targets/{gone}")

        assert client.get("/api/findings/facets/owners").json() == ["platform-team"]
        assert client.get("/api/findings/facets/environments").json() == ["production"]

    def test_the_scans_summary_drops_them_for_an_admin(self, client, engine):
        """Run as an admin, where no Target join exists to hang the
        predicate off -- the shape that catches the wrong fix, not just the
        missing one."""
        ws = _workspace(engine)
        gone = _target(engine, ws, name="gone")
        with Session(engine) as session:
            session.add(Scan(target_id=gone, tool="semgrep", branch="main", status="completed"))
            session.commit()
        _login(client, engine)

        assert str(gone) in client.get("/api/scans/summary").json()
        client.delete(f"/api/targets/{gone}")
        assert str(gone) not in client.get("/api/scans/summary").json()

    def test_scan_history_404s_for_a_deleted_target(self, client, engine):
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)
        client.delete(f"/api/targets/{tid}")

        assert client.get(f"/api/scans/history?target_id={tid}").status_code == 404

    def test_the_org_sbom_aggregate_drops_them(self, client, engine):
        """"Which of my repos still use package X" must not answer with a
        repo that no longer exists -- the component row survives the soft
        delete, so only the target filter keeps it out."""
        ws = _workspace(engine)
        gone = _target(engine, ws, name="gone")
        kept = _target(engine, ws, name="kept")
        with Session(engine) as session:
            for tid in (gone, kept):
                session.add(
                    SbomComponent(
                        target_id=tid, branch="main", name="left-pad",
                        version="1.0.0", package_type="npm", purl="pkg:npm/left-pad@1.0.0",
                    )
                )
            session.commit()
        _login(client, engine)

        before = client.get("/api/sbom/org").json()
        assert {t["id"] for c in before["components"] for t in c["targets"]} == {gone, kept}

        client.delete(f"/api/targets/{gone}")
        after = client.get("/api/sbom/org").json()
        assert {t["id"] for c in after["components"] for t in c["targets"]} == {kept}

    def test_the_org_pr_guardrail_log_drops_them(self, client, engine):
        ws = _workspace(engine)
        gone = _target(engine, ws, name="gone")
        kept = _target(engine, ws, name="kept")
        with Session(engine) as session:
            for tid in (gone, kept):
                session.add(
                    PRGuardrailScan(
                        target_id=tid, pr_number=7, pr_title="t", branch="feat",
                        status=PRGuardrailStatus.PASSED,
                    )
                )
            session.commit()
        _login(client, engine)

        assert client.get("/api/pr-guardrail/log").json()["stats"]["total"] == 2
        client.delete(f"/api/targets/{gone}")

        after = client.get("/api/pr-guardrail/log").json()
        assert after["stats"]["total"] == 1
        assert {s["target_id"] for s in after["scans"]} == {kept}

    def test_active_scans_drops_them_for_an_admin(self, client, engine):
        """Same admin-path shape as the scans summary above: the deleted
        target's running scan must not keep the Targets list showing work in
        flight for a repo that is gone."""
        ws = _workspace(engine)
        gone = _target(engine, ws, name="gone")
        kept = _target(engine, ws, name="kept")
        with Session(engine) as session:
            session.add(Scan(target_id=gone, tool="semgrep", branch="main", status="running"))
            session.add(Scan(target_id=kept, tool="semgrep", branch="main", status="running"))
            session.commit()
        _login(client, engine)

        assert set(client.get("/api/scans/active").json()) == {str(gone), str(kept)}
        client.delete(f"/api/targets/{gone}")
        assert set(client.get("/api/scans/active").json()) == {str(kept)}

    def test_org_activity_does_not_call_github_for_a_deleted_target(self, client, engine, monkeypatch):
        """Asserted on the outbound calls, not just the response: this
        endpoint makes one real GitHub API request per target, so a missed
        filter is a wasted call against a repo we were told to forget as
        well as a row that should not render."""
        from app.api import github as github_module

        called_paths: list[str] = []

        class _NoContent:
            status_code = 304  # anything non-200; the handler skips the repo

        def fake_get(path, params=None, token=""):
            called_paths.append(path)
            return _NoContent()

        monkeypatch.setattr(github_module, "github_get", fake_get)
        ws = _workspace(engine)
        gone = _target(engine, ws, name="gone")
        _target(engine, ws, name="kept")
        _login(client, engine)
        client.delete(f"/api/targets/{gone}")

        assert client.get("/api/github/org-activity").status_code == 200
        assert not any("gone" in p for p in called_paths)
        assert any("kept" in p for p in called_paths), "the live target is still fetched"


class TestDeactivationIsVisibleInAggregates:
    """Deactivated targets are NOT excluded from aggregates -- their
    findings still count, which is the point. But two surfaces have to
    report the state rather than silently carrying a stale number."""

    def test_the_compliance_report_says_which_targets_are_not_scanned(self, client, engine):
        """The single most consequential place this could have been
        omitted: an auditor reads the last scan date and concludes the
        repo is covered, when nothing will ever advance that date again."""
        ws = _workspace(engine)
        tid = _target(engine, ws, name="payments-api")
        with Session(engine) as session:
            session.add(Scan(target_id=tid, tool="semgrep", branch="main", status="completed"))
            session.commit()
        _login(client, engine)
        client.post(f"/api/targets/{tid}/deactivate")

        body = client.get("/api/reports/posture").text
        assert "payments-api" in body, "a deactivated target stays in the report"
        assert "OFF (deactivated)" in body, "and the report says its scanning is off"

    def test_an_active_targets_report_does_not_cry_wolf(self, client, engine):
        ws = _workspace(engine)
        _target(engine, ws, name="payments-api")
        _login(client, engine)

        assert "OFF (deactivated)" not in client.get("/api/reports/posture").text

    def test_deactivated_targets_leave_the_coverage_denominator(self, client, engine):
        """Otherwise the coverage component decays a little every day for a
        repo nobody can scan, and the only way to recover the score is to
        reactivate something you deliberately switched off."""
        ws = _workspace(engine)
        scanned = _target(engine, ws, name="scanned")
        off = _target(engine, ws, name="switched-off")
        with Session(engine) as session:
            session.add(Scan(target_id=scanned, tool="semgrep", branch="main", status="completed"))
            session.commit()
        _login(client, engine)

        before = client.get("/api/dashboard/security-score").json()["components"]["coverage"]
        assert (before["scanned_targets"], before["total_targets"]) == (1, 2)

        client.post(f"/api/targets/{off}/deactivate")
        after = client.get("/api/dashboard/security-score").json()["components"]["coverage"]
        assert (after["scanned_targets"], after["total_targets"]) == (1, 1)
        assert after["score"] == 100.0
        # The excluded count is reported, not silently dropped: "1 of 1"
        # against a target list of 2 has to be reconcilable.
        assert after["deactivated_targets"] == 1
        assert "deactivated" in after["note"]

    def test_an_entirely_deactivated_scope_is_neutral_not_zero(self, client, engine):
        """Scoring 0 would say "you scan nothing" about an estate that was
        switched off on purpose; neutral-100 matches _sla_score's own
        nothing-in-scope handling rather than inventing a third convention."""
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(client, engine)
        client.post(f"/api/targets/{tid}/deactivate")

        coverage = client.get("/api/dashboard/security-score").json()["components"]["coverage"]
        assert coverage["score"] == 100.0
        assert coverage["deactivated_targets"] == 1


class TestWorkspaceScopingOnTheNewEndpoints:
    """#57's read-path scoping applies to the write paths added here too: a
    non-admin must not be able to deactivate or delete a target in a
    workspace they hold no membership in, and must not learn it exists."""

    def _foreign_target(self, engine):
        mine = _workspace(engine)
        theirs = _workspace(engine)
        return mine, _target(engine, theirs, name="not-mine")

    def test_deactivate_404s_across_the_workspace_boundary(self, client, engine):
        mine, foreign = self._foreign_target(engine)
        _login(
            client, engine, role=UserRole.USER, workspace_id=mine,
            workspace_role=WorkspaceRole.SECURITY_ENGINEER, email="sec@example.com",
        )
        res = client.post(f"/api/targets/{foreign}/deactivate")
        # 404, not 403: the existence of another tenant's target is itself
        # information (the convention the rest of this file already uses).
        assert res.status_code == 404
        assert _reload(engine, foreign).deactivated_at is None

    def test_delete_404s_across_the_workspace_boundary(self, client, engine):
        mine, foreign = self._foreign_target(engine)
        _login(
            client, engine, role=UserRole.USER, workspace_id=mine,
            workspace_role=WorkspaceRole.SECURITY_ENGINEER, email="sec@example.com",
        )
        assert client.delete(f"/api/targets/{foreign}").status_code == 404
        assert _reload(engine, foreign).deleted_at is None

    def test_no_audit_row_is_written_for_a_refused_action(self, client, engine):
        """A refused attempt must not leave a row claiming the target was
        deleted -- the audit trail would then contradict the database."""
        mine, foreign = self._foreign_target(engine)
        _login(
            client, engine, role=UserRole.USER, workspace_id=mine,
            workspace_role=WorkspaceRole.SECURITY_ENGINEER, email="sec@example.com",
        )
        client.delete(f"/api/targets/{foreign}")
        assert _audit_rows(engine, AuthEventType.TARGET_DELETED) == []


class TestTheAuditTrailSurvives:
    def test_the_audit_feed_still_names_a_deleted_target(self, client, engine):
        """The one query deliberately NOT filtered to live targets. A scan
        that really happened against a repo that has since been deleted
        still happened; rendering it as "scan on 47" would destroy the one
        thing the row exists to record."""
        ws = _workspace(engine)
        tid = _target(engine, ws, name="payments-api")
        with Session(engine) as session:
            session.add(Scan(target_id=tid, tool="semgrep", branch="main", status="completed"))
            session.commit()
        _login(client, engine)
        client.delete(f"/api/targets/{tid}")

        feed = client.get("/api/audit/log").json()["items"]
        scan_entries = [e for e in feed if e["type"] == "scan"]
        assert scan_entries, "the scan event should still be in the audit feed"
        assert "payments-api" in scan_entries[0]["summary"]


# ---------------------------------------------------------------------------
# Authorisation
# ---------------------------------------------------------------------------


class TestRoleGating:
    def test_a_developer_can_deactivate(self, client, engine):
        """Same bar as PATCH, which can already set enforcement_mode
        ="disabled" and switch off the PR gate."""
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(
            client, engine, role=UserRole.USER, workspace_id=ws, workspace_role=WorkspaceRole.DEVELOPER,
            email="dev@example.com",
        )
        assert client.post(f"/api/targets/{tid}/deactivate").status_code == 200

    def test_a_developer_cannot_delete(self, client, engine):
        """Delete is gated at SECURITY_ENGINEER, the bar this codebase
        already uses for writes that change what the platform records
        (sla_rules, fp_rules, tool assignments)."""
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(
            client, engine, role=UserRole.USER, workspace_id=ws, workspace_role=WorkspaceRole.DEVELOPER,
            email="dev@example.com",
        )
        assert client.delete(f"/api/targets/{tid}").status_code == 403
        assert _reload(engine, tid).deleted_at is None

    def test_a_security_engineer_can_delete(self, client, engine):
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(
            client, engine, role=UserRole.USER, workspace_id=ws,
            workspace_role=WorkspaceRole.SECURITY_ENGINEER, email="sec@example.com",
        )
        assert client.delete(f"/api/targets/{tid}").status_code == 200

    def test_a_viewer_cannot_deactivate(self, client, engine):
        ws = _workspace(engine)
        tid = _target(engine, ws)
        _login(
            client, engine, role=UserRole.USER, workspace_id=ws, workspace_role=WorkspaceRole.VIEWER,
            email="view@example.com",
        )
        assert client.post(f"/api/targets/{tid}/deactivate").status_code == 403
