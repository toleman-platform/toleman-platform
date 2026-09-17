"""Tests for the Fix Plan package-level raise-PR endpoints (#247 follow-up):
POST /api/findings/remediations/raise-pr (single package, synchronous),
POST /api/findings/remediations/raise-all (bulk, async batch) and
GET /api/findings/remediations/raise-all-batches/{id} (poll).

Same two-layer approach as tests/test_bulk_pipeline_integration.py:

  1. Dispatch/logic tests against the endpoints, with
     app.core.remediation_autofix.raise_package_fix_pr mocked at the
     boundary (or .delay() mocked for the bulk dispatch).
  2. One end-to-end eager-mode test proving the real Celery task
     (run_raise_all_batch) processes a batch and lands the right
     per-item outcomes.

These endpoints take `target_id` inside the JSON body rather than as a
path/query param, so they can't use require_workspace_role(...)'s
Depends-based name-binding shortcut (see that function's own docstring);
they call enforce_workspace_role directly instead, same as POST
/api/targets does for its body-carried workspace_id. The role tests below
exist specifically to pin that down -- using the Depends shortcut here
by mistake would silently 404 every non-admin caller regardless of their
actual access, since target_id would never be bound.
"""
import json
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
import app.api.findings as findings_module
import app.core.autofix as autofix
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.main import app as fastapi_app
from app.models.models import (
    CveEnrichment,
    Finding,
    FindingState,
    Organization,
    RemediationPrBatch,
    RemediationPrBatchItem,
    Severity,
    Target,
    User,
    UserRole,
    Workspace,
    WorkspaceMembership,
    WorkspaceRole,
)
from app.tasks import remediation_tasks
from app.tasks.celery_app import celery_app


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


def _workspace(engine, name="ws") -> int:
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


def _target(engine, workspace_id, name="t") -> int:
    with Session(engine) as session:
        t = Target(workspace_id=workspace_id, name=name, repo_url=f"https://github.com/a/{name}")
        session.add(t)
        session.commit()
        session.refresh(t)
        return t.id


def _login(client, engine, role=UserRole.DEVELOPER, email=None) -> int:
    email = email or f"{role.value}-{id(object())}@example.com"
    with Session(engine) as session:
        user = User(email=email, name="U", password_hash=hash_password("whatever123"), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        uid = user.id
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return uid


def _assign(engine, user_id: int, workspace_id: int, role: WorkspaceRole):
    with Session(engine) as session:
        session.add(WorkspaceMembership(user_id=user_id, workspace_id=workspace_id, role=role))
        session.commit()


def _dev_client_with_target(client, engine, name="t") -> int:
    ws = _workspace(engine, name=name)
    target_id = _target(engine, ws, name=name)
    uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws, WorkspaceRole.DEVELOPER)
    return target_id


def _finding_with_fix(engine, target_id, cve_id, package, fixed_version, file_path="requirements.txt"):
    with Session(engine) as session:
        session.add(Finding(
            target_id=target_id, tool="trivy", rule_id=cve_id, title=f"{cve_id} in {package}",
            file_path=file_path, severity=Severity.HIGH, cve_id=cve_id,
            state=FindingState.OPEN, dedup_hash=f"hash-{cve_id}",
        ))
        session.add(CveEnrichment(
            cve_id=cve_id, osv_found=True,
            fixed_versions=json.dumps([{"package": package, "ecosystem": "PyPI", "fixed": fixed_version}]),
        ))
        session.commit()


# ---------------------------------------------------------------------------
# POST /api/findings/remediations/raise-pr (single package)
# ---------------------------------------------------------------------------


def test_raise_pr_opens_a_pr_for_the_current_plan(client, engine, monkeypatch):
    target_id = _dev_client_with_target(client, engine)
    _finding_with_fix(engine, target_id, "CVE-2024-1", "starlette", "0.40.0")

    def fake_raise(session, target, plan, raised_by):
        assert plan["package"] == "starlette"
        assert raised_by.startswith("user:")
        return {"pr_url": "https://github.com/a/t/pull/1", "pr_number": 1, "branch": "toleman/fix-pkg-1"}

    monkeypatch.setattr(findings_module, "raise_package_fix_pr", fake_raise)

    res = client.post(
        "/api/findings/remediations/raise-pr", json={"target_id": target_id, "package": "starlette"}
    )
    assert res.status_code == 200, res.text
    assert res.json() == {"pr_url": "https://github.com/a/t/pull/1", "pr_number": 1, "branch": "toleman/fix-pkg-1"}


def test_raise_pr_404s_for_a_package_not_in_the_current_plan(client, engine):
    target_id = _dev_client_with_target(client, engine)
    res = client.post("/api/findings/remediations/raise-pr", json={"target_id": target_id, "package": "nope"})
    assert res.status_code == 404


def test_raise_pr_surfaces_autofix_error_as_502(client, engine, monkeypatch):
    target_id = _dev_client_with_target(client, engine)
    _finding_with_fix(engine, target_id, "CVE-2024-1", "starlette", "0.40.0")

    def boom(session, target, plan, raised_by):
        raise autofix.AutofixError("no GitHub App installed")

    monkeypatch.setattr(findings_module, "raise_package_fix_pr", boom)

    res = client.post(
        "/api/findings/remediations/raise-pr", json={"target_id": target_id, "package": "starlette"}
    )
    assert res.status_code == 502
    assert "no GitHub App installed" in res.json()["detail"]


def test_raise_pr_requires_developer_role(client, engine):
    """A workspace VIEWER can see the plan but not act on it -- the
    real-world case enforce_workspace_role's explicit-call pattern has to
    get right since it isn't wired through require_workspace_role here."""
    ws = _workspace(engine)
    target_id = _target(engine, ws)
    uid = _login(client, engine, role=UserRole.USER)
    _assign(engine, uid, ws, WorkspaceRole.VIEWER)

    res = client.post(
        "/api/findings/remediations/raise-pr", json={"target_id": target_id, "package": "starlette"}
    )
    assert res.status_code == 403


def test_raise_pr_404s_for_a_target_outside_the_callers_workspaces(client, engine):
    target_id = _dev_client_with_target(client, engine)
    other_ws = _workspace(engine, name="other")
    other_target = _target(engine, other_ws, name="other-t")
    res = client.post(
        "/api/findings/remediations/raise-pr", json={"target_id": other_target, "package": "starlette"}
    )
    assert res.status_code == 404


def test_raise_pr_is_idempotent_end_to_end_through_the_endpoint(client, engine, monkeypatch):
    """A second POST for the same already-covered package returns the SAME
    PR (200), rather than opening a duplicate or 502ing -- exercised
    through the real endpoint and the real raise_package_fix_pr, with only
    the GitHub-API boundary (autofix._fetch_file/_commit_files_and_open_pr)
    mocked, so this covers the actual AlreadyRaisedError wiring end to end
    rather than a unit-level mock of raise_package_fix_pr itself."""
    target_id = _dev_client_with_target(client, engine)
    _finding_with_fix(engine, target_id, "CVE-2024-1", "starlette", "0.40.0")

    monkeypatch.setattr(autofix, "_fetch_file", lambda *a, **k: ("starlette==0.39.0\n", "sha1"))
    calls = {"n": 0}

    def fake_commit(session, target, ref, branch_name, files, commit_message, pr_title, pr_body):
        calls["n"] += 1
        return {"pr_url": f"https://github.com/a/t/pull/{calls['n']}", "pr_number": calls["n"], "branch": branch_name}

    monkeypatch.setattr(autofix, "_commit_files_and_open_pr", fake_commit)

    first = client.post(
        "/api/findings/remediations/raise-pr", json={"target_id": target_id, "package": "starlette"}
    )
    assert first.status_code == 200, first.text
    assert first.json()["pr_number"] == 1

    second = client.post(
        "/api/findings/remediations/raise-pr", json={"target_id": target_id, "package": "starlette"}
    )
    assert second.status_code == 200, second.text
    assert second.json() == first.json()
    assert calls["n"] == 1


def test_raise_pr_404s_for_an_unknown_target(client, engine):
    _dev_client_with_target(client, engine)
    res = client.post("/api/findings/remediations/raise-pr", json={"target_id": 9999, "package": "starlette"})
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/findings/remediations/raise-all + GET .../raise-all-batches/{id}
# ---------------------------------------------------------------------------


def test_raise_all_creates_batch_and_items_and_dispatches_without_blocking(client, engine, monkeypatch):
    target_id = _dev_client_with_target(client, engine)
    _finding_with_fix(engine, target_id, "CVE-2024-1", "starlette", "0.40.0")
    _finding_with_fix(engine, target_id, "CVE-2024-2", "axios", "1.7.4")

    mock_delay = MagicMock()
    monkeypatch.setattr(findings_module.run_raise_all_batch, "delay", mock_delay)

    res = client.post("/api/findings/remediations/raise-all", json={"target_id": target_id})
    assert res.status_code == 202
    body = res.json()
    assert body["status"] == "running"
    assert body["total"] == 2
    batch_id = body["batch_id"]
    mock_delay.assert_called_once_with(batch_id=batch_id)

    with Session(engine) as session:
        batch = session.get(RemediationPrBatch, batch_id)
        assert batch is not None
        assert batch.total == 2
        items = session.exec(
            select(RemediationPrBatchItem).where(RemediationPrBatchItem.batch_id == batch_id)
        ).all()
        assert {i.package for i in items} == {"starlette", "axios"}
        assert all(i.status == "pending" for i in items)


def test_raise_all_refuses_an_empty_plan(client, engine):
    target_id = _dev_client_with_target(client, engine)
    res = client.post("/api/findings/remediations/raise-all", json={"target_id": target_id})
    assert res.status_code == 400


def test_raise_all_dispatch_failure_fails_the_batch_without_leaking_the_raw_exception(client, engine, monkeypatch):
    """A broker publish failure (Redis unreachable, etc) must not leave the
    batch stuck "running" until mark_stale_if_needed's timeout, and must
    not put the raw exception text -- which can carry internal connection
    details -- in front of a DEVELOPER-role caller (flagged by Toleman's
    own PR Guardrail on this PR)."""
    target_id = _dev_client_with_target(client, engine)
    _finding_with_fix(engine, target_id, "CVE-2024-1", "starlette", "0.40.0")

    def boom(**kwargs):
        raise ConnectionError("redis://internal-host:6379 refused")

    monkeypatch.setattr(findings_module.run_raise_all_batch, "delay", boom)

    res = client.post("/api/findings/remediations/raise-all", json={"target_id": target_id})
    assert res.status_code == 502
    assert "redis://internal-host" not in res.json()["detail"]
    assert "check server logs" in res.json()["detail"]

    with Session(engine) as session:
        batch = session.exec(select(RemediationPrBatch)).first()
        assert batch.status == "completed"
        assert batch.failed == batch.total
        items = session.exec(
            select(RemediationPrBatchItem).where(RemediationPrBatchItem.batch_id == batch.id)
        ).all()
        assert all(i.status == "failed" for i in items)
        assert all("redis://internal-host" not in i.error for i in items)


def test_raise_all_requires_developer_role(client, engine, monkeypatch):
    ws = _workspace(engine)
    target_id = _target(engine, ws)
    uid = _login(client, engine, role=UserRole.USER)
    _assign(engine, uid, ws, WorkspaceRole.VIEWER)
    mock_delay = MagicMock()
    monkeypatch.setattr(findings_module.run_raise_all_batch, "delay", mock_delay)

    res = client.post("/api/findings/remediations/raise-all", json={"target_id": target_id})
    assert res.status_code == 403
    mock_delay.assert_not_called()


def test_get_raise_all_batch_status_running(client, engine, monkeypatch):
    target_id = _dev_client_with_target(client, engine)
    _finding_with_fix(engine, target_id, "CVE-2024-1", "starlette", "0.40.0")
    monkeypatch.setattr(findings_module.run_raise_all_batch, "delay", MagicMock())

    res = client.post("/api/findings/remediations/raise-all", json={"target_id": target_id})
    batch_id = res.json()["batch_id"]

    poll = client.get(f"/api/findings/remediations/raise-all-batches/{batch_id}")
    assert poll.status_code == 200
    body = poll.json()
    assert body["status"] == "running"
    assert body["total"] == 1
    assert len(body["items"]) == 1
    assert body["items"][0]["status"] == "pending"


def test_get_raise_all_batch_404_for_missing_batch(client, engine):
    _dev_client_with_target(client, engine)
    res = client.get("/api/findings/remediations/raise-all-batches/9999")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# End-to-end eager-mode: the real Celery task processes the batch
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


def test_batch_processes_every_package_and_records_mixed_outcomes(client, engine, monkeypatch, eager_celery):
    """One package succeeds, one fails; proves the batch finishes
    "completed" with an accurate per-item breakdown instead of stopping or
    getting stuck at "running" on the failure -- same property
    test_bulk_pipeline_integration.py pins down for its own batch task."""
    target_id = _dev_client_with_target(client, engine)
    _finding_with_fix(engine, target_id, "CVE-2024-1", "starlette", "0.40.0")
    _finding_with_fix(engine, target_id, "CVE-2024-2", "axios", "1.7.4")

    monkeypatch.setattr(remediation_tasks, "engine", engine)
    monkeypatch.setattr(remediation_tasks, "INTER_ITEM_DELAY_SECONDS", 0)

    def fake_raise(session, target, plan, raised_by):
        if plan["package"] == "starlette":
            return {"pr_url": "https://github.com/a/t/pull/1", "pr_number": 1, "branch": "toleman/fix-pkg-1"}
        raise autofix.AutofixError("no manifest could be bumped")

    monkeypatch.setattr(remediation_tasks, "raise_package_fix_pr", fake_raise)

    res = client.post("/api/findings/remediations/raise-all", json={"target_id": target_id})
    assert res.status_code == 202
    batch_id = res.json()["batch_id"]

    # eager mode: task already ran synchronously by the time .delay() returned.
    poll = client.get(f"/api/findings/remediations/raise-all-batches/{batch_id}")
    assert poll.status_code == 200
    body = poll.json()
    assert body["status"] == "completed"
    assert body["succeeded"] == 1
    assert body["failed"] == 1
    by_package = {i["package"]: i for i in body["items"]}
    assert by_package["starlette"]["status"] == "succeeded"
    assert by_package["starlette"]["pr_url"] == "https://github.com/a/t/pull/1"
    assert by_package["axios"]["status"] == "failed"
    assert "no manifest" in by_package["axios"]["error"]
