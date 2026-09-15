"""The PR scan log must be readable while the scan is still running.

#502 added PRGuardrailScan.tool_log, and got the timing wrong: it was
written once, after every tool had finished. So a scan still in flight
showed an empty log, and a scan killed mid-run -- by a deploy restarting
the Celery worker, which is how this was noticed on #510 -- showed nothing
at all, permanently.

Those are the two cases someone opens a scan log to understand. A log that
only exists for scans which completed normally answers the question nobody
was asking.

The log is now emitted after every tool and committed by the caller, and
tools that have not been reached yet appear as "pending" so a reviewer can
see which one the scan is currently sitting on.
"""
from app.core import pr_guardrail_executor as executor
from app.core.pr_guardrail_executor import build_tool_log, parse_tool_log


def test_a_tool_not_yet_reached_is_pending():
    """Distinct from "ran and found nothing", and what makes a live log
    readable: the first non-pending entry from the bottom is where the scan
    currently is."""
    raw = build_tool_log(
        tools=["gitleaks", "semgrep-core", "trivy"],
        durations={"gitleaks": 4.0},
        counts={"gitleaks": 1},
        failed=[], skipped={},
    )
    entries = {e["tool"]: e for e in parse_tool_log(raw)}

    assert entries["gitleaks"]["status"] == "ran"
    assert entries["semgrep-core"]["status"] == "pending"
    assert entries["trivy"]["status"] == "pending"
    assert entries["semgrep-core"]["seconds"] is None


def test_progress_is_emitted_after_every_tool(monkeypatch, tmp_path):
    """The load-bearing behaviour. One emission at the end is what #502
    shipped, and it is indistinguishable from no log at all for a scan that
    never finishes."""
    monkeypatch.setattr(executor.runner, "run_tool", lambda tool, repo_path, paths=None: {})
    monkeypatch.setattr(executor.parsers, "PARSER_MAP", {
        "a": lambda raw: [], "b": lambda raw: [], "c": lambda raw: [],
    })

    snapshots = []
    executor._run_guardrail_tools(
        ["a", "b", "c"], tmp_path, durations={}, counts={},
        on_progress=snapshots.append,
    )

    assert len(snapshots) == 3, "one emission per tool, not one at the end"
    # Each snapshot should show one more tool done than the last.
    done = [
        sum(1 for e in parse_tool_log(s) if e["status"] != "pending")
        for s in snapshots
    ]
    assert done == [1, 2, 3]


def test_a_failing_tool_still_reports_progress(monkeypatch, tmp_path):
    """"Ran for eighty seconds and then errored" is the case most worth
    seeing, so a failure must not skip the emission."""
    def boom(tool, repo_path, paths=None):
        raise RuntimeError("nope")

    monkeypatch.setattr(executor.runner, "run_tool", boom)
    monkeypatch.setattr(executor.parsers, "PARSER_MAP", {"a": lambda raw: []})

    snapshots = []
    _, failed, _ = executor._run_guardrail_tools(
        ["a"], tmp_path, durations={}, counts={}, on_progress=snapshots.append
    )

    assert failed == ["a"]
    assert len(snapshots) == 1
    assert parse_tool_log(snapshots[0])[0]["status"] == "failed"


def test_a_skipped_tool_still_reports_progress(monkeypatch, tmp_path):
    def not_applicable(tool, repo_path, paths=None):
        raise executor.runner.ToolNotApplicable("no manifest changed")

    monkeypatch.setattr(executor.runner, "run_tool", not_applicable)
    monkeypatch.setattr(executor.parsers, "PARSER_MAP", {"a": lambda raw: []})

    snapshots = []
    executor._run_guardrail_tools(
        ["a"], tmp_path, durations={}, counts={}, on_progress=snapshots.append
    )

    entry = parse_tool_log(snapshots[0])[0]
    assert entry["status"] == "skipped"
    assert entry["detail"] == "no manifest changed"


def test_a_failing_progress_callback_cannot_fail_the_scan(monkeypatch, tmp_path):
    """Persisting progress must never become the cause of the outage it was
    added to diagnose. A deadlocked commit or serialisation error is logged
    and the scan continues."""
    monkeypatch.setattr(executor.runner, "run_tool", lambda tool, repo_path, paths=None: {})
    monkeypatch.setattr(executor.parsers, "PARSER_MAP", {"a": lambda raw: []})

    def explode(_log):
        raise RuntimeError("database is on fire")

    findings, failed, skipped = executor._run_guardrail_tools(
        ["a"], tmp_path, durations={}, counts={}, on_progress=explode
    )

    assert failed == [] and skipped == {}


def test_no_callback_still_works(monkeypatch, tmp_path):
    """Every existing caller and test passes none."""
    monkeypatch.setattr(executor.runner, "run_tool", lambda tool, repo_path, paths=None: {})
    monkeypatch.setattr(executor.parsers, "PARSER_MAP", {"a": lambda raw: []})

    findings, failed, skipped = executor._run_guardrail_tools(["a"], tmp_path)

    assert findings == [] and failed == [] and skipped == {}


# --- retrying a PR scan ----------------------------------------------

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine  # noqa: E402

import app.api.deps as deps_module  # noqa: E402
from app.api.deps import get_session  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.security import create_session_token, hash_password  # noqa: E402
from app.core.time import utcnow  # noqa: E402
from app.main import app as fastapi_app  # noqa: E402
from app.models.models import (  # noqa: E402
    Organization,
    PRGuardrailScan,
    PRGuardrailStatus,
    Target,
    User,
    UserRole,
    Workspace,
    WorkspaceMembership,
    WorkspaceRole,
)
from datetime import timedelta  # noqa: E402


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


def _seed(engine, status=PRGuardrailStatus.ERROR, age_seconds=0):
    with Session(engine) as session:
        org = Organization(name="Acme")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws", api_key="k")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        t = Target(workspace_id=ws.id, name="t", repo_url="https://github.com/a/b")
        session.add(t)
        session.commit()
        session.refresh(t)
        scan = PRGuardrailScan(
            target_id=t.id, pr_number=510, branch="feat/x", status=status,
            created_at=utcnow() - timedelta(seconds=age_seconds),
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        user = User(email="d@example.com", name="D",
                    password_hash=hash_password("whatever123"), role=UserRole.DEVELOPER)
        session.add(user)
        session.commit()
        session.refresh(user)
        session.add(WorkspaceMembership(
            user_id=user.id, workspace_id=ws.id, role=WorkspaceRole.DEVELOPER))
        session.commit()
        return scan.id, create_session_token(user.id, user.token_version)


def test_an_errored_scan_can_be_retried(client, engine, monkeypatch):
    """Before this, a dead scan had no way back from the product: the only
    recourse was pushing an empty commit to make GitHub re-fire the
    webhook."""
    dispatched = []
    import app.api.pr_guardrail as api
    monkeypatch.setattr(api.run_pr_guardrail_scan_task, "delay",
                        lambda **kw: dispatched.append(kw))

    scan_id, token = _seed(engine, status=PRGuardrailStatus.ERROR)
    client.cookies.set("toleman_session", token)

    res = client.post(f"/api/pr-guardrail/{scan_id}/retry")

    assert res.status_code == 200
    assert res.json()["status"] == "queued"
    assert dispatched == [{"target_id": 1, "pr_number": 510}]


def test_a_healthy_running_scan_is_not_duplicated(client, engine, monkeypatch):
    """Two runs over one PR race each other's findings and commit status."""
    dispatched = []
    import app.api.pr_guardrail as api
    monkeypatch.setattr(api.run_pr_guardrail_scan_task, "delay",
                        lambda **kw: dispatched.append(kw))

    scan_id, token = _seed(engine, status=PRGuardrailStatus.RUNNING, age_seconds=5)
    client.cookies.set("toleman_session", token)

    res = client.post(f"/api/pr-guardrail/{scan_id}/retry")

    assert res.status_code == 409
    assert "still running" in res.json()["detail"]
    assert dispatched == []


def test_a_stuck_running_scan_can_be_retried(client, engine, monkeypatch):
    """The case that prompted this. A worker restarted by a deploy leaves
    the row on "running" forever; once it is old enough for the staleness
    sweep to disown, a retry supersedes it."""
    dispatched = []
    import app.api.pr_guardrail as api
    monkeypatch.setattr(api.run_pr_guardrail_scan_task, "delay",
                        lambda **kw: dispatched.append(kw))

    scan_id, token = _seed(
        engine, status=PRGuardrailStatus.RUNNING,
        age_seconds=settings.stale_job_timeout_seconds + 60,
    )
    client.cookies.set("toleman_session", token)

    res = client.post(f"/api/pr-guardrail/{scan_id}/retry")

    assert res.status_code == 200
    assert len(dispatched) == 1
    with Session(engine) as session:
        assert session.get(PRGuardrailScan, scan_id).status == PRGuardrailStatus.ERROR


def test_retrying_an_unknown_scan_is_a_404(client, engine):
    _scan_id, token = _seed(engine)
    client.cookies.set("toleman_session", token)

    assert client.post("/api/pr-guardrail/99999/retry").status_code == 404
