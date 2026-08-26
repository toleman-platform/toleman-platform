"""Tests for issue #212: scan status, elapsed time and a grounded ETA.

Two things are being pinned down here.

The first is that `GET /api/scans/active` exists at all, a scan dispatched
from one page used to be invisible on every other page, so Targets happily
showed "last scanned 3 days ago" while a scan was in flight.

The second, and the one most of these tests are about, is that an ETA is
only ever produced from that target's own history with that tool. A
fabricated estimate is worse than none, so the interesting assertions are
the ones about *not* returning a number: too few samples, failed runs, and a
different repo's history must all yield null rather than a plausible guess.

Same in-memory SQLite + TestClient + session-token-login pattern as
tests/test_stale_jobs.py.
"""
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.config import settings
from app.core.scan_eta import elapsed_seconds, estimate_duration_seconds
from app.core.security import create_session_token, hash_password
from app.core.time import utcnow
from app.main import app
from app.models.models import (
    Organization,
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


def _login(client, engine, role=UserRole.ADMIN):
    email = f"{role.value}-{id(object())}@example.com"
    with Session(engine) as session:
        user = User(email=email, name="Test", password_hash=hash_password("whatever123"), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        uid = user.id
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return client, uid


def _make_workspace_and_target(engine, name="target") -> tuple[int, int]:
    with Session(engine) as session:
        org = Organization(name=f"org-{name}")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name=f"ws-{name}", api_key=f"key-{name}")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        target = Target(workspace_id=ws.id, name=name, repo_url=f"https://github.com/acme/{name}")
        session.add(target)
        session.commit()
        session.refresh(target)
        return ws.id, target.id


def _completed_scan(session, target_id: int, tool: str, seconds: int, age_minutes: int = 0):
    started = utcnow() - timedelta(minutes=age_minutes, seconds=seconds)
    scan = Scan(
        target_id=target_id,
        tool=tool,
        branch="main",
        status="completed",
        started_at=started,
        completed_at=started + timedelta(seconds=seconds),
    )
    session.add(scan)
    session.commit()
    return scan


# ---------------------------------------------------------------------------
# estimate_duration_seconds: when a number is and is not justified
# ---------------------------------------------------------------------------


def test_no_estimate_without_any_history(engine):
    _, target_id = _make_workspace_and_target(engine)
    with Session(engine) as session:
        assert estimate_duration_seconds(session, target_id, "semgrep") is None


def test_no_estimate_below_the_minimum_sample_size(engine):
    # Two runs is not enough to resist one anomaly: the median of two is just
    # their average, so a single slow outlier moves it by half its error.
    _, target_id = _make_workspace_and_target(engine)
    with Session(engine) as session:
        _completed_scan(session, target_id, "semgrep", 30)
        _completed_scan(session, target_id, "semgrep", 34)
        assert estimate_duration_seconds(session, target_id, "semgrep") is None


def test_estimate_is_the_median_of_completed_runs(engine):
    _, target_id = _make_workspace_and_target(engine)
    with Session(engine) as session:
        for seconds in (30, 40, 50):
            _completed_scan(session, target_id, "semgrep", seconds)
        assert estimate_duration_seconds(session, target_id, "semgrep") == 40


def test_median_resists_a_single_outlier(engine):
    # The reason this is a median and not a mean: one pathological run should
    # not drag every subsequent estimate upward.
    _, target_id = _make_workspace_and_target(engine)
    with Session(engine) as session:
        for seconds in (30, 32, 34, 36, 3600):
            _completed_scan(session, target_id, "semgrep", seconds)
        assert estimate_duration_seconds(session, target_id, "semgrep") == 34


def test_failed_runs_are_not_sampled(engine):
    # A failed run's duration measures how long the platform took to give up (
    # usually a clone timeout) not how long the work takes.
    _, target_id = _make_workspace_and_target(engine)
    with Session(engine) as session:
        started = utcnow() - timedelta(seconds=900)
        for _ in range(5):
            session.add(
                Scan(
                    target_id=target_id,
                    tool="semgrep",
                    branch="main",
                    status="failed",
                    started_at=started,
                    completed_at=started + timedelta(seconds=900),
                    error="Timed out",
                )
            )
        session.commit()
        assert estimate_duration_seconds(session, target_id, "semgrep") is None


def test_estimate_is_per_tool(engine):
    # Trivy history says nothing about how long Semgrep will take.
    _, target_id = _make_workspace_and_target(engine)
    with Session(engine) as session:
        for seconds in (10, 12, 14):
            _completed_scan(session, target_id, "trivy", seconds)
        assert estimate_duration_seconds(session, target_id, "trivy") == 12
        assert estimate_duration_seconds(session, target_id, "semgrep") is None


def test_estimate_is_per_target(engine):
    # Scan duration is dominated by repo size, so another repo's history is
    # not evidence about this one. This is the case a global average would
    # get wrong.
    _, target_a = _make_workspace_and_target(engine, "repo-a")
    _, target_b = _make_workspace_and_target(engine, "repo-b")
    with Session(engine) as session:
        for seconds in (10, 12, 14):
            _completed_scan(session, target_a, "semgrep", seconds)
        assert estimate_duration_seconds(session, target_b, "semgrep") is None


def test_zero_and_negative_durations_are_discarded(engine):
    # A clock adjustment or an out-of-order write is bad data, not a scan
    # that finished instantly.
    _, target_id = _make_workspace_and_target(engine)
    with Session(engine) as session:
        started = utcnow() - timedelta(seconds=60)
        for delta in (0, -5, -10):
            session.add(
                Scan(
                    target_id=target_id,
                    tool="semgrep",
                    branch="main",
                    status="completed",
                    started_at=started,
                    completed_at=started + timedelta(seconds=delta),
                )
            )
        session.commit()
        assert estimate_duration_seconds(session, target_id, "semgrep") is None


def test_only_the_most_recent_runs_are_sampled(engine):
    # A repo that has grown should not be estimated from runs predating the
    # growth: 12 old fast runs must not outvote the recent slow ones.
    _, target_id = _make_workspace_and_target(engine)
    with Session(engine) as session:
        for i in range(12):
            _completed_scan(session, target_id, "semgrep", 10, age_minutes=1000 + i)
        for i in range(10):
            _completed_scan(session, target_id, "semgrep", 100, age_minutes=i)
        assert estimate_duration_seconds(session, target_id, "semgrep") == 100


# ---------------------------------------------------------------------------
# elapsed_seconds: the always-available fallback
# ---------------------------------------------------------------------------


def test_elapsed_counts_up_while_running(engine):
    _, target_id = _make_workspace_and_target(engine)
    scan = Scan(
        target_id=target_id,
        tool="semgrep",
        branch="main",
        status="running",
        started_at=utcnow() - timedelta(seconds=45),
    )
    assert 44 <= elapsed_seconds(scan) <= 47


def test_elapsed_freezes_at_completion(engine):
    _, target_id = _make_workspace_and_target(engine)
    started = utcnow() - timedelta(seconds=300)
    scan = Scan(
        target_id=target_id,
        tool="semgrep",
        branch="main",
        status="completed",
        started_at=started,
        completed_at=started + timedelta(seconds=42),
    )
    assert elapsed_seconds(scan) == 42


# ---------------------------------------------------------------------------
# GET /api/scans/{id}
# ---------------------------------------------------------------------------


def test_get_scan_reports_elapsed_and_eta_while_running(engine, client):
    client, _ = _login(client, engine)
    _, target_id = _make_workspace_and_target(engine)
    with Session(engine) as session:
        for seconds in (30, 40, 50):
            _completed_scan(session, target_id, "semgrep", seconds, age_minutes=60)
        running = Scan(
            target_id=target_id,
            tool="semgrep",
            branch="main",
            status="running",
            started_at=utcnow() - timedelta(seconds=10),
        )
        session.add(running)
        session.commit()
        session.refresh(running)
        scan_id = running.id

    body = client.get(f"/api/scans/{scan_id}").json()
    assert body["status"] == "running"
    assert body["eta_seconds"] == 40
    assert body["elapsed_seconds"] >= 9


def test_get_scan_omits_eta_when_history_is_too_thin(engine, client):
    client, _ = _login(client, engine)
    _, target_id = _make_workspace_and_target(engine)
    with Session(engine) as session:
        running = Scan(
            target_id=target_id,
            tool="semgrep",
            branch="main",
            status="running",
            started_at=utcnow() - timedelta(seconds=5),
        )
        session.add(running)
        session.commit()
        session.refresh(running)
        scan_id = running.id

    body = client.get(f"/api/scans/{scan_id}").json()
    # Null, not a default; the UI shows elapsed time instead.
    assert body["eta_seconds"] is None
    assert body["elapsed_seconds"] >= 4


def test_settled_scan_carries_no_eta(engine, client):
    client, _ = _login(client, engine)
    _, target_id = _make_workspace_and_target(engine)
    with Session(engine) as session:
        for seconds in (30, 40, 50):
            _completed_scan(session, target_id, "semgrep", seconds, age_minutes=60)
        scan = _completed_scan(session, target_id, "semgrep", 33)
        session.refresh(scan)
        scan_id = scan.id

    body = client.get(f"/api/scans/{scan_id}").json()
    # It has a real duration; an estimate for it would be noise.
    assert body["eta_seconds"] is None
    assert body["elapsed_seconds"] == 33


def test_stale_running_scan_reports_failed_with_a_reason(engine, client):
    # An indefinite spinner is indistinguishable from a hung platform, so a
    # timed-out row must read as failed and say why.
    client, _ = _login(client, engine)
    _, target_id = _make_workspace_and_target(engine)
    with Session(engine) as session:
        scan = Scan(
            target_id=target_id,
            tool="semgrep",
            branch="main",
            status="running",
            started_at=utcnow() - timedelta(seconds=settings.stale_job_timeout_seconds + 60),
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        scan_id = scan.id

    body = client.get(f"/api/scans/{scan_id}").json()
    assert body["status"] == "failed"
    assert body["error_message"]


# ---------------------------------------------------------------------------
# GET /api/scans/active
# ---------------------------------------------------------------------------


def test_active_lists_running_scans_grouped_by_target(engine, client):
    client, _ = _login(client, engine)
    _, target_id = _make_workspace_and_target(engine)
    with Session(engine) as session:
        for tool in ("semgrep", "trivy"):
            session.add(
                Scan(
                    target_id=target_id,
                    tool=tool,
                    branch="main",
                    status="running",
                    started_at=utcnow() - timedelta(seconds=5),
                )
            )
        session.commit()

    body = client.get("/api/scans/active").json()
    assert sorted(s["tool"] for s in body[str(target_id)]) == ["semgrep", "trivy"]


def test_active_excludes_settled_scans(engine, client):
    client, _ = _login(client, engine)
    _, target_id = _make_workspace_and_target(engine)
    with Session(engine) as session:
        _completed_scan(session, target_id, "semgrep", 30)

    assert client.get("/api/scans/active").json() == {}


def test_active_sweeps_and_excludes_stale_rows(engine, client):
    # This endpoint backs list views, so it is often the first thing to touch
    # a row a dead worker left running. Reporting it as active would render a
    # permanent in-flight badge on the Targets page.
    client, _ = _login(client, engine)
    _, target_id = _make_workspace_and_target(engine)
    with Session(engine) as session:
        session.add(
            Scan(
                target_id=target_id,
                tool="semgrep",
                branch="main",
                status="running",
                started_at=utcnow() - timedelta(seconds=settings.stale_job_timeout_seconds + 60),
            )
        )
        session.commit()

    assert client.get("/api/scans/active").json() == {}
    with Session(engine) as session:
        swept = session.exec(select(Scan)).first()
        assert swept.status == "failed"


def test_active_covers_dast_runs_too(engine, client):
    # Active API scanning writes to the same Scan table with tool="api-scan",
    # so DAST gets the same visibility as SAST without a parallel surface.
    client, _ = _login(client, engine)
    _, target_id = _make_workspace_and_target(engine)
    with Session(engine) as session:
        session.add(
            Scan(
                target_id=target_id,
                tool="api-scan",
                branch="main",
                status="running",
                started_at=utcnow() - timedelta(seconds=5),
            )
        )
        session.commit()

    body = client.get("/api/scans/active").json()
    assert body[str(target_id)][0]["tool"] == "api-scan"


def test_active_is_workspace_scoped(engine, client):
    # Same tenant-isolation rule as every other GET/list over workspace-owned
    # resources: a non-admin must not see another workspace's running scans.
    _, target_id = _make_workspace_and_target(engine, "other-tenant")
    with Session(engine) as session:
        session.add(
            Scan(
                target_id=target_id,
                tool="semgrep",
                branch="main",
                status="running",
                started_at=utcnow() - timedelta(seconds=5),
            )
        )
        session.commit()

    client, uid = _login(client, engine, role=UserRole.USER)
    assert client.get("/api/scans/active").json() == {}


def test_active_shows_scans_in_a_workspace_the_user_belongs_to(engine, client):
    ws_id, target_id = _make_workspace_and_target(engine, "mine")
    client, uid = _login(client, engine, role=UserRole.USER)
    with Session(engine) as session:
        session.add(WorkspaceMembership(workspace_id=ws_id, user_id=uid, role=WorkspaceRole.DEVELOPER))
        session.add(
            Scan(
                target_id=target_id,
                tool="semgrep",
                branch="main",
                status="running",
                started_at=utcnow() - timedelta(seconds=5),
            )
        )
        session.commit()

    body = client.get("/api/scans/active").json()
    assert str(target_id) in body
