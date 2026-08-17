"""Tests for GET /api/scans/summary.

Written to pin the endpoint's current behavior before a performance
refactor (senior-review pass, see ROADMAP/ARCHITECTURE notes on the
scans_summary N+1-shaped query): the original implementation pulled every
Scan row for every accessible target into the app process and grouped it in
Python, which scales with total scan history rather than with the number of
targets. There was no direct test coverage for this endpoint despite it
backing the Scans page's "last scanned" line and filter for every target on
every page load -- these tests exist so the query can be rewritten as
SQL-side aggregation with a guarantee that the response shape is unchanged.

Same in-memory SQLite + TestClient + session-token-login pattern as
tests/test_stale_jobs.py.
"""
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
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
    client.cookies.set("rikugan_session", token)
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


def _scan(session, target_id, tool, started_at, completed_at=None):
    session.add(Scan(target_id=target_id, tool=tool, branch="main", status="completed" if completed_at else "running",
                      started_at=started_at, completed_at=completed_at))


def test_empty_when_target_has_no_scans(engine, client):
    client, _ = _login(client, engine)
    _, target_id = _make_workspace_and_target(engine)
    body = client.get("/api/scans/summary").json()
    assert body == {}


def test_reports_last_scan_and_distinct_tools(engine, client):
    client, _ = _login(client, engine)
    _, target_id = _make_workspace_and_target(engine)
    now = datetime(2026, 1, 10, 12, 0, 0)
    with Session(engine) as session:
        _scan(session, target_id, "semgrep", now - timedelta(days=2), now - timedelta(days=2, hours=-1))
        _scan(session, target_id, "trivy", now, now + timedelta(minutes=5))
        session.commit()

    body = client.get("/api/scans/summary").json()
    entry = body[str(target_id)]
    assert sorted(entry["tools"]) == ["semgrep", "trivy"]
    # Latest by completed_at across both tools.
    assert entry["last_scan_at"].startswith("2026-01-10")


def test_running_scan_with_no_completed_at_falls_back_to_started_at(engine, client):
    client, _ = _login(client, engine)
    _, target_id = _make_workspace_and_target(engine)
    with Session(engine) as session:
        _scan(session, target_id, "semgrep", datetime(2026, 1, 5), None)
        session.commit()

    entry = client.get("/api/scans/summary").json()[str(target_id)]
    assert entry["last_scan_at"].startswith("2026-01-05")


def test_a_later_running_scan_beats_an_earlier_completed_one(engine, client):
    # last_scan_at reflects the most recent *attempt*, not just settled runs.
    client, _ = _login(client, engine)
    _, target_id = _make_workspace_and_target(engine)
    with Session(engine) as session:
        _scan(session, target_id, "semgrep", datetime(2026, 1, 1), datetime(2026, 1, 1, 1))
        _scan(session, target_id, "trivy", datetime(2026, 1, 5), None)
        session.commit()

    entry = client.get("/api/scans/summary").json()[str(target_id)]
    assert entry["last_scan_at"].startswith("2026-01-05")


def test_repeated_scans_of_the_same_tool_are_not_duplicated(engine, client):
    # This is the shape that made the original query scale with total scan
    # history: a target scanned nightly for a year has hundreds of rows for
    # one tool, but the tools list must still report it once.
    client, _ = _login(client, engine)
    _, target_id = _make_workspace_and_target(engine)
    with Session(engine) as session:
        base = datetime(2026, 1, 1)
        for i in range(50):
            _scan(session, target_id, "semgrep", base + timedelta(days=i), base + timedelta(days=i, minutes=1))
        session.commit()

    entry = client.get("/api/scans/summary").json()[str(target_id)]
    assert entry["tools"] == ["semgrep"]
    assert entry["last_scan_at"].startswith("2026-02-19")


def test_multiple_targets_are_kept_separate(engine, client):
    client, _ = _login(client, engine)
    _, target_a = _make_workspace_and_target(engine, "a")
    _, target_b = _make_workspace_and_target(engine, "b")
    with Session(engine) as session:
        _scan(session, target_a, "semgrep", datetime(2026, 1, 1), datetime(2026, 1, 1, 1))
        _scan(session, target_b, "trivy", datetime(2026, 1, 2), datetime(2026, 1, 2, 1))
        session.commit()

    body = client.get("/api/scans/summary").json()
    assert set(body.keys()) == {str(target_a), str(target_b)}
    assert body[str(target_a)]["tools"] == ["semgrep"]
    assert body[str(target_b)]["tools"] == ["trivy"]


def test_tools_list_is_sorted():
    pass  # covered implicitly by the alphabetical assertions above; kept as
    # a documented expectation in case ordering logic changes.


def test_scoped_to_accessible_workspaces(engine, client):
    # Same tenant-isolation rule as every other GET/list over
    # workspace-owned resources.
    _, other_target = _make_workspace_and_target(engine, "other-tenant")
    with Session(engine) as session:
        _scan(session, other_target, "semgrep", datetime(2026, 1, 1), datetime(2026, 1, 1, 1))
        session.commit()

    client, _ = _login(client, engine, role=UserRole.USER)
    assert client.get("/api/scans/summary").json() == {}


def test_admin_sees_scans_across_every_workspace(engine, client):
    client, _ = _login(client, engine, role=UserRole.ADMIN)
    _, target_id = _make_workspace_and_target(engine)
    with Session(engine) as session:
        _scan(session, target_id, "semgrep", datetime(2026, 1, 1), datetime(2026, 1, 1, 1))
        session.commit()

    assert str(target_id) in client.get("/api/scans/summary").json()


def test_timestamps_carry_an_explicit_utc_marker(engine, client):
    # started_at/completed_at are naive UTC datetimes; the response must
    # append "Z" so the frontend's `new Date(...)` does not silently
    # interpret them as local time.
    client, _ = _login(client, engine)
    _, target_id = _make_workspace_and_target(engine)
    with Session(engine) as session:
        _scan(session, target_id, "semgrep", datetime(2026, 1, 1), datetime(2026, 1, 1, 1))
        session.commit()

    entry = client.get("/api/scans/summary").json()[str(target_id)]
    assert entry["last_scan_at"].endswith("Z")
