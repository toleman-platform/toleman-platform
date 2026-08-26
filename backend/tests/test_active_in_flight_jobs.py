"""Tests for findings CTX-02 and CTX-03's in-flight-state half.

Both surfaces held "is this job running" in local React state, so navigating
away and back offered a fresh, clickable button for a job still running on
the worker:

  * PR History, "Scan This PR" reset to clickable while the API still
    reported the scan `running`, and the audit-log card *lower on the same
    page* correctly showed `running`. Clicking again starts a duplicate
    clone-and-scan.
  * Tool Marketplace, the install spinner vanished and the card offered
    "Install" again mid-install.

On-Demand Scan already did this correctly by reading GET /api/scans/active
(CTX-01). These endpoints are that same pattern for the two surfaces that
lacked it: the server is the source of truth for what is in flight.
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
    PRGuardrailScan,
    PRGuardrailStatus,
    Target,
    ToolInstallRun,
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
    with Session(engine) as session:
        user = User(
            email=f"{role.value}-{id(object())}@example.com",
            name="Test",
            password_hash=hash_password("whatever123"),
            role=role,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        uid = user.id
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return client, uid


def _make_target(engine, name="repo") -> tuple[int, int]:
    with Session(engine) as session:
        org = Organization(name=f"org-{name}")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name=f"ws-{name}", api_key=f"key-{name}")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        t = Target(workspace_id=ws.id, name=name, repo_url=f"https://github.com/acme/{name}")
        session.add(t)
        session.commit()
        session.refresh(t)
        return t.id, ws.id


def _pr_scan(engine, target_id, pr_number=4, status=PRGuardrailStatus.RUNNING, created_at=None) -> int:
    with Session(engine) as session:
        scan = PRGuardrailScan(
            target_id=target_id,
            pr_number=pr_number,
            branch="feature",
            status=status,
            created_at=created_at or datetime.utcnow(),
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        return scan.id


# ---------------------------------------------------------------------------
# CTX-02: GET /api/pr-guardrail/active
# ---------------------------------------------------------------------------


def test_running_pr_scan_is_reported_as_active(client, engine):
    target_id, _ = _make_target(engine)
    scan_id = _pr_scan(engine, target_id)
    client, _ = _login(client, engine)

    res = client.get("/api/pr-guardrail/active")
    assert res.status_code == 200
    body = res.json()

    # Keyed target:pr so a component rendering one PR row can answer
    # "am I running" without scanning a list.
    assert f"{target_id}:4" in body
    assert body[f"{target_id}:4"]["pr_scan_id"] == scan_id
    assert body[f"{target_id}:4"]["branch"] == "feature"


def test_settled_pr_scans_are_not_reported_as_active(client, engine):
    target_id, _ = _make_target(engine)
    for status in (PRGuardrailStatus.PASSED, PRGuardrailStatus.BLOCKED, PRGuardrailStatus.ERROR):
        _pr_scan(engine, target_id, pr_number=10, status=status)
    client, _ = _login(client, engine)

    assert client.get("/api/pr-guardrail/active").json() == {}


def test_a_stale_running_pr_scan_is_swept_not_reported(client, engine):
    """A worker that died mid-scan leaves the row "running" forever. Reporting
    it as active renders as permanently in flight, which is indistinguishable
    from a hung platform; and keeps the button disabled forever."""
    target_id, _ = _make_target(engine)
    scan_id = _pr_scan(engine, target_id, created_at=datetime.utcnow() - timedelta(hours=3))
    client, _ = _login(client, engine)

    assert client.get("/api/pr-guardrail/active").json() == {}

    with Session(engine) as session:
        scan = session.get(PRGuardrailScan, scan_id)
        # Its own status vocabulary, not the generic "failed"; this value
        # is what the GitHub commit status is derived from.
        assert scan.status == PRGuardrailStatus.ERROR
        assert scan.completed_at is not None


def test_active_pr_scans_are_workspace_scoped(client, engine):
    """A non-admin must not learn that a scan is running in a workspace they
    have no membership in."""
    mine_id, mine_ws = _make_target(engine, name="mine")
    theirs_id, _ = _make_target(engine, name="theirs")
    _pr_scan(engine, mine_id, pr_number=1)
    _pr_scan(engine, theirs_id, pr_number=2)

    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    with Session(engine) as session:
        session.add(WorkspaceMembership(user_id=uid, workspace_id=mine_ws, role=WorkspaceRole.DEVELOPER))
        session.commit()

    body = client.get("/api/pr-guardrail/active").json()
    assert f"{mine_id}:1" in body
    assert f"{theirs_id}:2" not in body


def test_a_user_with_no_memberships_sees_nothing(client, engine):
    target_id, _ = _make_target(engine)
    _pr_scan(engine, target_id)
    client, _ = _login(client, engine, role=UserRole.DEVELOPER)

    assert client.get("/api/pr-guardrail/active").json() == {}


def test_active_pr_scans_requires_a_session(client, engine):
    assert client.get("/api/pr-guardrail/active").status_code == 401


# ---------------------------------------------------------------------------
# CTX-03 (second half): GET /api/tools/installs/active
# ---------------------------------------------------------------------------


def _install_run(engine, tool="checkov", status="running", started_at=None) -> int:
    with Session(engine) as session:
        run = ToolInstallRun(
            tool=tool,
            package=tool,
            status=status,
            started_at=started_at or datetime.utcnow(),
        )
        session.add(run)
        session.commit()
        session.refresh(run)
        return run.id


def test_running_install_is_reported_as_active(client, engine):
    run_id = _install_run(engine)
    client, _ = _login(client, engine)

    body = client.get("/api/tools/installs/active").json()
    assert "checkov" in body
    assert body["checkov"]["run_id"] == run_id
    assert body["checkov"]["status"] == "running"


def test_settled_installs_are_not_reported_as_active(client, engine):
    _install_run(engine, status="completed")
    _install_run(engine, tool="tfsec", status="failed")
    client, _ = _login(client, engine)

    assert client.get("/api/tools/installs/active").json() == {}


def test_a_stale_running_install_is_swept_not_reported(client, engine):
    run_id = _install_run(engine, started_at=datetime.utcnow() - timedelta(hours=3))
    client, _ = _login(client, engine)

    assert client.get("/api/tools/installs/active").json() == {}

    with Session(engine) as session:
        assert session.get(ToolInstallRun, run_id).status == "failed"


def test_active_installs_route_is_not_shadowed_by_the_run_id_route(client, engine):
    """FastAPI matches in declaration order, so /installs/active must be
    declared before /installs/{run_id} or "active" gets captured as a run_id
    and 422s on int coercion."""
    client, _ = _login(client, engine)
    res = client.get("/api/tools/installs/active")
    assert res.status_code == 200
    assert res.status_code != 422


def test_active_installs_are_admin_only(client, engine):
    _install_run(engine)
    client, _ = _login(client, engine, role=UserRole.DEVELOPER)

    # Installing mutates the running environment, so even knowing what is
    # installing is admin-scoped; same gate as the install endpoint itself.
    assert client.get("/api/tools/installs/active").status_code == 403
