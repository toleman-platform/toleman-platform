"""#276: per-target scan history.

Deliberately a separate endpoint from GET /api/scans/summary rather than an
extension of it. That endpoint aggregates to at most one row per
(target, tool) precisely so a target scanned nightly for a year doesn't send
hundreds of rows to render one timestamp. A history view is the one place
those individual rows are the point -- so this returns them, scoped to a
single target and paginated, keeping the property that made the aggregation
worth doing: response size never scales with total scan history.
"""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.main import app as fastapi_app
from app.models.models import Organization, Scan, Target, User, UserRole, Workspace


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


def _admin(client, engine):
    with Session(engine) as session:
        u = User(email="a@e.com", name="A", password_hash=hash_password("whatever123"), role=UserRole.ADMIN)
        session.add(u); session.commit(); session.refresh(u)
        token = create_session_token(u.id, u.token_version)
    client.cookies.set("rikugan_session", token)
    return client


def _target(engine, name="t"):
    with Session(engine) as session:
        org = Organization(name="o")
        session.add(org); session.commit(); session.refresh(org)
        ws = Workspace(organization_id=org.id, name="w", api_key=f"k-{name}")
        session.add(ws); session.commit(); session.refresh(ws)
        t = Target(name=name, repo_url="https://github.com/a/b", workspace_id=ws.id)
        session.add(t); session.commit(); session.refresh(t)
        return t.id


def _scan(engine, target_id, tool="semgrep", status="completed", minutes_ago=0, findings=0, error=""):
    with Session(engine) as session:
        started = datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=minutes_ago)
        session.add(Scan(
            target_id=target_id, tool=tool, branch="main", status=status,
            started_at=started,
            completed_at=started + timedelta(seconds=30) if status != "running" else None,
            findings_count=findings, error=error,
        ))
        session.commit()


class TestHistory:
    def test_returns_scans_for_the_target(self, client, engine):
        _admin(client, engine)
        tid = _target(engine)
        _scan(engine, tid, tool="semgrep")
        _scan(engine, tid, tool="gitleaks")
        res = client.get(f"/api/scans/history?target_id={tid}")
        assert res.status_code == 200, res.text
        assert res.json()["total"] == 2
        assert {i["tool"] for i in res.json()["items"]} == {"semgrep", "gitleaks"}

    def test_newest_first(self, client, engine):
        """A history view that led with the oldest run would bury the thing
        the reader almost always wants."""
        _admin(client, engine)
        tid = _target(engine)
        _scan(engine, tid, tool="old", minutes_ago=120)
        _scan(engine, tid, tool="recent", minutes_ago=1)
        items = client.get(f"/api/scans/history?target_id={tid}").json()["items"]
        assert items[0]["tool"] == "recent"

    def test_does_not_leak_another_targets_scans(self, client, engine):
        _admin(client, engine)
        mine = _target(engine, "mine")
        theirs = _target(engine, "theirs")
        _scan(engine, mine, tool="semgrep")
        _scan(engine, theirs, tool="gitleaks")
        items = client.get(f"/api/scans/history?target_id={mine}").json()["items"]
        assert [i["tool"] for i in items] == ["semgrep"]

    def test_failure_reason_is_surfaced(self, client, engine):
        """A failed scan whose reason is invisible reads as 'nothing
        happened' -- the false-all-clear shape this codebase keeps refusing
        (#253)."""
        _admin(client, engine)
        tid = _target(engine)
        _scan(engine, tid, status="failed", error="git clone failed: credentials")
        item = client.get(f"/api/scans/history?target_id={tid}").json()["items"][0]
        assert item["status"] == "failed"
        assert "credentials" in item["error"]

    def test_running_scan_has_no_completed_at(self, client, engine):
        _admin(client, engine)
        tid = _target(engine)
        _scan(engine, tid, status="running")
        item = client.get(f"/api/scans/history?target_id={tid}").json()["items"][0]
        assert item["completed_at"] is None


class TestPagination:
    def test_paginates_and_reports_the_real_total(self, client, engine):
        _admin(client, engine)
        tid = _target(engine)
        for i in range(30):
            _scan(engine, tid, tool=f"tool{i}", minutes_ago=i)
        body = client.get(f"/api/scans/history?target_id={tid}&page=1&page_size=10").json()
        assert body["total"] == 30, "total must be the full count, not the page size"
        assert len(body["items"]) == 10

    def test_second_page_returns_different_rows(self, client, engine):
        _admin(client, engine)
        tid = _target(engine)
        for i in range(30):
            _scan(engine, tid, tool=f"tool{i}", minutes_ago=i)
        p1 = client.get(f"/api/scans/history?target_id={tid}&page=1&page_size=10").json()["items"]
        p2 = client.get(f"/api/scans/history?target_id={tid}&page=2&page_size=10").json()["items"]
        assert {i["scan_id"] for i in p1}.isdisjoint({i["scan_id"] for i in p2})

    def test_page_size_is_capped(self, client, engine):
        """Response size must never scale with total history -- the whole
        reason /summary aggregates instead of listing."""
        _admin(client, engine)
        tid = _target(engine)
        _scan(engine, tid)
        res = client.get(f"/api/scans/history?target_id={tid}&page_size=100000")
        assert res.status_code == 200

    def test_page_zero_is_clamped_not_an_error(self, client, engine):
        _admin(client, engine)
        tid = _target(engine)
        _scan(engine, tid)
        assert client.get(f"/api/scans/history?target_id={tid}&page=0").status_code == 200


class TestAccess:
    def test_unknown_target_is_404(self, client, engine):
        _admin(client, engine)
        assert client.get("/api/scans/history?target_id=9999").status_code == 404

    def test_requires_authentication(self, client, engine):
        tid = _target(engine)
        assert client.get(f"/api/scans/history?target_id={tid}").status_code in (401, 403)

    def test_history_route_is_not_shadowed_by_the_scan_id_route(self, client, engine):
        """GET /{scan_id} would capture "history" and 422 on int coercion if
        declared first -- FastAPI matches in definition order."""
        _admin(client, engine)
        tid = _target(engine)
        res = client.get(f"/api/scans/history?target_id={tid}")
        assert res.status_code != 422
