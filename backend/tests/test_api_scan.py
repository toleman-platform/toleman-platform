"""Tests for issue #72: active API scanning (nuclei) against a target's
already-discovered endpoints.

Same layering as tests/test_celery_offload.py (issue #59's dispatch tests):

  1. Pure-function tests for app.core.api_scan_targets.build_scan_urls (the
     actual safety boundary -- host/route validation) and
     app.scanners.parsers.parse_nuclei, no DB/subprocess involved.
  2. Dispatch tests: mock run_api_scan.delay() to prove POST
     /api/api-scan/{target_id} validates api_base_url/endpoints and creates
     the Scan tracking row without ever shelling out to nuclei.
  3. End-to-end eager-mode test: flip Celery's task_always_eager and
     monkeypatch only the boundary that actually shells out
     (runner.run_nuclei) with canned nuclei-shaped JSONL output, proving the
     full dispatch -> execution -> Finding-ingestion path genuinely works.
"""
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.api_scan_targets import ApiScanConfigError, build_scan_urls
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    ApiEndpoint,
    Finding,
    Organization,
    Scan,
    Target,
    User,
    UserRole,
    Workspace,
    WorkspaceMembership,
    WorkspaceRole,
)
from app.scanners.parsers import parse_nuclei
from app.tasks import api_scan_tasks
from app.tasks.celery_app import celery_app


# ---------------------------------------------------------------------------
# 1. Pure-function tests
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    return eng


def _make_target(engine, api_base_url: str | None = "https://api.example.com") -> int:
    with Session(engine) as session:
        org = Organization(name="org")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(name="ws", organization_id=org.id, api_key=f"key-{org.id}-{id(org)}")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        target = Target(
            workspace_id=ws.id,
            name="svc",
            repo_url="https://github.com/acme/svc",
            default_branch="main",
            api_base_url=api_base_url,
        )
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


def _add_endpoint(engine, target_id: int, route: str, method: str = "GET") -> int:
    with Session(engine) as session:
        target = session.get(Target, target_id)
        e = ApiEndpoint(
            target_id=target_id, branch=target.default_branch, framework="fastapi", method=method,
            route=route, file_path="main.py", line=1,
        )
        session.add(e)
        session.commit()
        session.refresh(e)
        return e.id


def test_build_scan_urls_requires_api_base_url(engine):
    target_id = _make_target(engine, api_base_url=None)
    _add_endpoint(engine, target_id, "/health")
    with Session(engine) as session:
        target = session.get(Target, target_id)
        with pytest.raises(ApiScanConfigError):
            build_scan_urls(session, target)


def test_build_scan_urls_joins_route_onto_base(engine):
    target_id = _make_target(engine, api_base_url="https://api.example.com")
    _add_endpoint(engine, target_id, "/users/{id}")
    with Session(engine) as session:
        target = session.get(Target, target_id)
        urls, endpoints = build_scan_urls(session, target)
        assert urls == ["https://api.example.com/users/{id}"]
        assert len(endpoints) == 1


def test_build_scan_urls_rejects_route_that_pivots_host(engine):
    """A route containing '://' or starting with '//' must never be allowed
    to redirect the scan to a different host than the target's configured
    api_base_url -- this is the core SSRF-adjacent safety boundary for
    active scanning (see api_scan_targets.py docstring)."""
    target_id = _make_target(engine, api_base_url="https://api.example.com")
    _add_endpoint(engine, target_id, "//evil.example.com/steal")
    _add_endpoint(engine, target_id, "https://evil.example.com/steal")
    _add_endpoint(engine, target_id, "/legit")
    with Session(engine) as session:
        target = session.get(Target, target_id)
        urls, endpoints = build_scan_urls(session, target)
        # The two malicious routes are dropped, not fatal to the whole scan.
        assert urls == ["https://api.example.com/legit"]
        assert len(endpoints) == 1


def test_build_scan_urls_filters_to_selected_endpoint_ids(engine):
    target_id = _make_target(engine)
    keep_id = _add_endpoint(engine, target_id, "/keep")
    _add_endpoint(engine, target_id, "/drop")
    with Session(engine) as session:
        target = session.get(Target, target_id)
        urls, endpoints = build_scan_urls(session, target, endpoint_ids=[keep_id])
        assert urls == ["https://api.example.com/keep"]


def test_build_scan_urls_ignores_endpoint_ids_from_other_targets(engine):
    """An id belonging to a different target must never leak its route into
    this target's scan -- build_scan_urls only ever queries this target's
    own ApiEndpoint rows, so a foreign id is just absent from the result,
    never resolved cross-target."""
    target_id = _make_target(engine)
    other_target_id = _make_target(engine)
    foreign_id = _add_endpoint(engine, other_target_id, "/other-teams-route")
    _add_endpoint(engine, target_id, "/mine")
    with Session(engine) as session:
        target = session.get(Target, target_id)
        urls, _ = build_scan_urls(session, target, endpoint_ids=[foreign_id])
        assert urls == []


def test_parse_nuclei_maps_severity_and_cve():
    raw = [
        {
            "template-id": "exposed-panel-detect",
            "info": {
                "name": "Exposed Admin Panel",
                "severity": "high",
                "description": "An admin panel is exposed.",
                "classification": {"cve-id": ["CVE-2021-1234"]},
            },
            "matched-at": "https://api.example.com/admin",
            "matcher-name": "panel-match",
        }
    ]
    out = parse_nuclei(raw)
    assert len(out) == 1
    item = out[0]
    assert item["rule_id"] == "exposed-panel-detect"
    assert item["title"] == "Exposed Admin Panel"
    assert item["file_path"] == "https://api.example.com/admin"
    assert item["cve_id"] == "CVE-2021-1234"
    from app.models.models import Severity

    assert item["severity"] == Severity.HIGH


def test_parse_nuclei_handles_no_cve_gracefully():
    raw = [{"template-id": "default-login", "info": {"name": "Default creds", "severity": "medium"}, "matched-at": "https://x/login"}]
    out = parse_nuclei(raw)
    assert out[0]["cve_id"] is None


# ---------------------------------------------------------------------------
# 2 & 3. API-level tests (TestClient + in-memory SQLite)
# ---------------------------------------------------------------------------


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


def _login(client, engine, role=UserRole.DEVELOPER):
    email = f"{role.value}-apiscan@example.com"
    with Session(engine) as session:
        user = User(email=email, name="Test", password_hash=hash_password("whatever123"), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        uid = user.id
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("osp_session", token)
    return client, uid


def _join_workspace(engine, user_id: int, workspace_id: int, role=WorkspaceRole.DEVELOPER):
    with Session(engine) as session:
        session.add(WorkspaceMembership(user_id=user_id, workspace_id=workspace_id, role=role))
        session.commit()


def test_post_api_scan_rejects_target_without_api_base_url(client, engine):
    client, uid = _login(client, engine)
    target_id = _make_target(engine, api_base_url=None)
    with Session(engine) as session:
        _join_workspace(engine, uid, session.get(Target, target_id).workspace_id)

    resp = client.post(f"/api/api-scan/{target_id}")
    assert resp.status_code == 400
    assert "api_base_url" in resp.json()["detail"]


def test_post_api_scan_dispatches_task_and_creates_scan_row(client, engine, monkeypatch):
    client, uid = _login(client, engine)
    target_id = _make_target(engine)
    _add_endpoint(engine, target_id, "/health")
    with Session(engine) as session:
        _join_workspace(engine, uid, session.get(Target, target_id).workspace_id)

    mock_delay = MagicMock()
    monkeypatch.setattr(api_scan_tasks.run_api_scan, "delay", mock_delay)
    # Also patch the reference imported into the router module.
    import app.api.api_scan as api_scan_module

    monkeypatch.setattr(api_scan_module.run_api_scan, "delay", mock_delay)

    resp = client.post(f"/api/api-scan/{target_id}")
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "running"
    assert body["endpoint_count"] == 1
    mock_delay.assert_called_once()

    with Session(engine) as session:
        scan = session.get(Scan, body["scan_id"])
        assert scan is not None
        assert scan.tool == "api-scan"
        assert scan.status == "running"


def test_get_latest_api_scan_returns_full_scanrun_shape(client, engine):
    """The frontend's ScanRun type (also used by GET /api/scans/{id}) needs
    scan_id/target_id/tool/branch/status/findings_count/started_at/
    completed_at all present -- verify the /latest payload matches, not
    just a status string."""
    client, uid = _login(client, engine)
    target_id = _make_target(engine)
    with Session(engine) as session:
        _join_workspace(engine, uid, session.get(Target, target_id).workspace_id)
        scan = Scan(target_id=target_id, tool="api-scan", branch="main", status="completed", findings_count=3)
        session.add(scan)
        session.commit()

    resp = client.get(f"/api/api-scan/{target_id}/latest")
    assert resp.status_code == 200
    scan_body = resp.json()["scan"]
    assert scan_body["tool"] == "api-scan"
    assert scan_body["target_id"] == target_id
    assert scan_body["branch"] == "main"
    assert scan_body["status"] == "completed"
    assert scan_body["findings_count"] == 3


def test_get_latest_api_scan_workspace_scoped(client, engine):
    """Issue #57-style IDOR check: a viewer with no membership in this
    target's workspace must not see its scan state (404, not leaking
    existence)."""
    client, uid = _login(client, engine, role=UserRole.USER)
    target_id = _make_target(engine)
    # Deliberately no WorkspaceMembership created for this user.

    resp = client.get(f"/api/api-scan/{target_id}/latest")
    assert resp.status_code == 404


def test_get_latest_api_scan_returns_none_when_never_run(client, engine):
    client, uid = _login(client, engine)
    target_id = _make_target(engine)
    with Session(engine) as session:
        _join_workspace(engine, uid, session.get(Target, target_id).workspace_id, role=WorkspaceRole.VIEWER)

    resp = client.get(f"/api/api-scan/{target_id}/latest")
    assert resp.status_code == 200
    assert resp.json()["scan"] is None


def test_api_scan_end_to_end_eager_creates_findings(engine, monkeypatch):
    """Full dispatch -> Celery task -> ingest_findings path, with only the
    actual subprocess boundary (runner.run_nuclei) faked out -- everything
    else (DB writes, dedup, Scan/Finding rows) is real."""
    celery_app.conf.task_always_eager = True
    try:
        target_id = _make_target(engine)
        _add_endpoint(engine, target_id, "/admin")

        canned_nuclei_output = [
            {
                "template-id": "exposed-admin-panel",
                "info": {"name": "Exposed Admin Panel", "severity": "high", "description": "desc"},
                "matched-at": "https://api.example.com/admin",
            }
        ]
        monkeypatch.setattr(api_scan_tasks.runner, "run_nuclei", lambda urls: canned_nuclei_output)

        import app.core.db as db_module

        monkeypatch.setattr(db_module, "engine", engine)
        monkeypatch.setattr(api_scan_tasks, "engine", engine)

        with Session(engine) as session:
            target = session.get(Target, target_id)
            scan = Scan(target_id=target_id, tool="api-scan", branch=target.default_branch, status="running")
            session.add(scan)
            session.commit()
            session.refresh(scan)
            scan_id = scan.id

        result = api_scan_tasks.run_api_scan.apply(kwargs={"target_id": target_id, "scan_id": scan_id}).get()
        assert result["ingested"] == 1

        with Session(engine) as session:
            scan = session.get(Scan, scan_id)
            assert scan.status == "completed"
            findings = session.exec(select(Finding).where(Finding.tool == "api-scan")).all()
            assert len(findings) == 1
            assert findings[0].rule_id == "exposed-admin-panel"
            assert findings[0].file_path == "https://api.example.com/admin"
    finally:
        celery_app.conf.task_always_eager = False
