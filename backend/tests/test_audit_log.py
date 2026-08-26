"""Tests for GET /api/audit/log (filters, real pagination) and the
bulk-triage batch-grouping mechanism (issue #123): a single bulk-triage call
over N findings should collapse into one grouped feed item instead of N
near-identical rows.

Same in-memory SQLite + dependency_override pattern as tests/test_findings.py.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.core.time import utcnow
from app.main import app
from app.models.models import Finding, FindingState, FindingStateLog, Organization, Scan, Severity, Target, User, Workspace


@pytest.fixture()
def engine():
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(eng)
    return eng


@pytest.fixture()
def client(engine):
    def override_get_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session

    original_deps_engine = deps_module.engine
    deps_module.engine = engine

    c = TestClient(app)
    yield c
    app.dependency_overrides.clear()
    deps_module.engine = original_deps_engine


def _login(client, engine, email="user@example.com", password="whatever123"):
    with Session(engine) as session:
        user = User(email=email, name="Test User", password_hash=hash_password(password))
        session.add(user)
        session.commit()
        session.refresh(user)
        token = create_session_token(user.id)
    client.cookies.set("toleman_session", token)
    return client


def _make_target(engine, name="Target A") -> int:
    with Session(engine) as session:
        org = Organization(name="Org")
        session.add(org)
        session.commit()
        session.refresh(org)

        workspace = Workspace(organization_id=org.id, name="WS", api_key=f"key-{name}")
        session.add(workspace)
        session.commit()
        session.refresh(workspace)

        target = Target(workspace_id=workspace.id, name=name, repo_url="https://example.com/repo.git")
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


def _make_finding(engine, target_id, **overrides) -> int:
    defaults = dict(
        target_id=target_id,
        dedup_hash=f"hash-{overrides.get('title', 'x')}-{overrides.get('rule_id', 'r')}",
        tool="semgrep",
        rule_id="rule-1",
        title="SQL Injection",
        file_path="app/main.py",
        severity=Severity.HIGH,
        priority_score=50,
        state=FindingState.OPEN,
    )
    defaults.update(overrides)
    with Session(engine) as session:
        finding = Finding(**defaults)
        session.add(finding)
        session.commit()
        session.refresh(finding)
        return finding.id


def test_bulk_triage_groups_into_one_audit_log_entry(client, engine):
    """The core #123 data-layer fix: a bulk-triage call over N findings must
    surface as one feed item with grouped_count == N, not N separate rows."""
    _login(client, engine)
    target_id = _make_target(engine)
    ids = [_make_finding(engine, target_id, title=f"Finding {i}", rule_id=f"r{i}") for i in range(30)]

    resp = client.post(
        "/api/findings/bulk-triage",
        json={"finding_ids": ids, "to_state": "Mitigated", "reason": "stale on rescan", "actor": "alice"},
    )
    assert resp.status_code == 200
    assert resp.json()["updated"] == 30

    log_resp = client.get("/api/audit/log")
    body = log_resp.json()
    triage_events = [e for e in body["items"] if e["type"] == "triage"]
    assert len(triage_events) == 1
    event = triage_events[0]
    assert event["grouped_count"] == 30
    assert event["actor"] == "alice"
    assert len(event["expand"]) == 30
    assert "30 findings" in event["summary"]

    # the 30 individual FindingStateLog rows still exist underneath (per-finding
    # history like GET /api/findings/{id}/history must keep working unmodified)
    with Session(engine) as session:
        from sqlmodel import select
        logs = session.exec(select(FindingStateLog)).all()
        assert len(logs) == 30
        batch_ids = {l.batch_id for l in logs}
        assert len(batch_ids) == 1
        assert None not in batch_ids


def test_single_triage_is_not_grouped(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id)

    resp = client.post(f"/api/findings/{finding_id}/triage", params={"to_state": "Accepted Risk"})
    assert resp.status_code == 200

    log_resp = client.get("/api/audit/log")
    triage_events = [e for e in log_resp.json()["items"] if e["type"] == "triage"]
    assert len(triage_events) == 1
    assert triage_events[0]["grouped_count"] == 1
    assert triage_events[0]["expand"] is None


def test_bulk_triage_of_single_finding_is_not_grouped(client, engine):
    """A 'batch' of exactly one finding is just a normal triage; it
    shouldn't render as a collapsible group of one."""
    _login(client, engine)
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id)

    resp = client.post(
        "/api/findings/bulk-triage",
        json={"finding_ids": [finding_id], "to_state": "Accepted Risk"},
    )
    assert resp.status_code == 200

    log_resp = client.get("/api/audit/log")
    triage_events = [e for e in log_resp.json()["items"] if e["type"] == "triage"]
    assert len(triage_events) == 1
    assert triage_events[0]["grouped_count"] == 1


def test_two_separate_bulk_actions_stay_separate_groups(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    batch_a = [_make_finding(engine, target_id, title=f"A{i}", rule_id=f"a{i}") for i in range(3)]
    batch_b = [_make_finding(engine, target_id, title=f"B{i}", rule_id=f"b{i}") for i in range(4)]

    client.post("/api/findings/bulk-triage", json={"finding_ids": batch_a, "to_state": "Accepted Risk"})
    client.post("/api/findings/bulk-triage", json={"finding_ids": batch_b, "to_state": "False Positive"})

    log_resp = client.get("/api/audit/log")
    triage_events = [e for e in log_resp.json()["items"] if e["type"] == "triage"]
    assert len(triage_events) == 2
    counts = sorted(e["grouped_count"] for e in triage_events)
    assert counts == [3, 4]


def test_filter_by_event_type(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id)
    client.post(f"/api/findings/{finding_id}/triage", params={"to_state": "Accepted Risk"})
    with Session(engine) as session:
        session.add(Scan(target_id=target_id, tool="semgrep", branch="main", status="completed", findings_count=1))
        session.commit()

    resp = client.get("/api/audit/log", params={"event_type": "scan"})
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["type"] == "scan"

    resp2 = client.get("/api/audit/log", params={"event_type": "triage"})
    body2 = resp2.json()
    assert body2["total"] == 1
    assert body2["items"][0]["type"] == "triage"


def test_filter_by_actor(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    f1 = _make_finding(engine, target_id, title="A", rule_id="r1")
    f2 = _make_finding(engine, target_id, title="B", rule_id="r2")
    client.post(f"/api/findings/{f1}/triage", params={"to_state": "Accepted Risk", "actor": "alice"})
    client.post(f"/api/findings/{f2}/triage", params={"to_state": "Accepted Risk", "actor": "bob"})

    resp = client.get("/api/audit/log", params={"actor": "alice"})
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["actor"] == "alice"


def test_actor_filter_excludes_scan_events_for_non_system_actor(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    with Session(engine) as session:
        session.add(Scan(target_id=target_id, tool="semgrep", branch="main", status="completed", findings_count=1))
        session.commit()

    resp = client.get("/api/audit/log", params={"actor": "alice"})
    assert resp.json()["total"] == 0

    resp2 = client.get("/api/audit/log", params={"actor": "system"})
    assert resp2.json()["total"] == 1


def test_pagination_reports_total_and_slices_items(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    for i in range(30):
        finding_id = _make_finding(engine, target_id, title=f"F{i}", rule_id=f"r{i}")
        client.post(f"/api/findings/{finding_id}/triage", params={"to_state": "Accepted Risk"})

    resp = client.get("/api/audit/log", params={"page": 1, "page_size": 10})
    body = resp.json()
    assert body["total"] == 30
    assert len(body["items"]) == 10

    resp2 = client.get("/api/audit/log", params={"page": 3, "page_size": 10})
    body2 = resp2.json()
    assert len(body2["items"]) == 10

    resp3 = client.get("/api/audit/log", params={"page": 4, "page_size": 10})
    assert resp3.json()["items"] == []


def test_default_page_size_is_25(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    for i in range(30):
        finding_id = _make_finding(engine, target_id, title=f"F{i}", rule_id=f"r{i}")
        client.post(f"/api/findings/{finding_id}/triage", params={"to_state": "Accepted Risk"})

    resp = client.get("/api/audit/log")
    body = resp.json()
    assert body["total"] == 30
    assert len(body["items"]) == 25


def test_date_range_filter(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id)
    client.post(f"/api/findings/{finding_id}/triage", params={"to_state": "Accepted Risk"})

    from datetime import UTC, datetime, timedelta
    tomorrow = (utcnow() + timedelta(days=1)).date().isoformat()
    yesterday = (utcnow() - timedelta(days=1)).date().isoformat()

    resp = client.get("/api/audit/log", params={"date_from": tomorrow})
    assert resp.json()["total"] == 0

    resp2 = client.get("/api/audit/log", params={"date_from": yesterday})
    assert resp2.json()["total"] == 1


def test_list_actors(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    f1 = _make_finding(engine, target_id, title="A", rule_id="r1")
    f2 = _make_finding(engine, target_id, title="B", rule_id="r2")
    client.post(f"/api/findings/{f1}/triage", params={"to_state": "Accepted Risk", "actor": "alice"})
    client.post(f"/api/findings/{f2}/triage", params={"to_state": "Accepted Risk", "actor": "bob"})

    resp = client.get("/api/audit/actors")
    assert resp.status_code == 200
    assert set(resp.json()) == {"alice", "bob"}
