"""Tests for GET /api/findings (filtering, search, pagination) and the
bulk-triage endpoint.

Follows the same in-memory SQLite + dependency_override pattern used in
tests/test_rate_limit.py -- no shared conftest existed for this yet either,
so a scoped client/engine fixture pair lives here.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import Finding, FindingState, Organization, Severity, Target, User, Workspace


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
    client.cookies.set("rikugan_session", token)
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


def test_list_findings_returns_items_and_total(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    _make_finding(engine, target_id, title="A", rule_id="r1")
    _make_finding(engine, target_id, title="B", rule_id="r2")

    resp = client.get("/api/findings")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2
    assert len(body["items"]) == 2


def test_filter_by_severity(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    _make_finding(engine, target_id, title="Critical one", rule_id="r1", severity=Severity.CRITICAL)
    _make_finding(engine, target_id, title="Low one", rule_id="r2", severity=Severity.LOW)

    resp = client.get("/api/findings", params={"severity": "Critical"})
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["title"] == "Critical one"


def test_filter_by_tool(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    _make_finding(engine, target_id, title="Semgrep finding", rule_id="r1", tool="semgrep")
    _make_finding(engine, target_id, title="Trivy finding", rule_id="r2", tool="trivy")

    resp = client.get("/api/findings", params={"tool": "trivy"})
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["tool"] == "trivy"


def test_filter_by_state(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    _make_finding(engine, target_id, title="Open one", rule_id="r1", state=FindingState.OPEN)
    _make_finding(engine, target_id, title="Accepted one", rule_id="r2", state=FindingState.ACCEPTED_RISK)

    resp = client.get("/api/findings", params={"state": "Accepted Risk"})
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["title"] == "Accepted one"


def test_filter_by_target(client, engine):
    _login(client, engine)
    target_a = _make_target(engine, name="Target A")
    target_b = _make_target(engine, name="Target B")
    _make_finding(engine, target_a, title="In A", rule_id="r1")
    _make_finding(engine, target_b, title="In B", rule_id="r2")

    resp = client.get("/api/findings", params={"target_id": target_a})
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["title"] == "In A"


def test_search_matches_title(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    _make_finding(engine, target_id, title="Hardcoded secret found", rule_id="r1")
    _make_finding(engine, target_id, title="Unrelated finding", rule_id="r2")

    resp = client.get("/api/findings", params={"search": "secret"})
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["title"] == "Hardcoded secret found"


def test_search_matches_file_path(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    _make_finding(engine, target_id, title="A", rule_id="r1", file_path="src/auth/login.py")
    _make_finding(engine, target_id, title="B", rule_id="r2", file_path="src/other.py")

    resp = client.get("/api/findings", params={"search": "auth"})
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["file_path"] == "src/auth/login.py"


def test_search_matches_rule_id(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    _make_finding(engine, target_id, title="A", rule_id="python.sql-injection")
    _make_finding(engine, target_id, title="B", rule_id="python.xss")

    resp = client.get("/api/findings", params={"search": "sql-injection"})
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["rule_id"] == "python.sql-injection"


def test_pagination_limits_page_size_and_reports_total(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    for i in range(30):
        _make_finding(engine, target_id, title=f"Finding {i}", rule_id=f"r{i}", priority_score=i)

    resp = client.get("/api/findings", params={"page": 1, "page_size": 10})
    body = resp.json()
    assert body["total"] == 30
    assert len(body["items"]) == 10

    resp2 = client.get("/api/findings", params={"page": 2, "page_size": 10})
    body2 = resp2.json()
    assert len(body2["items"]) == 10
    assert {i["id"] for i in body2["items"]}.isdisjoint({i["id"] for i in body["items"]})

    resp3 = client.get("/api/findings", params={"page": 4, "page_size": 10})
    assert resp3.json()["items"] == []


def test_default_page_size_is_25(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    for i in range(30):
        _make_finding(engine, target_id, title=f"Finding {i}", rule_id=f"r{i}")

    resp = client.get("/api/findings")
    body = resp.json()
    assert body["total"] == 30
    assert len(body["items"]) == 25


def test_findings_ordered_by_priority_score_desc(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    _make_finding(engine, target_id, title="Low priority", rule_id="r1", priority_score=10)
    _make_finding(engine, target_id, title="High priority", rule_id="r2", priority_score=90)

    resp = client.get("/api/findings")
    items = resp.json()["items"]
    assert items[0]["title"] == "High priority"
    assert items[1]["title"] == "Low priority"


def test_bulk_triage_updates_all_findings_and_writes_audit_log(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    id_a = _make_finding(engine, target_id, title="A", rule_id="r1")
    id_b = _make_finding(engine, target_id, title="B", rule_id="r2")

    resp = client.post(
        "/api/findings/bulk-triage",
        json={"finding_ids": [id_a, id_b], "to_state": "Accepted Risk", "reason": "batch review"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["updated"] == 2

    with Session(engine) as session:
        finding_a = session.get(Finding, id_a)
        finding_b = session.get(Finding, id_b)
        assert finding_a.state == FindingState.ACCEPTED_RISK
        assert finding_b.state == FindingState.ACCEPTED_RISK

    from app.models.models import FindingStateLog

    with Session(engine) as session:
        from sqlmodel import select

        logs = session.exec(select(FindingStateLog)).all()
        assert len(logs) == 2
        assert all(log.reason == "batch review" for log in logs)
        assert all(log.to_state == FindingState.ACCEPTED_RISK for log in logs)


def test_bulk_triage_skips_missing_ids_without_error(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    id_a = _make_finding(engine, target_id, title="A", rule_id="r1")

    resp = client.post(
        "/api/findings/bulk-triage",
        json={"finding_ids": [id_a, 999999], "to_state": "False Positive", "reason": "n/a"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["updated"] == 1


def test_findings_endpoint_requires_login(client, engine):
    resp = client.get("/api/findings")
    assert resp.status_code == 401
