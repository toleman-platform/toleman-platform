"""Tests for GET /api/search -- requires auth, matches findings/targets by
substring across the fields listed in the Sprint 3 roadmap item (title/
file_path/rule_id/cve_id for findings; name/repo_url for targets).

Follows the same TestClient + in-memory SQLite harness pattern established in
tests/test_rate_limit.py (no shared conftest exists yet in this repo).
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import Finding, Organization, Target, User, Workspace


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

    # Skip lifespan (see test_rate_limit.py) -- we only want the overridden
    # in-memory SQLite session, not a connection to the real Postgres engine.
    c = TestClient(app)
    yield c
    app.dependency_overrides.clear()
    deps_module.engine = original_deps_engine


def _make_user(engine, email="user@example.com", password="correct-horse") -> User:
    with Session(engine) as session:
        user = User(email=email, name="Test User", password_hash=hash_password(password))
        session.add(user)
        session.commit()
        session.refresh(user)
        return user


def _authed_client(client, engine) -> TestClient:
    user = _make_user(engine)
    token = create_session_token(user.id, user.token_version)
    client.cookies.set("rikugan_session", token)
    return client


def _seed(engine):
    with Session(engine) as session:
        org = Organization(name="Test Org")
        session.add(org)
        session.commit()
        session.refresh(org)

        workspace = Workspace(organization_id=org.id, name="Test WS", api_key="test-ws-key")
        session.add(workspace)
        session.commit()
        session.refresh(workspace)

        target = Target(
            workspace_id=workspace.id,
            name="payments-service",
            repo_url="https://github.com/acme/payments-service",
        )
        other_target = Target(
            workspace_id=workspace.id,
            name="unrelated-repo",
            repo_url="https://github.com/acme/unrelated-repo",
        )
        session.add(target)
        session.add(other_target)
        session.commit()
        session.refresh(target)

        finding = Finding(
            target_id=target.id,
            dedup_hash="hash-1",
            tool="semgrep",
            rule_id="sql-injection-risk",
            title="Possible SQL Injection",
            file_path="app/db/queries.py",
            severity="High",
            cve_id="CVE-2023-9999",
        )
        other_finding = Finding(
            target_id=target.id,
            dedup_hash="hash-2",
            tool="semgrep",
            rule_id="hardcoded-secret",
            title="Hardcoded API key",
            file_path="app/config.py",
            severity="Medium",
        )
        session.add(finding)
        session.add(other_finding)
        session.commit()

        return target.id


def test_search_requires_auth(client, engine):
    _seed(engine)
    resp = client.get("/api/search", params={"q": "payments"})
    assert resp.status_code == 401


def test_search_matches_target_by_name(client, engine):
    _seed(engine)
    _authed_client(client, engine)
    resp = client.get("/api/search", params={"q": "payments"})
    assert resp.status_code == 200
    body = resp.json()
    assert any(t["name"] == "payments-service" for t in body["targets"])
    assert not any(t["name"] == "unrelated-repo" for t in body["targets"])


def test_search_matches_target_by_repo_url(client, engine):
    _seed(engine)
    _authed_client(client, engine)
    resp = client.get("/api/search", params={"q": "acme/payments"})
    body = resp.json()
    assert any(t["repo_url"].endswith("payments-service") for t in body["targets"])


def test_search_matches_finding_by_title(client, engine):
    _seed(engine)
    _authed_client(client, engine)
    resp = client.get("/api/search", params={"q": "SQL Injection"})
    body = resp.json()
    assert any(f["title"] == "Possible SQL Injection" for f in body["findings"])
    assert not any(f["title"] == "Hardcoded API key" for f in body["findings"])


def test_search_matches_finding_by_file_path(client, engine):
    _seed(engine)
    _authed_client(client, engine)
    resp = client.get("/api/search", params={"q": "queries.py"})
    body = resp.json()
    assert any(f["file_path"] == "app/db/queries.py" for f in body["findings"])


def test_search_matches_finding_by_rule_id(client, engine):
    _seed(engine)
    _authed_client(client, engine)
    resp = client.get("/api/search", params={"q": "hardcoded-secret"})
    body = resp.json()
    assert any(f["rule_id"] == "hardcoded-secret" for f in body["findings"])


def test_search_matches_finding_by_cve_id(client, engine):
    _seed(engine)
    _authed_client(client, engine)
    resp = client.get("/api/search", params={"q": "CVE-2023-9999"})
    body = resp.json()
    assert any(f["cve_id"] == "CVE-2023-9999" for f in body["findings"])


def test_search_empty_query_returns_empty_results(client, engine):
    _seed(engine)
    _authed_client(client, engine)
    resp = client.get("/api/search", params={"q": ""})
    assert resp.status_code == 200
    assert resp.json() == {"findings": [], "targets": []}


def test_search_no_matches_returns_empty_lists(client, engine):
    _seed(engine)
    _authed_client(client, engine)
    resp = client.get("/api/search", params={"q": "nonexistent-zzz"})
    body = resp.json()
    assert body["findings"] == []
    assert body["targets"] == []
