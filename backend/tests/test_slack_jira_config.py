"""Tests for issue #74 (Slack webhook + Jira API config, test-connection
endpoints, and Jira auto-ticket-creation on ingestion).

Follows the same TestClient + in-memory SQLite harness + httpx-mock pattern
established in tests/test_ai.py for the OpenAI-compatible provider (#67).
These tests verify OUR request-building/response-parsing/dispatch logic
against a mocked HTTP layer -- there's no real Slack workspace or Jira
instance available in this sandbox (see test_live_http_roundtrip.py for a
"real HTTP call against a server we control" style check, mirroring #67's
local OpenAI-compatible server verification).
"""
import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.crypto import encrypt_secret
from app.core.security import create_session_token, hash_password
from app.core.ingestion import ingest_findings
from app.models.models import (
    Finding,
    Organization,
    PlatformConfig,
    Scan,
    Severity,
    Target,
    User,
    UserRole,
    Workspace,
)


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    return eng


@pytest.fixture()
def client(engine):
    from app.main import app

    def override_get_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    original_deps_engine = deps_module.engine
    deps_module.engine = engine

    c = TestClient(app)
    _login(c, engine)
    yield c
    app.dependency_overrides.clear()
    deps_module.engine = original_deps_engine


def _login(client, engine, email="user@example.com", password="whatever123"):
    with Session(engine) as session:
        user = User(email=email, name="Test User", password_hash=hash_password(password), role=UserRole.ADMIN)
        session.add(user)
        session.commit()
        session.refresh(user)
        token = create_session_token(user.id)
    client.cookies.set("rikugan_session", token)
    return client


def _set_config(engine, **kwargs) -> None:
    with Session(engine) as session:
        config = PlatformConfig(**kwargs)
        session.add(config)
        session.commit()


def _make_target(engine) -> int:
    with Session(engine) as session:
        org = Organization(name="Org")
        session.add(org)
        session.commit()
        session.refresh(org)

        workspace = Workspace(organization_id=org.id, name="WS", api_key="key-1")
        session.add(workspace)
        session.commit()
        session.refresh(workspace)

        target = Target(workspace_id=workspace.id, name="Target A", repo_url="https://github.com/a/b")
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


# ---------------------------------------------------------------------------
# /api/config: new fields round-trip, secrets encrypted, never echoed
# ---------------------------------------------------------------------------


def test_update_config_encrypts_slack_and_jira_secrets_and_never_echoes_them(client, engine):
    resp = client.post(
        "/api/config",
        json={
            "slack_webhook_url": "https://hooks.slack.com/services/T000/B000/xxxxxxxx",
            "jira_url": "https://yourorg.atlassian.net/",
            "jira_api_token": "super-secret-jira-token",
            "jira_project_key": "SEC",
            "jira_issue_type": "Bug",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["slack_webhook_url_set"] is True
    assert body["jira_url"] == "https://yourorg.atlassian.net"  # trailing slash stripped
    assert body["jira_api_token_set"] is True
    assert body["jira_project_key"] == "SEC"
    assert body["jira_issue_type"] == "Bug"
    assert "super-secret-jira-token" not in resp.text
    assert "hooks.slack.com" not in resp.text

    with Session(engine) as session:
        config = session.exec(select(PlatformConfig)).first()
        assert config.slack_webhook_url != "https://hooks.slack.com/services/T000/B000/xxxxxxxx"
        assert config.jira_api_token != "super-secret-jira-token"

    get_resp = client.get("/api/config")
    assert "super-secret-jira-token" not in get_resp.text
    assert "hooks.slack.com" not in get_resp.text


def test_update_config_jira_auto_create_severity_round_trips_and_validates(client, engine):
    resp = client.post("/api/config", json={"jira_auto_create_severity": "Critical"})
    assert resp.status_code == 200
    assert resp.json()["jira_auto_create_severity"] == "Critical"

    resp = client.post("/api/config", json={"jira_auto_create_severity": "not-a-severity"})
    assert resp.status_code == 400

    resp = client.post("/api/config", json={"jira_auto_create_severity": ""})
    assert resp.status_code == 200
    assert resp.json()["jira_auto_create_severity"] is None


def test_get_config_defaults_when_no_row(client):
    resp = client.get("/api/config")
    body = resp.json()
    assert body["slack_webhook_url_set"] is False
    assert body["jira_url"] == ""
    assert body["jira_api_token_set"] is False
    assert body["jira_issue_type"] == "Task"
    assert body["jira_auto_create_severity"] is None


# ---------------------------------------------------------------------------
# POST /api/config/test-slack: real webhook payload shape, real response check
# ---------------------------------------------------------------------------


def test_test_slack_sends_expected_payload_and_reports_success(client, engine, monkeypatch):
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        return httpx.Response(200, text="ok", request=httpx.Request("POST", url))

    monkeypatch.setattr("app.core.slack_integration.httpx.post", fake_post)

    resp = client.post("/api/config/test-slack", json={"webhook_url": "https://hooks.slack.com/services/T/B/X"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert captured["url"] == "https://hooks.slack.com/services/T/B/X"
    assert "text" in captured["json"]
    assert isinstance(captured["json"]["text"], str)


def test_test_slack_uses_saved_webhook_when_none_supplied(client, engine, monkeypatch):
    _set_config(engine, slack_webhook_url=encrypt_secret("https://hooks.slack.com/services/SAVED"))

    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        return httpx.Response(200, text="ok", request=httpx.Request("POST", url))

    monkeypatch.setattr("app.core.slack_integration.httpx.post", fake_post)

    resp = client.post("/api/config/test-slack", json={})
    assert resp.status_code == 200
    assert captured["url"] == "https://hooks.slack.com/services/SAVED"


def test_test_slack_returns_400_with_no_webhook_configured(client, engine):
    resp = client.post("/api/config/test-slack", json={})
    assert resp.status_code == 400


def test_test_slack_surfaces_real_error_response(client, engine, monkeypatch):
    def fake_post(url, json=None, timeout=None):
        return httpx.Response(404, text="channel_not_found", request=httpx.Request("POST", url))

    monkeypatch.setattr("app.core.slack_integration.httpx.post", fake_post)

    resp = client.post("/api/config/test-slack", json={"webhook_url": "https://hooks.slack.com/services/BAD"})
    assert resp.status_code == 502
    assert "channel_not_found" in resp.json()["detail"]


def test_test_slack_surfaces_connection_error(client, engine, monkeypatch):
    def fake_post(url, json=None, timeout=None):
        raise httpx.ConnectError("connection refused", request=httpx.Request("POST", url))

    monkeypatch.setattr("app.core.slack_integration.httpx.post", fake_post)

    resp = client.post("/api/config/test-slack", json={"webhook_url": "https://hooks.slack.com/services/DOWN"})
    assert resp.status_code == 502


# ---------------------------------------------------------------------------
# POST /api/config/test-jira: real auth header + endpoint shape, real response check
# ---------------------------------------------------------------------------


def test_test_jira_calls_myself_endpoint_with_bearer_auth(client, engine, monkeypatch):
    captured = {}

    def fake_get(url, headers=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        return httpx.Response(200, json={"displayName": "Jira Bot"}, request=httpx.Request("GET", url))

    monkeypatch.setattr("app.core.jira_integration.httpx.get", fake_get)

    resp = client.post(
        "/api/config/test-jira",
        json={"jira_url": "https://yourorg.atlassian.net", "jira_api_token": "tok-123"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert "Jira Bot" in body["message"]
    assert captured["url"] == "https://yourorg.atlassian.net/rest/api/2/myself"
    assert captured["headers"]["Authorization"] == "Bearer tok-123"


def test_test_jira_uses_saved_config_when_none_supplied(client, engine, monkeypatch):
    _set_config(engine, jira_url="https://saved.atlassian.net", jira_api_token=encrypt_secret("saved-token"))

    captured = {}

    def fake_get(url, headers=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        return httpx.Response(200, json={"displayName": "Saved User"}, request=httpx.Request("GET", url))

    monkeypatch.setattr("app.core.jira_integration.httpx.get", fake_get)

    resp = client.post("/api/config/test-jira", json={})
    assert resp.status_code == 200
    assert captured["url"] == "https://saved.atlassian.net/rest/api/2/myself"
    assert captured["headers"]["Authorization"] == "Bearer saved-token"


def test_test_jira_returns_400_with_nothing_configured(client, engine):
    resp = client.post("/api/config/test-jira", json={})
    assert resp.status_code == 400


def test_test_jira_surfaces_real_auth_failure(client, engine, monkeypatch):
    def fake_get(url, headers=None, timeout=None):
        return httpx.Response(401, text='{"errorMessages":["Client must be authenticated"]}', request=httpx.Request("GET", url))

    monkeypatch.setattr("app.core.jira_integration.httpx.get", fake_get)

    resp = client.post(
        "/api/config/test-jira",
        json={"jira_url": "https://yourorg.atlassian.net", "jira_api_token": "bad-token"},
    )
    assert resp.status_code == 502
    assert "401" in resp.json()["detail"]


def test_test_jira_surfaces_connection_error(client, engine, monkeypatch):
    def fake_get(url, headers=None, timeout=None):
        raise httpx.ConnectError("connection refused", request=httpx.Request("GET", url))

    monkeypatch.setattr("app.core.jira_integration.httpx.get", fake_get)

    resp = client.post(
        "/api/config/test-jira",
        json={"jira_url": "https://unreachable.example", "jira_api_token": "tok"},
    )
    assert resp.status_code == 502


# ---------------------------------------------------------------------------
# Jira auto-ticket-creation on ingestion (issue #74 v1: severity threshold)
# ---------------------------------------------------------------------------


def _parsed_finding(rule_id="rule-1", severity=Severity.CRITICAL, title="Test finding"):
    return {
        "rule_id": rule_id,
        "title": title,
        "description": "desc",
        "file_path": "app.py",
        "line_start": 1,
        "line_end": 1,
        "severity": severity,
        "cve_id": None,
        "snippet": "snippet",
    }


def test_ingestion_auto_creates_jira_ticket_when_severity_meets_threshold(engine, monkeypatch):
    _set_config(
        engine,
        jira_url="https://yourorg.atlassian.net",
        jira_api_token=encrypt_secret("tok-123"),
        jira_project_key="SEC",
        jira_issue_type="Bug",
        jira_auto_create_severity="High",
    )
    target_id = _make_target(engine)

    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        return httpx.Response(201, json={"key": "SEC-42"}, request=httpx.Request("POST", url))

    monkeypatch.setattr("app.core.jira_integration.httpx.post", fake_post)

    with Session(engine) as session:
        target = session.get(Target, target_id)
        scan = Scan(target_id=target_id, tool="semgrep", branch="main")
        session.add(scan)
        session.commit()
        session.refresh(scan)

        ingest_findings(session, target, scan, "semgrep", "main", [_parsed_finding(severity=Severity.CRITICAL)])

    assert captured["url"] == "https://yourorg.atlassian.net/rest/api/2/issue"
    assert captured["json"]["fields"]["project"]["key"] == "SEC"
    assert captured["json"]["fields"]["issuetype"]["name"] == "Bug"
    assert "Critical" in captured["json"]["fields"]["summary"]
    assert captured["headers"]["Authorization"] == "Bearer tok-123"


def test_ingestion_skips_jira_ticket_when_below_threshold(engine, monkeypatch):
    _set_config(
        engine,
        jira_url="https://yourorg.atlassian.net",
        jira_api_token=encrypt_secret("tok-123"),
        jira_project_key="SEC",
        jira_auto_create_severity="Critical",
    )
    target_id = _make_target(engine)

    called = {"count": 0}

    def fake_post(url, json=None, headers=None, timeout=None):
        called["count"] += 1
        return httpx.Response(201, json={"key": "SEC-1"}, request=httpx.Request("POST", url))

    monkeypatch.setattr("app.core.jira_integration.httpx.post", fake_post)

    with Session(engine) as session:
        target = session.get(Target, target_id)
        scan = Scan(target_id=target_id, tool="semgrep", branch="main")
        session.add(scan)
        session.commit()
        session.refresh(scan)

        ingest_findings(session, target, scan, "semgrep", "main", [_parsed_finding(severity=Severity.MEDIUM)])

    assert called["count"] == 0


def test_ingestion_skips_jira_ticket_when_auto_create_disabled(engine, monkeypatch):
    _set_config(
        engine,
        jira_url="https://yourorg.atlassian.net",
        jira_api_token=encrypt_secret("tok-123"),
        jira_project_key="SEC",
        jira_auto_create_severity=None,
    )
    target_id = _make_target(engine)

    called = {"count": 0}

    def fake_post(url, json=None, headers=None, timeout=None):
        called["count"] += 1
        return httpx.Response(201, json={"key": "SEC-1"}, request=httpx.Request("POST", url))

    monkeypatch.setattr("app.core.jira_integration.httpx.post", fake_post)

    with Session(engine) as session:
        target = session.get(Target, target_id)
        scan = Scan(target_id=target_id, tool="semgrep", branch="main")
        session.add(scan)
        session.commit()
        session.refresh(scan)

        ingest_findings(session, target, scan, "semgrep", "main", [_parsed_finding(severity=Severity.CRITICAL)])

    assert called["count"] == 0


def test_ingestion_does_not_recreate_ticket_for_existing_finding_rescan(engine, monkeypatch):
    """Only net-new findings trigger auto-create -- a rescan that just bumps
    last_seen on an already-existing finding must not fire another ticket."""
    _set_config(
        engine,
        jira_url="https://yourorg.atlassian.net",
        jira_api_token=encrypt_secret("tok-123"),
        jira_project_key="SEC",
        jira_auto_create_severity="Critical",
    )
    target_id = _make_target(engine)

    called = {"count": 0}

    def fake_post(url, json=None, headers=None, timeout=None):
        called["count"] += 1
        return httpx.Response(201, json={"key": "SEC-1"}, request=httpx.Request("POST", url))

    monkeypatch.setattr("app.core.jira_integration.httpx.post", fake_post)

    with Session(engine) as session:
        target = session.get(Target, target_id)
        scan1 = Scan(target_id=target_id, tool="semgrep", branch="main")
        session.add(scan1)
        session.commit()
        session.refresh(scan1)
        ingest_findings(session, target, scan1, "semgrep", "main", [_parsed_finding(severity=Severity.CRITICAL)])

    assert called["count"] == 1

    with Session(engine) as session:
        target = session.get(Target, target_id)
        scan2 = Scan(target_id=target_id, tool="semgrep", branch="main")
        session.add(scan2)
        session.commit()
        session.refresh(scan2)
        # Same finding reappears (same rule_id/file_path/tool -> same dedup hash)
        ingest_findings(session, target, scan2, "semgrep", "main", [_parsed_finding(severity=Severity.CRITICAL)])

    assert called["count"] == 1  # still just the first call


def test_ingestion_jira_failure_does_not_break_ingestion(engine, monkeypatch):
    """A Jira outage/misconfiguration must not fail the scan/ingestion --
    best-effort per app.core.ingestion._maybe_auto_create_jira_ticket."""
    _set_config(
        engine,
        jira_url="https://yourorg.atlassian.net",
        jira_api_token=encrypt_secret("tok-123"),
        jira_project_key="SEC",
        jira_auto_create_severity="Critical",
    )
    target_id = _make_target(engine)

    def fake_post(url, json=None, headers=None, timeout=None):
        raise httpx.ConnectError("connection refused", request=httpx.Request("POST", url))

    monkeypatch.setattr("app.core.jira_integration.httpx.post", fake_post)

    with Session(engine) as session:
        target = session.get(Target, target_id)
        scan = Scan(target_id=target_id, tool="semgrep", branch="main")
        session.add(scan)
        session.commit()
        session.refresh(scan)

        count = ingest_findings(session, target, scan, "semgrep", "main", [_parsed_finding(severity=Severity.CRITICAL)])

    assert count == 1
    with Session(engine) as session:
        finding = session.exec(select(Finding)).first()
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
