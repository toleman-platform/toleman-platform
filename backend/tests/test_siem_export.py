"""Tests for issue #114 (SIEM export webhook, test-connection endpoint, and
auto-export on ingestion). Same TestClient + in-memory SQLite + httpx-mock
pattern as tests/test_slack_jira_config.py.
"""
import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.crypto import encrypt_secret
from app.core.ingestion import ingest_findings
from app.core.security import create_session_token, hash_password
from app.models.models import (
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


# ---------------------------------------------------------------------------
# /api/config: new fields round-trip, secrets encrypted, never echoed
# ---------------------------------------------------------------------------


def test_update_config_encrypts_siem_webhook_and_never_echoes_it(client):
    resp = client.post(
        "/api/config",
        json={"siem_webhook_url": "https://siem.example.com/ingest?token=secret123"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["siem_webhook_url_set"] is True
    assert "secret123" not in resp.text

    get_resp = client.get("/api/config")
    assert "secret123" not in get_resp.text


def test_update_config_siem_export_severity_round_trips_and_validates(client):
    resp = client.post("/api/config", json={"siem_export_severity": "High"})
    assert resp.status_code == 200
    assert resp.json()["siem_export_severity"] == "High"

    resp = client.post("/api/config", json={"siem_export_severity": "not-a-severity"})
    assert resp.status_code == 400

    resp = client.post("/api/config", json={"siem_export_severity": ""})
    assert resp.status_code == 200
    assert resp.json()["siem_export_severity"] is None


def test_get_config_defaults_when_no_row(client):
    resp = client.get("/api/config")
    body = resp.json()
    assert body["siem_webhook_url_set"] is False
    assert body["siem_export_severity"] is None


# ---------------------------------------------------------------------------
# POST /api/config/test-siem
# ---------------------------------------------------------------------------


def test_test_siem_sends_expected_payload_and_reports_success(client, monkeypatch):
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        return httpx.Response(200, text="ok", request=httpx.Request("POST", url))

    monkeypatch.setattr("app.core.siem_export.httpx.post", fake_post)

    resp = client.post("/api/config/test-siem", json={"webhook_url": "https://siem.example.com/ingest"})
    assert resp.status_code == 200
    assert resp.json()["success"] is True
    assert captured["url"] == "https://siem.example.com/ingest"
    assert captured["json"]["event_type"] == "test_connection"
    assert captured["json"]["source"] == "rikugan"


def test_test_siem_uses_saved_webhook_when_none_supplied(client, engine, monkeypatch):
    _set_config(engine, siem_webhook_url=encrypt_secret("https://siem.example.com/saved"))

    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        return httpx.Response(200, text="ok", request=httpx.Request("POST", url))

    monkeypatch.setattr("app.core.siem_export.httpx.post", fake_post)

    resp = client.post("/api/config/test-siem", json={})
    assert resp.status_code == 200
    assert captured["url"] == "https://siem.example.com/saved"


def test_test_siem_returns_400_with_no_webhook_configured(client):
    resp = client.post("/api/config/test-siem", json={})
    assert resp.status_code == 400


def test_test_siem_surfaces_real_error_response(client, monkeypatch):
    def fake_post(url, json=None, timeout=None):
        return httpx.Response(500, text="internal error", request=httpx.Request("POST", url))

    monkeypatch.setattr("app.core.siem_export.httpx.post", fake_post)

    resp = client.post("/api/config/test-siem", json={"webhook_url": "https://siem.example.com/bad"})
    assert resp.status_code == 502
    assert "internal error" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# SIEM export on ingestion (issue #114: severity threshold)
# ---------------------------------------------------------------------------


def test_ingestion_exports_to_siem_when_severity_meets_threshold(engine, monkeypatch):
    _set_config(
        engine,
        siem_webhook_url=encrypt_secret("https://siem.example.com/ingest"),
        siem_export_severity="High",
    )
    target_id = _make_target(engine)

    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        return httpx.Response(200, text="ok", request=httpx.Request("POST", url))

    monkeypatch.setattr("app.core.siem_export.httpx.post", fake_post)

    with Session(engine) as session:
        target = session.get(Target, target_id)
        scan = Scan(target_id=target_id, tool="semgrep", branch="main")
        session.add(scan)
        session.commit()
        session.refresh(scan)

        ingest_findings(session, target, scan, "semgrep", "main", [_parsed_finding(severity=Severity.CRITICAL)])

    assert captured["url"] == "https://siem.example.com/ingest"
    assert captured["json"]["source"] == "rikugan"
    assert captured["json"]["event_type"] == "finding"
    assert captured["json"]["severity"] == "Critical"
    assert captured["json"]["target_name"] == "Target A"


def test_ingestion_skips_siem_export_when_below_threshold(engine, monkeypatch):
    _set_config(
        engine,
        siem_webhook_url=encrypt_secret("https://siem.example.com/ingest"),
        siem_export_severity="Critical",
    )
    target_id = _make_target(engine)

    called = {"count": 0}

    def fake_post(url, json=None, timeout=None):
        called["count"] += 1
        return httpx.Response(200, text="ok", request=httpx.Request("POST", url))

    monkeypatch.setattr("app.core.siem_export.httpx.post", fake_post)

    with Session(engine) as session:
        target = session.get(Target, target_id)
        scan = Scan(target_id=target_id, tool="semgrep", branch="main")
        session.add(scan)
        session.commit()
        session.refresh(scan)

        ingest_findings(session, target, scan, "semgrep", "main", [_parsed_finding(severity=Severity.MEDIUM)])

    assert called["count"] == 0


def test_ingestion_skips_siem_export_when_disabled(engine, monkeypatch):
    _set_config(
        engine,
        siem_webhook_url=encrypt_secret("https://siem.example.com/ingest"),
        siem_export_severity=None,
    )
    target_id = _make_target(engine)

    called = {"count": 0}

    def fake_post(url, json=None, timeout=None):
        called["count"] += 1
        return httpx.Response(200, text="ok", request=httpx.Request("POST", url))

    monkeypatch.setattr("app.core.siem_export.httpx.post", fake_post)

    with Session(engine) as session:
        target = session.get(Target, target_id)
        scan = Scan(target_id=target_id, tool="semgrep", branch="main")
        session.add(scan)
        session.commit()
        session.refresh(scan)

        ingest_findings(session, target, scan, "semgrep", "main", [_parsed_finding(severity=Severity.CRITICAL)])

    assert called["count"] == 0


def test_ingestion_skips_siem_export_when_no_webhook_configured(engine, monkeypatch):
    _set_config(engine, siem_export_severity="Critical")
    target_id = _make_target(engine)

    called = {"count": 0}

    def fake_post(url, json=None, timeout=None):
        called["count"] += 1
        return httpx.Response(200, text="ok", request=httpx.Request("POST", url))

    monkeypatch.setattr("app.core.siem_export.httpx.post", fake_post)

    with Session(engine) as session:
        target = session.get(Target, target_id)
        scan = Scan(target_id=target_id, tool="semgrep", branch="main")
        session.add(scan)
        session.commit()
        session.refresh(scan)

        ingest_findings(session, target, scan, "semgrep", "main", [_parsed_finding(severity=Severity.CRITICAL)])

    assert called["count"] == 0


def test_ingestion_siem_failure_does_not_break_ingestion(engine, monkeypatch):
    """A SIEM webhook outage must not fail the scan/ingestion -- best-effort
    per app.core.ingestion._maybe_export_to_siem."""
    _set_config(
        engine,
        siem_webhook_url=encrypt_secret("https://siem.example.com/ingest"),
        siem_export_severity="Critical",
    )
    target_id = _make_target(engine)

    def fake_post(url, json=None, timeout=None):
        raise httpx.ConnectError("connection refused", request=httpx.Request("POST", url))

    monkeypatch.setattr("app.core.siem_export.httpx.post", fake_post)

    with Session(engine) as session:
        target = session.get(Target, target_id)
        scan = Scan(target_id=target_id, tool="semgrep", branch="main")
        session.add(scan)
        session.commit()
        session.refresh(scan)

        count = ingest_findings(session, target, scan, "semgrep", "main", [_parsed_finding(severity=Severity.CRITICAL)])

    assert count == 1


def test_ingestion_does_not_reexport_existing_finding_on_rescan(engine, monkeypatch):
    """Only net-new findings trigger export -- a rescan that just bumps
    last_seen on an already-existing finding must not fire another event."""
    _set_config(
        engine,
        siem_webhook_url=encrypt_secret("https://siem.example.com/ingest"),
        siem_export_severity="Critical",
    )
    target_id = _make_target(engine)

    called = {"count": 0}

    def fake_post(url, json=None, timeout=None):
        called["count"] += 1
        return httpx.Response(200, text="ok", request=httpx.Request("POST", url))

    monkeypatch.setattr("app.core.siem_export.httpx.post", fake_post)

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
        ingest_findings(session, target, scan2, "semgrep", "main", [_parsed_finding(severity=Severity.CRITICAL)])

    assert called["count"] == 1  # still just the first call
