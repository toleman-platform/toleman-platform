"""Tests for /api/ai (provider dispatch: Anthropic vs. any OpenAI-compatible
endpoint -- Kimi/Moonshot, Ollama, vLLM, LM Studio, etc.) and /api/config's
handling of the new provider fields.

Follows the same TestClient + in-memory SQLite harness pattern established in
tests/test_rate_limit.py and tests/test_findings.py (no shared conftest exists
yet in this repo). The Anthropic SDK call and the openai_compatible httpx call
are both mocked here -- these tests verify OUR dispatch/request-building/
response-parsing logic, not that any real vendor endpoint works.
"""
import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.models.models import (
    AiAnalysisRun,
    Finding,
    Organization,
    PlatformConfig,
    Severity,
    Target,
    User,
    UserRole,
    Workspace,
    WorkspaceMembership,
    WorkspaceRole,
)


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
    # User.role defaults to UserRole.ADMIN (single-org/admin pattern, see
    # app/models/models.py), so this also satisfies config_api's admin-only gate.
    with Session(engine) as session:
        user = User(email=email, name="Test User", password_hash=hash_password(password), role=UserRole.ADMIN)
        session.add(user)
        session.commit()
        session.refresh(user)
        token = create_session_token(user.id)
    client.cookies.set("rikugan_session", token)
    return client


def _make_finding(engine) -> int:
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

        finding = Finding(
            target_id=target.id,
            dedup_hash="hash-1",
            tool="semgrep",
            rule_id="sql-injection",
            title="SQL Injection",
            description="Unsanitized input reaches a raw query.",
            file_path="app.py",
            line_start=42,
            severity=Severity.HIGH,
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)
        return finding.id


def _set_config(engine, **kwargs) -> None:
    with Session(engine) as session:
        config = PlatformConfig(**kwargs)
        session.add(config)
        session.commit()


# ---------------------------------------------------------------------------
# Missing config -> 400, no fabricated success
# ---------------------------------------------------------------------------


def test_analyze_returns_400_when_no_provider_configured(client, engine):
    finding_id = _make_finding(engine)
    resp = client.post(f"/api/ai/analyze/{finding_id}")
    assert resp.status_code == 400


def test_analyze_returns_404_for_missing_finding(client, engine):
    resp = client.post("/api/ai/analyze/99999")
    assert resp.status_code == 404


def test_analyze_openai_compatible_returns_400_when_base_url_or_model_missing(client, engine):
    finding_id = _make_finding(engine)
    _set_config(engine, ai_provider="openai_compatible", openai_compatible_base_url="", openai_compatible_model="")
    resp = client.post(f"/api/ai/analyze/{finding_id}")
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# /api/ai/status reports provider + configured
# ---------------------------------------------------------------------------


def test_status_reports_anthropic_provider_by_default(client, engine, monkeypatch):
    monkeypatch.setattr("app.api.ai.settings.anthropic_api_key", "")
    resp = client.get("/api/ai/status")
    assert resp.status_code == 200
    body = resp.json()
    assert body["provider"] == "anthropic"
    assert body["configured"] is False


def test_status_reports_openai_compatible_when_selected_and_configured(client, engine):
    _set_config(
        engine,
        ai_provider="openai_compatible",
        openai_compatible_base_url="http://localhost:11434/v1",
        openai_compatible_model="qwen2.5:0.5b",
    )
    resp = client.get("/api/ai/status")
    body = resp.json()
    assert body["provider"] == "openai_compatible"
    assert body["configured"] is True


# ---------------------------------------------------------------------------
# openai_compatible request-building / response-parsing (httpx mocked)
# ---------------------------------------------------------------------------


def test_analyze_openai_compatible_builds_expected_request_and_parses_response(client, engine, monkeypatch):
    finding_id = _make_finding(engine)
    _set_config(
        engine,
        ai_provider="openai_compatible",
        openai_compatible_base_url="http://localhost:11434/v1",
        openai_compatible_model="qwen2.5:0.5b",
        openai_compatible_api_key="",
    )

    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "Use parameterized queries."}}]},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr("app.api.ai.httpx.post", fake_post)

    resp = client.post(f"/api/ai/analyze/{finding_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"finding_id": finding_id, "analysis": "Use parameterized queries."}

    assert captured["url"] == "http://localhost:11434/v1/chat/completions"
    assert captured["json"]["model"] == "qwen2.5:0.5b"
    assert captured["json"]["messages"][0]["role"] == "user"
    assert "SQL Injection" in captured["json"]["messages"][0]["content"]
    # No key configured -- self-hosted backends (Ollama) typically need none.
    assert "Authorization" not in captured["headers"]


def test_analyze_openai_compatible_sends_bearer_auth_when_key_configured(client, engine, monkeypatch):
    finding_id = _make_finding(engine)
    from app.core.crypto import encrypt_secret

    _set_config(
        engine,
        ai_provider="openai_compatible",
        openai_compatible_base_url="https://api.moonshot.cn/v1",
        openai_compatible_model="kimi-k2",
        openai_compatible_api_key=encrypt_secret("sk-test-key-123"),
    )

    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["headers"] = headers
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "ok"}}]},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr("app.api.ai.httpx.post", fake_post)

    resp = client.post(f"/api/ai/analyze/{finding_id}")
    assert resp.status_code == 200
    assert captured["headers"]["Authorization"] == "Bearer sk-test-key-123"


def test_analyze_openai_compatible_surfaces_upstream_error_as_502(client, engine, monkeypatch):
    finding_id = _make_finding(engine)
    _set_config(
        engine,
        ai_provider="openai_compatible",
        openai_compatible_base_url="http://localhost:11434/v1",
        openai_compatible_model="qwen2.5:0.5b",
    )

    def fake_post(url, json=None, headers=None, timeout=None):
        request = httpx.Request("POST", url)
        response = httpx.Response(500, text="model not found", request=request)
        raise httpx.HTTPStatusError("server error", request=request, response=response)

    monkeypatch.setattr("app.api.ai.httpx.post", fake_post)

    resp = client.post(f"/api/ai/analyze/{finding_id}")
    assert resp.status_code == 502
    assert "model not found" in resp.json()["detail"]


def test_analyze_openai_compatible_surfaces_connection_error_as_502(client, engine, monkeypatch):
    finding_id = _make_finding(engine)
    _set_config(
        engine,
        ai_provider="openai_compatible",
        openai_compatible_base_url="http://localhost:11434/v1",
        openai_compatible_model="qwen2.5:0.5b",
    )

    def fake_post(url, json=None, headers=None, timeout=None):
        raise httpx.ConnectError("connection refused", request=httpx.Request("POST", url))

    monkeypatch.setattr("app.api.ai.httpx.post", fake_post)

    resp = client.post(f"/api/ai/analyze/{finding_id}")
    assert resp.status_code == 502


def test_analyze_openai_compatible_surfaces_bad_response_shape_as_502(client, engine, monkeypatch):
    finding_id = _make_finding(engine)
    _set_config(
        engine,
        ai_provider="openai_compatible",
        openai_compatible_base_url="http://localhost:11434/v1",
        openai_compatible_model="qwen2.5:0.5b",
    )

    def fake_post(url, json=None, headers=None, timeout=None):
        return httpx.Response(200, json={"unexpected": "shape"}, request=httpx.Request("POST", url))

    monkeypatch.setattr("app.api.ai.httpx.post", fake_post)

    resp = client.post(f"/api/ai/analyze/{finding_id}")
    assert resp.status_code == 502


# ---------------------------------------------------------------------------
# Anthropic path stays intact when selected (dispatch correctness)
# ---------------------------------------------------------------------------


def test_analyze_dispatches_to_anthropic_when_provider_is_anthropic(client, engine, monkeypatch):
    finding_id = _make_finding(engine)
    _set_config(engine, ai_provider="anthropic", anthropic_api_key="sk-ant-test")

    class FakeBlock:
        text = "Sanitize the input."

    class FakeResponse:
        content = [FakeBlock()]

    class FakeMessages:
        def create(self, **kwargs):
            assert kwargs["model"] == "claude-sonnet-4-5"
            assert kwargs["messages"][0]["role"] == "user"
            return FakeResponse()

    class FakeAnthropic:
        def __init__(self, api_key):
            self.messages = FakeMessages()

    monkeypatch.setattr("anthropic.Anthropic", FakeAnthropic)

    resp = client.post(f"/api/ai/analyze/{finding_id}")
    assert resp.status_code == 200
    assert resp.json() == {"finding_id": finding_id, "analysis": "Sanitize the input."}


# ---------------------------------------------------------------------------
# /api/config: new fields round-trip, key is encrypted at rest, never echoed
# ---------------------------------------------------------------------------


def test_update_config_encrypts_openai_compatible_key_and_never_echoes_it(client, engine):
    resp = client.post(
        "/api/config",
        json={
            "ai_provider": "openai_compatible",
            "openai_compatible_base_url": "http://localhost:11434/v1",
            "openai_compatible_api_key": "super-secret-key",
            "openai_compatible_model": "llama3.1",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ai_provider"] == "openai_compatible"
    assert body["openai_compatible_api_key_set"] is True
    assert "super-secret-key" not in resp.text

    with Session(engine) as session:
        config = session.exec(select(PlatformConfig)).first()
        assert config.openai_compatible_api_key != "super-secret-key"
        assert config.openai_compatible_api_key != ""

    get_resp = client.get("/api/config")
    assert "super-secret-key" not in get_resp.text
    assert get_resp.json()["openai_compatible_api_key_set"] is True


def test_update_config_partial_update_leaves_other_fields_unchanged(client, engine):
    client.post("/api/config", json={"anthropic_api_key": "sk-ant-abc"})
    resp = client.post("/api/config", json={"ai_provider": "openai_compatible"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ai_provider"] == "openai_compatible"
    assert body["anthropic_api_key_set"] is True  # untouched by the partial update


def test_update_config_rejects_unknown_provider(client, engine):
    resp = client.post("/api/config", json={"ai_provider": "not-a-real-provider"})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Issue #122: AI Analysis real entry point -- recent-analyses tracking +
# GET /api/ai/recent
# ---------------------------------------------------------------------------


def _make_finding_with_ids(engine, target_name="Target A") -> tuple[int, int, int]:
    """Same as _make_finding but also returns (target_id, workspace_id) for
    workspace-scoping tests."""
    with Session(engine) as session:
        org = Organization(name="Org")
        session.add(org)
        session.commit()
        session.refresh(org)

        workspace = Workspace(organization_id=org.id, name="WS", api_key=f"key-{target_name}")
        session.add(workspace)
        session.commit()
        session.refresh(workspace)

        target = Target(workspace_id=workspace.id, name=target_name, repo_url="https://github.com/a/b")
        session.add(target)
        session.commit()
        session.refresh(target)

        finding = Finding(
            target_id=target.id,
            dedup_hash=f"hash-{target_name}",
            tool="semgrep",
            rule_id="sql-injection",
            title="SQL Injection",
            description="Unsanitized input reaches a raw query.",
            file_path="app.py",
            line_start=42,
            severity=Severity.HIGH,
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)
        return finding.id, target.id, workspace.id


def test_successful_analyze_records_an_ai_analysis_run(client, engine, monkeypatch):
    finding_id = _make_finding(engine)
    _set_config(engine, ai_provider="anthropic", anthropic_api_key="sk-ant-test")

    class FakeBlock:
        text = "Sanitize the input."

    class FakeResponse:
        content = [FakeBlock()]

    class FakeMessages:
        def create(self, **kwargs):
            return FakeResponse()

    class FakeAnthropic:
        def __init__(self, api_key):
            self.messages = FakeMessages()

    monkeypatch.setattr("anthropic.Anthropic", FakeAnthropic)

    resp = client.post(f"/api/ai/analyze/{finding_id}")
    assert resp.status_code == 200

    with Session(engine) as session:
        runs = session.exec(select(AiAnalysisRun).where(AiAnalysisRun.finding_id == finding_id)).all()
        assert len(runs) == 1
        assert runs[0].analysis_count == 1


def test_analyzing_same_finding_twice_upserts_rather_than_duplicates(client, engine, monkeypatch):
    finding_id = _make_finding(engine)
    _set_config(engine, ai_provider="anthropic", anthropic_api_key="sk-ant-test")

    class FakeBlock:
        text = "Sanitize the input."

    class FakeResponse:
        content = [FakeBlock()]

    class FakeMessages:
        def create(self, **kwargs):
            return FakeResponse()

    class FakeAnthropic:
        def __init__(self, api_key):
            self.messages = FakeMessages()

    monkeypatch.setattr("anthropic.Anthropic", FakeAnthropic)

    client.post(f"/api/ai/analyze/{finding_id}")
    resp2 = client.post(f"/api/ai/analyze/{finding_id}")
    assert resp2.status_code == 200

    with Session(engine) as session:
        runs = session.exec(select(AiAnalysisRun).where(AiAnalysisRun.finding_id == finding_id)).all()
        assert len(runs) == 1  # upserted, not a second row
        assert runs[0].analysis_count == 2


def test_recent_analyses_empty_when_nothing_analyzed_yet(client, engine):
    resp = client.get("/api/ai/recent")
    assert resp.status_code == 200
    assert resp.json() == []


def test_recent_analyses_lists_findings_this_user_has_analyzed(client, engine, monkeypatch):
    finding_id, target_id, _ws_id = _make_finding_with_ids(engine)
    _set_config(engine, ai_provider="anthropic", anthropic_api_key="sk-ant-test")

    class FakeBlock:
        text = "Sanitize the input."

    class FakeResponse:
        content = [FakeBlock()]

    class FakeMessages:
        def create(self, **kwargs):
            return FakeResponse()

    class FakeAnthropic:
        def __init__(self, api_key):
            self.messages = FakeMessages()

    monkeypatch.setattr("anthropic.Anthropic", FakeAnthropic)
    client.post(f"/api/ai/analyze/{finding_id}")

    resp = client.get("/api/ai/recent")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["finding_id"] == finding_id
    assert body[0]["title"] == "SQL Injection"
    assert body[0]["severity"] == "High"
    assert body[0]["target_id"] == target_id
    assert body[0]["target_name"] == "Target A"


def test_recent_analyses_is_scoped_to_the_calling_user_not_global(client, engine, monkeypatch):
    finding_id = _make_finding(engine)
    _set_config(engine, ai_provider="anthropic", anthropic_api_key="sk-ant-test")

    class FakeBlock:
        text = "Sanitize the input."

    class FakeResponse:
        content = [FakeBlock()]

    class FakeMessages:
        def create(self, **kwargs):
            return FakeResponse()

    class FakeAnthropic:
        def __init__(self, api_key):
            self.messages = FakeMessages()

    monkeypatch.setattr("anthropic.Anthropic", FakeAnthropic)
    client.post(f"/api/ai/analyze/{finding_id}")

    # A second, different logged-in user should not see the first user's
    # recent-analyses entry.
    _login(client, engine, email="other@example.com")
    resp = client.get("/api/ai/recent")
    assert resp.status_code == 200
    assert resp.json() == []


def test_analyze_returns_404_for_finding_outside_non_admin_callers_workspace(client, engine):
    finding_id, _target_id, _ws_id = _make_finding_with_ids(engine, target_name="Other Target")
    _set_config(engine, ai_provider="anthropic", anthropic_api_key="sk-ant-test")

    # Log in as a plain (non-admin) user with no WorkspaceMembership at all
    # -- accessible_workspace_ids() returns [] for them, so the finding
    # (which belongs to a workspace they're not a member of) must 404, not
    # leak via a successful analysis.
    with Session(engine) as session:
        user = User(email="dev@example.com", name="Dev", password_hash=hash_password("whatever123"), role=UserRole.USER)
        session.add(user)
        session.commit()
        session.refresh(user)
        token = create_session_token(user.id)
    client.cookies.set("rikugan_session", token)

    resp = client.post(f"/api/ai/analyze/{finding_id}")
    assert resp.status_code == 404


def test_analyze_succeeds_for_finding_in_non_admin_callers_own_workspace(client, engine, monkeypatch):
    finding_id, _target_id, ws_id = _make_finding_with_ids(engine, target_name="My Target")
    _set_config(engine, ai_provider="anthropic", anthropic_api_key="sk-ant-test")

    class FakeBlock:
        text = "Sanitize the input."

    class FakeResponse:
        content = [FakeBlock()]

    class FakeMessages:
        def create(self, **kwargs):
            return FakeResponse()

    class FakeAnthropic:
        def __init__(self, api_key):
            self.messages = FakeMessages()

    monkeypatch.setattr("anthropic.Anthropic", FakeAnthropic)

    with Session(engine) as session:
        user = User(email="dev2@example.com", name="Dev2", password_hash=hash_password("whatever123"), role=UserRole.USER)
        session.add(user)
        session.commit()
        session.refresh(user)
        session.add(WorkspaceMembership(user_id=user.id, workspace_id=ws_id, role=WorkspaceRole.DEVELOPER))
        session.commit()
        token = create_session_token(user.id)
    client.cookies.set("rikugan_session", token)

    resp = client.post(f"/api/ai/analyze/{finding_id}")
    assert resp.status_code == 200
