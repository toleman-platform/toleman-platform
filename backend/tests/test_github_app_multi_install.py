"""Tests for #34 (multi-App / multi-install support).

Covers:
  - resolve_config_for_installation / resolve_installation_for_repo (core
    resolution helpers that replaced blind `.first()` lookups)
  - /api/github-app/status reporting every registered App + its installations
  - webhook signature verification routes to the correct App's secret when
    more than one App/installation is configured
"""
import hashlib
import hmac

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.api.webhooks import _candidate_configs, _verify_signature
from app.core.crypto import encrypt_secret
from app.core.github_app import resolve_config_for_installation, resolve_installation_for_repo
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import GitHubAppConfig, GitHubInstallation, Organization, User, UserRole, Workspace


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


def _login(client, engine):
    with Session(engine) as session:
        user = User(email="admin@example.com", name="Admin", password_hash=hash_password("whatever123"), role=UserRole.ADMIN)
        session.add(user)
        session.commit()
        session.refresh(user)
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return client


def _make_workspace(session) -> Workspace:
    org = Organization(name="default")
    session.add(org)
    session.commit()
    session.refresh(org)
    ws = Workspace(organization_id=org.id, name="default", api_key="k")
    session.add(ws)
    session.commit()
    session.refresh(ws)
    return ws


def _make_config(session, app_id, slug, webhook_secret="", setup_token=None) -> GitHubAppConfig:
    cfg = GitHubAppConfig(
        app_id=app_id, slug=slug, client_id="cid", client_secret="csecret",
        private_key_pem="pem", webhook_secret=encrypt_secret(webhook_secret) if webhook_secret else "",
        html_url=f"https://github.com/apps/{slug}",
        setup_token=setup_token,
    )
    session.add(cfg)
    session.commit()
    session.refresh(cfg)
    return cfg


def _make_installation(session, workspace_id, installation_id, account_login, config_id=None) -> GitHubInstallation:
    inst = GitHubInstallation(
        installation_id=installation_id, account_login=account_login, account_type="Organization",
        workspace_id=workspace_id, github_app_config_id=config_id,
    )
    session.add(inst)
    session.commit()
    session.refresh(inst)
    return inst


# --- resolve_config_for_installation -----------------------------------

def test_resolve_config_for_installation_uses_fk_when_present(engine):
    with Session(engine) as session:
        ws = _make_workspace(session)
        cfg_a = _make_config(session, "1", "app-a")
        cfg_b = _make_config(session, "2", "app-b")
        inst = _make_installation(session, ws.id, 111, "org-a", config_id=cfg_b.id)

        resolved = resolve_config_for_installation(session, inst)
        assert resolved.id == cfg_b.id
        assert resolved.id != cfg_a.id


def test_resolve_config_for_installation_falls_back_when_exactly_one_config(engine):
    """Legacy installation rows (created before github_app_config_id existed)
    still resolve correctly as long as there's only one App configured."""
    with Session(engine) as session:
        ws = _make_workspace(session)
        cfg = _make_config(session, "1", "only-app")
        inst = _make_installation(session, ws.id, 111, "org-a", config_id=None)

        resolved = resolve_config_for_installation(session, inst)
        assert resolved.id == cfg.id


def test_resolve_config_for_installation_ambiguous_with_multiple_unlinked_configs(engine):
    with Session(engine) as session:
        ws = _make_workspace(session)
        _make_config(session, "1", "app-a")
        _make_config(session, "2", "app-b")
        inst = _make_installation(session, ws.id, 111, "org-a", config_id=None)

        assert resolve_config_for_installation(session, inst) is None


# --- resolve_installation_for_repo --------------------------------------

def test_resolve_installation_for_repo_matches_by_account_login(engine):
    with Session(engine) as session:
        ws = _make_workspace(session)
        _make_installation(session, ws.id, 111, "govwa")
        inst_gotest = _make_installation(session, ws.id, 222, "gotest")

        resolved = resolve_installation_for_repo(session, ws.id, "gotest/some-repo")
        assert resolved.installation_id == inst_gotest.installation_id


def test_resolve_installation_for_repo_falls_back_to_first_when_no_match(engine):
    with Session(engine) as session:
        ws = _make_workspace(session)
        inst = _make_installation(session, ws.id, 111, "govwa")

        resolved = resolve_installation_for_repo(session, ws.id, "unrelated-org/some-repo")
        assert resolved.installation_id == inst.installation_id


def test_resolve_installation_for_repo_none_when_no_installations(engine):
    with Session(engine) as session:
        ws = _make_workspace(session)
        assert resolve_installation_for_repo(session, ws.id, "org/repo") is None


# --- /api/github-app/status ---------------------------------------------

def test_status_lists_every_app_and_its_own_installations(client, engine):
    _login(client, engine)
    with Session(engine) as session:
        ws = _make_workspace(session)
        cfg_a = _make_config(session, "1", "app-a", webhook_secret="secretA")
        cfg_b = _make_config(session, "2", "app-b", webhook_secret="secretB")
        _make_installation(session, ws.id, 111, "org-a", config_id=cfg_a.id)
        _make_installation(session, ws.id, 222, "org-b1", config_id=cfg_b.id)
        _make_installation(session, ws.id, 333, "org-b2", config_id=cfg_b.id)

    res = client.get("/api/github-app/status")
    assert res.status_code == 200
    data = res.json()
    assert data["app_configured"] is True
    assert data["installed"] is True
    assert len(data["apps"]) == 2

    by_slug = {a["app_slug"]: a for a in data["apps"]}
    assert len(by_slug["app-a"]["installations"]) == 1
    assert by_slug["app-a"]["installations"][0]["account_login"] == "org-a"
    assert len(by_slug["app-b"]["installations"]) == 2
    logins = {i["account_login"] for i in by_slug["app-b"]["installations"]}
    assert logins == {"org-b1", "org-b2"}


def test_status_empty_when_nothing_configured(client, engine):
    _login(client, engine)
    res = client.get("/api/github-app/status")
    data = res.json()
    assert data["apps"] == []
    assert data["app_configured"] is False
    assert data["installed"] is False


# --- webhook signature verification across multiple Apps -----------------

def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_verify_signature_routes_to_correct_app_via_payload_installation_id(engine):
    with Session(engine) as session:
        ws = _make_workspace(session)
        cfg_a = _make_config(session, "1", "app-a", webhook_secret="secretA")
        cfg_b = _make_config(session, "2", "app-b", webhook_secret="secretB")
        _make_installation(session, ws.id, 111, "org-a", config_id=cfg_a.id)
        _make_installation(session, ws.id, 222, "org-b", config_id=cfg_b.id)

    with Session(engine) as session:
        body = b'{"action": "opened"}'
        sig_from_app_b = _sign("secretB", body)
        # Delivery claims to be from installation 222 (App B) -- only App B's
        # secret should verify it, even though App A is also configured.
        assert _verify_signature(body, sig_from_app_b, session, payload_installation_id=222) is True
        assert _verify_signature(body, sig_from_app_b, session, payload_installation_id=111) is False


def test_verify_signature_falls_back_to_trying_all_configs_without_installation_id(engine):
    with Session(engine) as session:
        _make_config(session, "1", "app-a", webhook_secret="secretA")
        _make_config(session, "2", "app-b", webhook_secret="secretB")

    with Session(engine) as session:
        body = b'{"action": "opened"}'
        sig = _sign("secretB", body)
        assert _verify_signature(body, sig, session, payload_installation_id=None) is True


def test_verify_signature_rejects_when_no_config_matches(engine):
    with Session(engine) as session:
        _make_config(session, "1", "app-a", webhook_secret="secretA")

    with Session(engine) as session:
        body = b'{"action": "opened"}'
        sig = _sign("some-other-secret", body)
        assert _verify_signature(body, sig, session, payload_installation_id=None) is False


def test_candidate_configs_narrows_to_the_owning_app(engine):
    with Session(engine) as session:
        ws = _make_workspace(session)
        cfg_a = _make_config(session, "1", "app-a")
        cfg_b = _make_config(session, "2", "app-b")
        _make_installation(session, ws.id, 111, "org-a", config_id=cfg_a.id)
        _make_installation(session, ws.id, 222, "org-b", config_id=cfg_b.id)

        candidates = _candidate_configs(session, 222)
        assert [c.id for c in candidates] == [cfg_b.id]
