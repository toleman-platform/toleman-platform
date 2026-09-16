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
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
import app.api.github_app as github_app_api
from app.api.deps import get_session
from app.api.webhooks import _candidate_configs, _verify_signature
from app.core.crypto import encrypt_secret
from app.core.github_app import resolve_config_for_installation, resolve_installation_for_repo
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    GitHubAppConfig,
    GitHubInstallation,
    Organization,
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


def _login(client, engine):
    with Session(engine) as session:
        user = User(email="admin@example.com", name="Admin", password_hash=hash_password("whatever123"), role=UserRole.ADMIN)
        session.add(user)
        session.commit()
        session.refresh(user)
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return client


def _login_as(client, engine, role=UserRole.USER, email=None):
    """(#506) Non-admin login, for the per-config authorization tests --
    _login above always creates a global admin, which bypasses every
    per-config gate under test here."""
    email = email or f"{role.value}-{id(object())}@example.com"
    with Session(engine) as session:
        user = User(email=email, name="Test", password_hash=hash_password("whatever123"), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        uid = user.id
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return client, uid


def _assign(engine, user_id: int, workspace_id: int, role: WorkspaceRole = WorkspaceRole.VIEWER):
    with Session(engine) as session:
        session.add(WorkspaceMembership(user_id=user_id, workspace_id=workspace_id, role=role))
        session.commit()


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


def _make_config(
    session, app_id, slug, webhook_secret="", setup_token=None, owner_login=None, owner_type=None,
    workspace_id=None,
) -> GitHubAppConfig:
    cfg = GitHubAppConfig(
        app_id=app_id, slug=slug, client_id="cid", client_secret="csecret",
        private_key_pem="pem", webhook_secret=encrypt_secret(webhook_secret) if webhook_secret else "",
        html_url=f"https://github.com/apps/{slug}",
        setup_token=setup_token,
        owner_login=owner_login,
        owner_type=owner_type,
        workspace_id=workspace_id,
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


# --- "Manage on GitHub" link (manage_url) ---------------------------------
#
# Org-owned and personal-account-owned Apps live at different GitHub
# settings URLs; connect-github-card.tsx 404'd because it guessed the
# personal-account shape for an App actually owned by an org. manage_url is
# now computed server-side from GitHubAppConfig.owner_login/owner_type.


def test_status_manage_url_for_org_owned_app(client, engine):
    _login(client, engine)
    with Session(engine) as session:
        _make_config(session, "1", "app-org", owner_login="acme-corp", owner_type="Organization")

    res = client.get("/api/github-app/status")
    manage_url = res.json()["apps"][0]["manage_url"]
    assert manage_url == "https://github.com/organizations/acme-corp/settings/apps/app-org"


def test_status_manage_url_for_personal_app(client, engine):
    _login(client, engine)
    with Session(engine) as session:
        _make_config(session, "1", "app-personal", owner_login="someuser", owner_type="User")

    res = client.get("/api/github-app/status")
    manage_url = res.json()["apps"][0]["manage_url"]
    assert manage_url == "https://github.com/settings/apps/app-personal"


def test_status_manage_url_falls_back_to_personal_shape_when_owner_unknown(client, engine):
    """A GitHubAppConfig row from before owner_login/owner_type existed (or
    whose lazy backfill via GET /app failed -- see fetch_app_owner) has no
    owner info at all. manage_url must still return *something* clickable
    rather than crash the status read; the old (pre-fix) behavior is the
    only guess available until a successful backfill."""
    _login(client, engine)
    with Session(engine) as session:
        _make_config(session, "1", "app-unknown")

    res = client.get("/api/github-app/status")
    assert res.status_code == 200
    manage_url = res.json()["apps"][0]["manage_url"]
    assert manage_url == "https://github.com/settings/apps/app-unknown"


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
        # Delivery claims to be from installation 222 (App B); only App B's
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


# --- Issue #506: per-workspace GitHub App -------------------------------


def test_resolve_config_for_installation_prefers_workspace_match_over_platform_default(engine):
    """An unlinked legacy installation resolves to its own workspace's App
    ahead of the platform-default one, when both exist."""
    with Session(engine) as session:
        ws = _make_workspace(session)
        platform_default = _make_config(session, "1", "platform-app", workspace_id=None)
        ws_scoped = _make_config(session, "2", "ws-app", workspace_id=ws.id)
        inst = _make_installation(session, ws.id, 111, "org-a", config_id=None)

        resolved = resolve_config_for_installation(session, inst)
        assert resolved.id == ws_scoped.id
        assert resolved.id != platform_default.id


def test_resolve_config_for_installation_falls_back_to_platform_default(engine):
    """No config scoped to this installation's own workspace, but exactly
    one platform-default config exists -- that's the safe fallback."""
    with Session(engine) as session:
        ws_a = _make_workspace(session)
        ws_b = _make_workspace(session)
        platform_default = _make_config(session, "1", "platform-app", workspace_id=None)
        _make_config(session, "2", "ws-b-app", workspace_id=ws_b.id)
        inst = _make_installation(session, ws_a.id, 111, "org-a", config_id=None)

        resolved = resolve_config_for_installation(session, inst)
        assert resolved.id == platform_default.id


def test_resolve_config_for_installation_does_not_fall_through_to_platform_default_when_workspace_match_is_ambiguous(engine):
    """Two configs both scoped to this installation's own workspace is a
    real ambiguity (data-integrity bug elsewhere, not a case to guess
    through) -- falling back to a single platform-default config here would
    hand this installation an App that doesn't own it."""
    with Session(engine) as session:
        ws = _make_workspace(session)
        _make_config(session, "1", "ws-app-a", workspace_id=ws.id)
        _make_config(session, "2", "ws-app-b", workspace_id=ws.id)
        _make_config(session, "3", "platform-app", workspace_id=None)
        inst = _make_installation(session, ws.id, 111, "org-a", config_id=None)

        assert resolve_config_for_installation(session, inst) is None


def test_status_filters_to_platform_default_and_accessible_workspaces(client, engine):
    """A non-admin sees the platform-default App plus only the workspace-
    scoped Apps for workspaces they belong to -- previously /status
    returned every App platform-wide to any authenticated viewer."""
    with Session(engine) as session:
        ws_a = _make_workspace(session)
        ws_b = _make_workspace(session)
        ws_a_id, ws_b_id = ws_a.id, ws_b.id
        _make_config(session, "1", "platform-app", workspace_id=None)
        _make_config(session, "2", "ws-a-app", workspace_id=ws_a_id)
        _make_config(session, "3", "ws-b-app", workspace_id=ws_b_id)

    client, uid = _login_as(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a_id)

    res = client.get("/api/github-app/status")
    assert res.status_code == 200
    slugs = {a["app_slug"] for a in res.json()["apps"]}
    assert slugs == {"platform-app", "ws-a-app"}


def test_status_admin_sees_every_app(client, engine):
    with Session(engine) as session:
        ws_a = _make_workspace(session)
        ws_b = _make_workspace(session)
        _make_config(session, "1", "platform-app", workspace_id=None)
        _make_config(session, "2", "ws-a-app", workspace_id=ws_a.id)
        _make_config(session, "3", "ws-b-app", workspace_id=ws_b.id)

    _login(client, engine)
    res = client.get("/api/github-app/status")
    slugs = {a["app_slug"] for a in res.json()["apps"]}
    assert slugs == {"platform-app", "ws-a-app", "ws-b-app"}


def test_manifest_data_requires_admin_for_platform_default_app(client, engine):
    client, uid = _login_as(client, engine, role=UserRole.VIEWER)
    res = client.get("/api/github-app/manifest-data")
    assert res.status_code == 403


def test_manifest_data_requires_workspace_role_for_scoped_app(client, engine):
    with Session(engine) as session:
        ws = _make_workspace(session)

    client, uid = _login_as(client, engine, role=UserRole.VIEWER)
    # No membership at all yet -- must be refused, not silently treated as
    # the platform-default (admin-only) path.
    res = client.get("/api/github-app/manifest-data", params={"workspace_id": ws.id})
    assert res.status_code == 403

    _assign(engine, uid, ws.id, role=WorkspaceRole.SECURITY_ENGINEER)
    res = client.get("/api/github-app/manifest-data", params={"workspace_id": ws.id})
    assert res.status_code == 200


def test_manifest_callback_round_trip_sets_workspace_id(client, engine, monkeypatch):
    """manifest-data mints a state carrying workspace_id; callback reads it
    back off _pending_states and sets it on the row it creates."""
    with Session(engine) as session:
        ws = _make_workspace(session)

    client, uid = _login_as(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws.id, role=WorkspaceRole.SECURITY_ENGINEER)

    res = client.get("/api/github-app/manifest-data", params={"workspace_id": ws.id})
    assert res.status_code == 200
    post_url = res.json()["post_url"]
    state = post_url.split("state=")[1]

    fake_response = MagicMock()
    fake_response.raise_for_status = lambda: None
    fake_response.json = lambda: {
        "id": 555,
        "slug": "toleman-devsecops-xyz",
        "client_id": "cid",
        "client_secret": "csecret",
        "pem": "test-fixture-not-a-real-key",
        "webhook_secret": "whsec",
        "html_url": "https://github.com/apps/toleman-devsecops-xyz",
        "owner": {"login": "acme-corp", "type": "Organization"},
    }
    monkeypatch.setattr(github_app_api.httpx, "post", lambda *a, **kw: fake_response)

    cb = client.get("/api/github-app/callback", params={"code": "onetime", "state": state}, follow_redirects=False)
    assert cb.status_code in (302, 307)

    with Session(engine) as session:
        config = session.exec(select(GitHubAppConfig).where(GitHubAppConfig.setup_token == state)).first()
        assert config is not None
        assert config.workspace_id == ws.id


def test_update_webhook_secret_workspace_security_engineer_can_manage_own_config(client, engine):
    with Session(engine) as session:
        ws = _make_workspace(session)
        ws_id = ws.id
        cfg = _make_config(session, "1", "ws-app", workspace_id=ws_id)
        cfg_id = cfg.id

    client, uid = _login_as(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_id, role=WorkspaceRole.SECURITY_ENGINEER)

    res = client.patch(
        "/api/github-app/webhook-secret",
        json={"webhook_secret": "new-secret", "config_id": cfg_id},
    )
    assert res.status_code == 200
    assert res.json()["webhook_secret_set"] is True


def test_update_webhook_secret_refused_for_other_workspaces_config(client, engine):
    with Session(engine) as session:
        ws_a = _make_workspace(session)
        ws_b = _make_workspace(session)
        ws_a_id = ws_a.id
        cfg_b = _make_config(session, "1", "ws-b-app", workspace_id=ws_b.id)
        cfg_b_id = cfg_b.id

    client, uid = _login_as(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a_id, role=WorkspaceRole.SECURITY_ENGINEER)

    res = client.patch(
        "/api/github-app/webhook-secret",
        json={"webhook_secret": "new-secret", "config_id": cfg_b_id},
    )
    assert res.status_code == 403


def test_update_webhook_secret_refused_for_non_admin_on_platform_default(client, engine):
    with Session(engine) as session:
        ws = _make_workspace(session)
        ws_id = ws.id
        cfg = _make_config(session, "1", "platform-app", workspace_id=None)
        cfg_id = cfg.id

    client, uid = _login_as(client, engine, role=UserRole.VIEWER)
    # Even a security engineer of a real workspace can't touch the
    # platform-default config -- only a global admin can.
    _assign(engine, uid, ws_id, role=WorkspaceRole.SECURITY_ENGINEER)

    res = client.patch(
        "/api/github-app/webhook-secret",
        json={"webhook_secret": "new-secret", "config_id": cfg_id},
    )
    assert res.status_code == 403


def test_delete_app_config_workspace_security_engineer_can_delete_own_config(client, engine):
    with Session(engine) as session:
        ws = _make_workspace(session)
        ws_id = ws.id
        cfg = _make_config(session, "1", "ws-app", workspace_id=ws_id)
        cfg_id = cfg.id

    client, uid = _login_as(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_id, role=WorkspaceRole.SECURITY_ENGINEER)

    res = client.delete(f"/api/github-app/{cfg_id}")
    assert res.status_code == 200

    with Session(engine) as session:
        assert session.get(GitHubAppConfig, cfg_id) is None


def test_delete_app_config_refused_for_other_workspaces_config(client, engine):
    with Session(engine) as session:
        ws_a = _make_workspace(session)
        ws_b = _make_workspace(session)
        ws_a_id = ws_a.id
        cfg_b = _make_config(session, "1", "ws-b-app", workspace_id=ws_b.id)
        cfg_b_id = cfg_b.id

    client, uid = _login_as(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a_id, role=WorkspaceRole.SECURITY_ENGINEER)

    res = client.delete(f"/api/github-app/{cfg_b_id}")
    assert res.status_code == 403

    with Session(engine) as session:
        assert session.get(GitHubAppConfig, cfg_b_id) is not None


def test_delete_app_config_refused_for_non_admin_on_platform_default(client, engine):
    with Session(engine) as session:
        cfg = _make_config(session, "1", "platform-app", workspace_id=None)
        cfg_id = cfg.id

    client, uid = _login_as(client, engine, role=UserRole.VIEWER)

    res = client.delete(f"/api/github-app/{cfg_id}")
    assert res.status_code == 403


def test_delete_app_config_admin_can_delete_platform_default(client, engine):
    with Session(engine) as session:
        cfg = _make_config(session, "1", "platform-app", workspace_id=None)
        cfg_id = cfg.id

    _login(client, engine)
    res = client.delete(f"/api/github-app/{cfg_id}")
    assert res.status_code == 200
