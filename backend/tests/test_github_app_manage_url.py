"""Tests for the "Manage on GitHub" link fix.

connect-github-card.tsx's "Manage on GitHub" link 404'd for any App owned
by an organization: it guessed `https://github.com/settings/apps/{slug}`
(the personal-account shape) unconditionally, but an App created via
`manifest-data`'s `org` param is owned by that org and lives at
`https://github.com/organizations/{org}/settings/apps/{slug}` instead.

Covers:
  - app.core.github_app.app_management_url building the right URL shape
    for both owner types.
  - app.core.github_app.fetch_app_owner degrading to None (never raising)
    when it can't sign a JWT or reach GitHub -- this runs opportunistically
    on every /api/github-app/status read for legacy rows, so it must never
    break that read.
  - /api/github-app/callback (the manifest-conversion redirect target)
    persisting owner_login/owner_type from GitHub's response so newly
    created Apps don't need the lazy backfill at all.
"""
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
import app.api.github_app as github_app_api
import app.core.github_app as github_app_core
from app.api.deps import get_session
from app.core.github_app import app_management_url, fetch_app_owner
from app.main import app
from app.models.models import GitHubAppConfig


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


def _config(**overrides) -> GitHubAppConfig:
    defaults = dict(
        id=1, app_id="1", slug="my-app", client_id="cid", client_secret="csecret",
        private_key_pem="pem", webhook_secret="", html_url="https://github.com/apps/my-app",
    )
    defaults.update(overrides)
    return GitHubAppConfig(**defaults)


# --- app_management_url ----------------------------------------------------


def test_manage_url_for_organization_owned_app():
    cfg = _config(owner_login="acme-corp", owner_type="Organization")
    assert app_management_url(cfg) == "https://github.com/organizations/acme-corp/settings/apps/my-app"


def test_manage_url_for_personal_app():
    cfg = _config(owner_login="someuser", owner_type="User")
    assert app_management_url(cfg) == "https://github.com/settings/apps/my-app"


def test_manage_url_falls_back_to_personal_shape_when_owner_unset():
    cfg = _config(owner_login=None, owner_type=None)
    assert app_management_url(cfg) == "https://github.com/settings/apps/my-app"


def test_manage_url_ignores_organization_type_without_a_login():
    """Defensive: owner_type could theoretically be set without owner_login
    (e.g. a partial/corrupted backfill). Must not build a malformed URL."""
    cfg = _config(owner_login=None, owner_type="Organization")
    assert app_management_url(cfg) == "https://github.com/settings/apps/my-app"


# --- fetch_app_owner ---------------------------------------------------


def test_fetch_app_owner_returns_none_on_invalid_signing_key():
    """private_key_pem isn't a real PEM here (as in every other test
    fixture in this suite) -- generate_app_jwt can't sign a JWT with it, so
    this must degrade to None rather than raising and breaking the caller
    (app.api.github_app.status, a request every page load hits)."""
    cfg = _config()
    assert fetch_app_owner(cfg) is None


def test_fetch_app_owner_returns_none_on_github_error(monkeypatch):
    cfg = _config()
    monkeypatch.setattr(github_app_core, "generate_app_jwt", lambda c: "fake.jwt.token")

    def fake_get(*args, **kwargs):
        raise Exception("network unreachable")

    monkeypatch.setattr(github_app_core.httpx, "get", fake_get)
    assert fetch_app_owner(cfg) is None


# --- /api/github-app/callback persists owner info ----------------------


def test_callback_persists_owner_login_and_type(client, engine, monkeypatch):
    state = "test-state-123"
    github_app_api._pending_states.add(state)

    fake_response = MagicMock()
    fake_response.raise_for_status = lambda: None
    fake_response.json = lambda: {
        "id": 999,
        "slug": "toleman-devsecops-abc",
        "client_id": "cid",
        "client_secret": "csecret",
        "pem": "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----",
        "webhook_secret": "whsec",
        "html_url": "https://github.com/apps/toleman-devsecops-abc",
        "owner": {"login": "acme-corp", "type": "Organization"},
    }
    monkeypatch.setattr(github_app_api.httpx, "post", lambda *a, **kw: fake_response)

    res = client.get("/api/github-app/callback", params={"code": "onetime", "state": state}, follow_redirects=False)
    assert res.status_code in (302, 307)

    with Session(engine) as session:
        configs = session.exec(select(GitHubAppConfig)).all()
        assert len(configs) == 1
        assert configs[0].owner_login == "acme-corp"
        assert configs[0].owner_type == "Organization"


def test_callback_persists_none_owner_fields_when_github_omits_it(client, engine, monkeypatch):
    """Defensive: if GitHub's response ever lacks an "owner" key, this must
    not crash -- the row just falls back to the personal-account URL guess
    until a later backfill (or never, if it truly has no owner, which
    shouldn't happen for a real App but the code must not assume)."""
    state = "test-state-456"
    github_app_api._pending_states.add(state)

    fake_response = MagicMock()
    fake_response.raise_for_status = lambda: None
    fake_response.json = lambda: {
        "id": 1000,
        "slug": "toleman-devsecops-def",
        "client_id": "cid",
        "client_secret": "csecret",
        "pem": "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----",
        "webhook_secret": "whsec",
        "html_url": "https://github.com/apps/toleman-devsecops-def",
    }
    monkeypatch.setattr(github_app_api.httpx, "post", lambda *a, **kw: fake_response)

    res = client.get("/api/github-app/callback", params={"code": "onetime", "state": state}, follow_redirects=False)
    assert res.status_code in (302, 307)

    with Session(engine) as session:
        configs = session.exec(select(GitHubAppConfig)).all()
        assert configs[0].owner_login is None
        assert configs[0].owner_type is None
