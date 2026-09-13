"""Tests for #355: a localhost PUBLIC_API_URL blocks GitHub App creation.

The manifest declares ``hook_attributes.url``, and GitHub validates that URL
when the manifest is submitted: a loopback host is refused with "Hook url is
not supported because it isn't reachable over the public Internet
(localhost)" and *nothing is created*. Before #234 the manifest carried no
hook URL at all, so a localhost install got an App that simply never
received events -- a real degraded mode, and the one the old warning copy
(and ``webhook_reachable``'s old docstring) described. Adding
hook_attributes turned that into a hard failure without the copy catching
up, so the product promised "PRs will only scan on demand" for an App that
can never exist.

Covers:
  - ``webhook_reachable`` classification: the loopback literals, a
    compose-internal bare hostname, and a real public URL.
  - ``/api/github-app/status`` carrying ``webhook_reachable`` /
    ``public_api_url`` with **zero** Apps configured. That is the whole
    point of moving them onto this endpoint: the warning has to render, and
    the Connect button has to be disabled, on a fresh install where
    ``apps`` is empty and the old placement (inside ``status.apps.map``)
    rendered nothing at all.
  - reading the status page not minting a CSRF state token, which is what
    the frontend's old per-page-load call to ``/manifest-data`` did just to
    get this one boolean.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
import app.api.github_app as github_app_api
from app.api.deps import get_session
from app.core.crypto import encrypt_secret
from app.core.github_app import webhook_reachable
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import GitHubAppConfig, User, UserRole


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
        user = User(
            email="admin@example.com",
            name="Admin",
            password_hash=hash_password("whatever123"),
            role=UserRole.ADMIN,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return client


# --- webhook_reachable classification --------------------------------------


@pytest.mark.parametrize(
    "backend_url",
    [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://[::1]:8000",
        "http://0.0.0.0:8000",
        # urlparse().hostname lowercases, so a shouty .env value is caught
        # too rather than sailing past a case-sensitive comparison.
        "HTTP://LOCALHOST:8000",
    ],
)
def test_loopback_addresses_are_not_reachable(backend_url):
    """Every form the default local install can produce. GitHub rejects the
    manifest for all of them, so the UI must refuse to submit it."""
    assert webhook_reachable(backend_url) is False


def test_a_real_public_url_is_reachable():
    assert webhook_reachable("https://api.toleman.example.com") is True
    # What a tunnel hands back, the answer this warning actually points at.
    assert webhook_reachable("https://spare-cloud-1234.trycloudflare.com") is True


def test_a_bare_hostname_is_treated_as_reachable():
    """Deliberate, and a limitation worth stating: a compose-internal name
    like ``backend`` is not publicly resolvable either, and GitHub will
    reject it just the same -- but this function cannot know that from the
    string, whereas a loopback literal is certainly unreachable from
    GitHub's side. Blocking every hostname this process can't classify
    would wedge the only path to creating an App for a deployment whose DNS
    lives somewhere this code cannot see, so the check stays narrow and the
    uncertain cases are left to GitHub."""
    assert webhook_reachable("http://backend:8000") is True
    assert webhook_reachable("https://toleman-internal") is True


# --- /api/github-app/status ------------------------------------------------


def test_status_reports_an_unreachable_webhook_host_before_any_app_exists(client, engine, monkeypatch):
    """The regression this issue is really about. The old warning lived
    inside ``status.apps.map(...)``, so with zero Apps it rendered nothing,
    and the operator clicking Connect for the first time -- the only person
    who can hit this -- was told nothing at all. The flag has to be on the
    payload even when ``apps`` is empty."""
    _login(client, engine)
    monkeypatch.setattr(github_app_api, "BACKEND_URL", "http://localhost:8000")

    data = client.get("/api/github-app/status").json()

    assert data["apps"] == []
    assert data["app_configured"] is False
    assert data["webhook_reachable"] is False
    # Echoed so the warning can name the offending value instead of sending
    # the operator to go and find it.
    assert data["public_api_url"] == "http://localhost:8000"


def test_status_reports_a_reachable_webhook_host(client, engine, monkeypatch):
    _login(client, engine)
    monkeypatch.setattr(github_app_api, "BACKEND_URL", "https://api.toleman.example.com")

    data = client.get("/api/github-app/status").json()

    assert data["webhook_reachable"] is True
    assert data["public_api_url"] == "https://api.toleman.example.com"


def test_status_still_reports_reachability_alongside_configured_apps(client, engine, monkeypatch):
    """An App created while PUBLIC_API_URL was public, then pointed back at
    localhost: the App exists, but its deliveries no longer arrive and no
    *new* App can be created either. Both facts have to survive on the same
    payload."""
    _login(client, engine)
    with Session(engine) as session:
        session.add(GitHubAppConfig(
            app_id="1", slug="app-a", client_id="cid", client_secret="csecret",
            private_key_pem="pem", webhook_secret=encrypt_secret("whsec"),
            html_url="https://github.com/apps/app-a",
            owner_login="acme-corp", owner_type="Organization",
        ))
        session.commit()
    monkeypatch.setattr(github_app_api, "BACKEND_URL", "http://localhost:8000")

    data = client.get("/api/github-app/status").json()

    assert len(data["apps"]) == 1
    assert data["webhook_reachable"] is False


def test_status_does_not_mint_a_manifest_state_token(client, engine, monkeypatch):
    """Why this moved off /manifest-data rather than staying there: that
    endpoint parks a single-use CSRF state token in ``_pending_states`` on
    every call, and the card called it on every mount purely to read this
    boolean. Status reads must stay free of that side effect."""
    _login(client, engine)
    monkeypatch.setattr(github_app_api, "BACKEND_URL", "http://localhost:8000")
    before = set(github_app_api._pending_states)

    client.get("/api/github-app/status")

    assert set(github_app_api._pending_states) == before
