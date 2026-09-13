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
  - ``webhook_reachable`` classification: every spelling of localhost, the
    LAN/link-local/CGNAT ranges that are equally unreachable from
    github.com, a value with no parseable host, a compose-internal bare
    hostname (reachable here, advised against in the UI), and a real public
    URL.
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
        # No scheme. urlparse reads this as scheme="localhost", path="8000"
        # and reports hostname None, which used to make the emptiest
        # possible answer ("") sail past a tuple of loopback literals and
        # classify as reachable -- no banner, an enabled Connect button,
        # and GitHub's rejection page. Nothing in config.py requires a
        # scheme, so this is a value an operator can really end up with.
        "localhost:8000",
        "127.0.0.1:8000",
        # The rest of 127.0.0.0/8, not just .1.
        "http://127.0.0.2:8000",
        # inet_aton shorthand for 127.0.0.1. Rejected by ipaddress (it
        # wants four octets) but accepted by resolvers, browsers and curl.
        "http://127.1:8000",
        # IPv4-mapped IPv6. The v6 address reports is_loopback False; it
        # has to be unwrapped to the v4 address it carries.
        "http://[::ffff:127.0.0.1]:8000",
        # RFC 6761 reserves .localhost to the loopback interface.
        "http://toleman.localhost:8000",
        # The trailing dot of a fully-qualified name is legal in a URL and
        # resolves to the same place.
        "http://localhost.:8000",
    ],
)
def test_loopback_addresses_are_not_reachable(backend_url):
    """Every spelling of "this machine". GitHub rejects the manifest for
    all of them, so the UI must refuse to submit it -- and
    target_has_pr_guardrail_coverage must not read any of them as proof
    that PRs are already scanned server-side."""
    assert webhook_reachable(backend_url) is False


@pytest.mark.parametrize(
    "backend_url",
    [
        # RFC 1918. An on-prem deployment reachable on the office LAN is an
        # ordinary configuration, and just as unreachable from github.com as
        # localhost is -- but is_loopback says False for all of these, so
        # they used to sail through with no warning, an enabled Connect
        # button, and (worse) a True that told
        # target_has_pr_guardrail_coverage this target's PRs were already
        # scanned server-side.
        "http://192.168.1.50:8000",
        "http://10.0.0.5:8000",
        "http://172.16.3.4:8000",
        # Link-local, including the cloud metadata endpoint.
        "http://169.254.169.254:8000",
        "http://[fe80::1]:8000",
        # CGNAT (100.64.0.0/10): is_private alone misses this, which is why
        # the check is `not is_global`.
        "http://100.64.0.1:8000",
        # RFC 5737 documentation range, likewise not globally routable.
        "http://203.0.113.10:8000",
    ],
)
def test_addresses_that_are_not_globally_routable_are_not_reachable(backend_url):
    """Certain, not merely likely: Toleman only ever talks to
    api.github.com (hardcoded, no GitHub-host setting), so a delivery has
    to come back from the public internet. No deployment shape makes a LAN
    address reachable from there, which is what earns this a block rather
    than the advisory a dotless *name* gets."""
    assert webhook_reachable(backend_url) is False


@pytest.mark.parametrize("backend_url", ["", "   ", "http://", "http://:8000"])
def test_a_value_with_no_host_is_not_reachable(backend_url):
    """An unparseable or empty PUBLIC_API_URL is not a host that merely
    happens not to be loopback; there is nothing for GitHub to deliver to
    either way. Classified unreachable so it lands on the warning path
    rather than the silently-broken one."""
    assert webhook_reachable(backend_url) is False


def test_a_real_public_url_is_reachable():
    assert webhook_reachable("https://api.toleman.example.com") is True
    # What a tunnel hands back, the answer this warning actually points at.
    assert webhook_reachable("https://spare-cloud-1234.trycloudflare.com") is True
    # A globally routable IP is a host like any other. Deliberately not one
    # of the RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
    # 203.0.113.0/24) that would otherwise be the natural choice here:
    # Python reports those as not global, so they are classified
    # unreachable along with the LAN ranges -- correctly, since nothing
    # routes to them either.
    assert webhook_reachable("http://8.8.8.8:8000") is True


def test_a_dotless_hostname_is_still_reachable_here_and_warned_about_in_the_ui():
    """A compose service name like ``backend`` is a single-label host that
    cannot resolve publicly, so GitHub will reject it too. It is
    deliberately *not* classified here anyway: False disables the Connect
    button, which has no override, and feeds
    target_has_pr_guardrail_coverage's routing decision, so False is
    reserved for what is certain. connect-github-card.tsx carries the
    almost-certain case as an advisory that warns without blocking -- see
    connect-github-card.test.tsx -- where clicking Connect anyway is the
    override this function cannot offer."""
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


def test_manifest_data_does_mint_a_state_token(client, engine, monkeypatch):
    """Positive control for the test above, which would pass just as well if
    /manifest-data had quietly stopped minting tokens (or if the endpoint
    were broken outright). It still does, which is exactly why a page-load
    read must not go through it: every mount of the card used to leave one
    more never-expiring valid CSRF state behind."""
    _login(client, engine)
    monkeypatch.setattr(github_app_api, "BACKEND_URL", "http://localhost:8000")
    before = set(github_app_api._pending_states)

    res = client.get("/api/github-app/manifest-data")

    assert res.status_code == 200
    minted = set(github_app_api._pending_states) - before
    assert len(minted) == 1
    # And it is the same token the caller is told to round-trip back.
    assert f"state={minted.pop()}" in res.json()["post_url"]


def test_status_rejects_an_unauthenticated_caller(client, engine, monkeypatch):
    """/status now carries deployment configuration (PUBLIC_API_URL), not
    just "is anything connected". current_user is the right level -- the
    value is in the App's own public manifest and webhook auth is HMAC, not
    URL obscurity -- but "any logged-in user" is a floor, not nothing, and
    nothing is what an unauthenticated caller gets."""
    monkeypatch.setattr(github_app_api, "BACKEND_URL", "http://localhost:8000")

    res = client.get("/api/github-app/status")

    assert res.status_code in (401, 403)
    assert "public_api_url" not in res.text
