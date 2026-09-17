import ipaddress
import socket
import time
from urllib.parse import urlparse

import httpx
import jwt
from sqlmodel import Session, select

from app.core.crypto import decrypt_secret
from app.models.models import GitHubAppConfig, GitHubInstallation, Target


def _webhook_hostname(backend_url: str) -> str:
    """The host out of a PUBLIC_API_URL, tolerating a missing scheme.

    ``urlparse("localhost:8000")`` does not mean what it looks like: with no
    ``//`` present it reads ``localhost`` as the *scheme* and ``8000`` as
    the path, so ``.hostname`` is None. Nothing in app.core.config requires
    a scheme, so a schemeless PUBLIC_API_URL used to fall straight through
    webhook_reachable's loopback check and classify as reachable -- no
    warning, an enabled Connect button, and GitHub's rejection page.

    Re-parsing with a leading ``//`` forces the netloc reading, which is
    what the value obviously means. Returns "" when there is no host to be
    had (an empty setting, or an unbracketed IPv6 literal, which is not
    parseable as a URL at all); callers treat that as unreachable rather
    than as a host that happens not to be loopback."""
    candidate = backend_url.strip()
    parsed = urlparse(candidate)
    if not parsed.netloc and "//" not in candidate:
        parsed = urlparse(f"//{candidate}")
    # The "//" guard matters: a value that already has one and still parsed
    # to an empty netloc ("http://", "http://:8000") has no host, and
    # re-parsing it would read the scheme itself as the hostname.
    #
    # The trailing dot of a fully-qualified name ("localhost.") is legal in a
    # URL and resolves identically, so it is dropped rather than left to turn
    # a loopback host into an unrecognised one.
    return (parsed.hostname or "").lower().rstrip(".")


def _is_unroutable_host(hostname: str) -> bool:
    """Whether an address at this host is certainly not reachable from
    GitHub's servers.

    Two families, both certain rather than likely:

    **Loopback names.** ``localhost`` and, per RFC 6761, anything under
    ``*.localhost``, which is reserved to the loopback interface.

    **Any IP literal that is not globally routable.** ``ip.is_global`` is
    the test, not ``is_loopback`` (which misses a LAN address entirely) and
    not ``is_private`` (which misses link-local, CGNAT and the reserved
    ranges). What that buys, beyond the loopback cases this started as:

      - ``192.168.1.50``, ``10.0.0.5``, ``172.16.3.4`` -- RFC 1918. An
        on-prem deployment reachable on the LAN is an ordinary
        configuration, and it is exactly as unreachable from github.com as
        localhost is.
      - ``169.254.169.254`` and ``fe80::1`` -- link-local, including the
        cloud metadata endpoint.
      - ``127.0.0.2`` and the rest of 127.0.0.0/8, not just ``127.0.0.1``.
      - the unspecified addresses (``0.0.0.0``, ``::``).

    Certain because Toleman only ever talks to ``api.github.com`` (hardcoded
    across this module and its siblings; there is no GitHub-host setting),
    so the delivery has to come back from the public internet. There is no
    deployment shape in which an RFC 1918 address is reachable from there,
    which is what makes this a block rather than the advisory that
    connect-github-card.tsx gives a dotless *name*.

    Two parsing details behind the literals above:

      - ``127.1`` is inet_aton shorthand for 127.0.0.1. ``ipaddress``
        rejects it (it wants four octets) but resolvers, browsers and curl
        all accept it, so it is a real way to spell localhost.
      - ``::ffff:127.0.0.1`` is an IPv4-mapped IPv6 address, whose IPv6
        form reports ``is_loopback`` False and has to be unwrapped first.
    """
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        # Not an address ipaddress recognises. inet_aton still accepts the
        # shorthand forms (127.1, 2130706433); anything it rejects too is a
        # hostname, not an address.
        try:
            ip = ipaddress.ip_address(socket.inet_aton(hostname))
        except (OSError, ValueError):
            return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return not ip.is_global


def webhook_reachable(backend_url: str) -> bool:
    """Whether GitHub can plausibly reach the given backend URL's webhook
    endpoint -- i.e. it is a publicly routable address rather than a
    localhost or LAN one. Takes the URL as a
    parameter rather than reading settings.public_api_url itself, same
    convention as build_manifest's own app_url/backend_url params just
    below: keeps this testable by callers without needing to monkeypatch a
    module-level settings read, and lets the api layer's own BACKEND_URL
    constant (app.api.github_app) stay the single source callers pass
    through.

    A core-level function (no FastAPI dependency) so both the api layer
    (manifest_data's own "will this App's webhook even work" warning,
    GH-03) and task modules (app.tasks.pipeline_tasks' #245 double-scan
    check, without pulling a FastAPI router module into the Celery
    worker's import graph) can use the same answer.

    False is not a degraded mode at App-creation time, it is a hard stop
    (#355). The manifest declares ``hook_attributes.url`` and GitHub
    validates that URL when the manifest is submitted, rejecting a
    loopback host outright ("Hook url is not supported because it isn't
    reachable over the public Internet (localhost)"); nothing is created,
    so the outcome is no App rather than a working App minus automatic
    scanning. That was survivable once -- before #234 the manifest carried
    no hook URL at all, so a localhost install got an App that simply
    never received events, which is what the "warn, don't block" comment
    that used to sit here described -- and it stopped being true the
    moment hook_attributes landed. The api/UI layer therefore blocks the
    create action on this answer instead of letting the operator discover
    it from github.com.

    ``target_has_pr_guardrail_coverage`` below uses the same answer for a
    different question: for an App that already exists (created while this
    was public, then pointed back at localhost) deliveries stop arriving,
    and that genuinely is a degraded mode.

    False is reserved for what is *certain*: a host that is not globally
    routable (see ``_is_unroutable_host`` -- loopback names, and any IP
    literal from a private, loopback, link-local, CGNAT or reserved range),
    or a value with no parseable host at all. Certainty is the bar because
    of what False now does -- it disables the Connect button, which has no
    override, and it is the same answer
    ``target_has_pr_guardrail_coverage`` uses to decide which path scans a
    target's PRs. A wrong False is not a cosmetic warning, it is an
    operator with no way to proceed.

    A dotless single-label host (``http://backend:8000``, a compose service
    name) is reported reachable for that reason and that reason only. It is
    *almost* certainly unreachable from GitHub too, and saying nothing
    about it would be unhelpful -- so connect-github-card.tsx warns on it
    without blocking, where clicking Connect anyway is the override. What
    genuinely cannot be judged from the string is a dotted name on
    split-horizon or internal-only DNS, which looks exactly like a public
    one from here."""
    hostname = _webhook_hostname(backend_url)
    if not hostname:
        return False
    return not _is_unroutable_host(hostname)


def build_manifest(app_url: str, backend_url: str, name_suffix: str, setup_token: str) -> dict:
    """GitHub App Manifest, https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest

    Permissions mirror the architecture doc's Integration & Permissions Matrix:
    contents (clone + commit fixes), pull_requests + statuses (PR Guardrail),
    workflows (issue #66: Pipeline Integration writes files under
    .github/workflows/), metadata read-only (mandatory baseline).

    ``workflows: write`` is required in addition to ``contents: write`` for
    any Contents-API write under ``.github/workflows/``, GitHub gates that
    path behind its own separate permission scope regardless of the App's
    general contents access (confirmed live: without it, PUT
    /repos/{owner}/{repo}/contents/.github/workflows/<file> 403s with
    "Resource not accessible by integration" even though creating the
    backing branch via POST git/refs succeeds fine on contents:write alone).
    An App installed before this permission existed needs its installation
    owner to re-approve the updated permission set in GitHub's UI,
    ``setup_on_update: True`` below prompts that on next install/reconfigure,
    but doesn't retroactively grant it to installations that don't revisit
    that flow.

    ``setup_url`` carries ``?cfg=<setup_token>`` baked in at manifest-creation
    time (#34: multi-App support). ``setup_url`` is a fixed property of the
    App once created via the manifest conversion, GitHub calls exactly this
    URL (appending its own ``installation_id``/``setup_action`` params) every
    time *this* App is installed/reconfigured, for the life of the App, so
    the token reliably tells /setup-callback which GitHubAppConfig row a new
    installation belongs to without needing to guess or brute-force it.

    No field here sets the App's avatar -- the manifest schema has none, and
    there is no REST endpoint for it either. Left unset, GitHub defaults a
    newly created App's badge to an automatically generated identicon, not a
    Toleman logo. One-time manual fix per App, not automatable from here:
    its owner uploads a logo at github.com/settings/apps/<app-slug> (or the
    org's Developer Settings for an org-owned App).
    """
    return {
        # (GH-05) "Toleman", not "Rikugan", and not the older "OSP
        # DevSecOps" that one replaced in turn. This string
        # is the product's signature on every pull request in an adopting
        # org: GitHub derives the bot login from it, so the old name shipped
        # as `osp-devsecops-*[bot]` on every PR comment. Cosmetic internally,
        # not cosmetic externally.
        #
        # Only affects Apps created from here on; an App's name is fixed at
        # creation, so an existing installation keeps its old bot login until
        # its owner renames it in GitHub's own App settings.
        "name": f"Toleman DevSecOps {name_suffix}",
        "url": app_url,
        "redirect_url": f"{backend_url}/api/github-app/callback",
        "setup_url": f"{backend_url}/api/github-app/setup-callback?cfg={setup_token}",
        "setup_on_update": True,
        "public": False,
        "default_permissions": {
            "contents": "write",
            "workflows": "write",
            "pull_requests": "write",
            "statuses": "write",
            "metadata": "read",
            "issues": "read",
        },
        # (GH-03) Subscribe to pull_request so blocking mode is actually
        # automatic. This was `[]` with no hook_attributes, so the App
        # subscribed to nothing: a human had to open PR History and press
        # "Scan This PR" for anything to happen. An external review put it
        # exactly right; "blocking mode" that depends on someone
        # remembering to press a button is advisory in practice, and a
        # required check nobody triggers blocks every PR forever.
        #
        # Nothing else had to be built for this. app/api/webhooks.py already
        # verifies the HMAC signature, filters to pull_request, resolves the
        # target and dispatches the Celery scan; and the manifest-conversion
        # handler already persists the webhook secret GitHub generates for a
        # manifest that declares hook_attributes. The only missing piece was
        # the subscription itself.
        #
        # push/installation_repositories/issue_comment added later, closing
        # three real gaps found while explaining this App's behavior in a
        # support session. Only push turned out to be a plain default_events
        # entry (#475): issue_comment also needs "issues": "read" above, and
        # installation_repositories is not declared here at all. A manifest only
        # shapes Apps created from here on, so no existing installation's
        # owner is prompted to re-approve anything either way -- but by the
        # same token an App created before "issues": "read" was in this
        # manifest cannot subscribe to issue_comment until its owner grants
        # Issues read access on the App's own settings page (there is no API
        # for it; see app_management_url below):
        #   - push: without it, nothing tells Toleman a PR merged. A
        #     target's own generated toleman-scan.yml (if TOLEMAN_API_URL/
        #     TOLEMAN_API_KEY are configured on it) already re-scans on push
        #     and posts back via /api/ingest, but that path is entirely
        #     opt-in per target repo; this makes "the dashboard reflects a
        #     merged fix" not depend on a target repo's own secrets being
        #     set up. See the push branch in app/api/webhooks.py.
        #   - installation_repositories: without it, adding a repo to an
        #     existing installation (via GitHub's own "Configure" screen,
        #     not through Toleman) creates no Target until someone remembers
        #     the manual "Sync now" button (POST /api/github-app/sync). Not
        #     listed in default_events below: GitHub sends it to every App
        #     automatically and rejects a manifest that tries to subscribe
        #     to it explicitly ("you cannot manually subscribe to this
        #     event").
        #   - issue_comment: lets `@toleman ignore finding=<id> <reason>` on
        #     a PR create the same IgnoreStatus.REQUESTED row the "Request
        #     ignore" UI button does (app/api/pr_guardrail.py's
        #     request_ignore, refactored so both share
        #     pr_guardrail_executor.submit_ignore_request) -- still goes to
        #     the security team for approval either way, never
        #     auto-approved from a comment. Requires "issues": "read" above;
        #     GitHub rejects the event without it since issue_comment is an
        #     Issues-API webhook even when it fires on a PR thread.
        #
        # backend_url must be reachable *from GitHub*; see
        # settings.public_api_url. GitHub validates this URL when the
        # manifest is submitted and refuses any host it cannot reach over
        # the public internet -- a loopback address, and equally a LAN one
        # -- so such a value does not produce a degraded App, it produces
        # no App at all:
        # the flow dies on github.com with "Hook url is not supported
        # because it isn't reachable over the public Internet (localhost)".
        # webhook_reachable() is what the api/UI layer uses to stop that
        # attempt before it leaves the browser (#355); this comment used to
        # claim the opposite, which is why the old behaviour read as
        # deliberate.
        #
        # Permanent for the life of the App, too: there is no API to change
        # a GitHub App's hook URL after creation, only its settings page by
        # hand (the same limitation update_webhook_secret in
        # app/api/github_app.py already documents for the webhook secret).
        "default_events": ["pull_request", "push", "issue_comment"],
        "hook_attributes": {
            "url": f"{backend_url}/api/webhooks/github",
            "active": True,
        },
    }


def app_management_url(config: GitHubAppConfig) -> str:
    """Where this App's owner edits its permissions/webhook event
    subscriptions -- GitHub has no API for that, only this settings page
    (see connect-github-card.tsx's "Manage on GitHub" link). Organization-
    owned Apps live under a different URL shape than personal ones
    (``manifest_data``'s own ``org`` param decides which one an App is
    created as); guessing personal-only 404s for an org-owned App."""
    if config.owner_type == "Organization" and config.owner_login:
        return f"https://github.com/organizations/{config.owner_login}/settings/apps/{config.slug}"
    return f"https://github.com/settings/apps/{config.slug}"


def fetch_app_owner(config: GitHubAppConfig) -> tuple[str, str] | None:
    """GET /app (authenticated as the App itself via JWT) returns the App's
    owner login/type -- used to backfill GitHubAppConfig rows created before
    ``owner_login``/``owner_type`` existed. Returns None on any failure
    (network, revoked/rotated credentials, or a private_key_pem that can't
    sign a JWT at all -- e.g. a test fixture's placeholder string, not a
    real PEM); this is best-effort enrichment on a status read, not
    something that should break the page, so a failure here just means the
    "Manage on GitHub" link keeps guessing personal-account-owned until a
    later read succeeds. Broad `except Exception` deliberately: JWT signing
    failures aren't httpx errors, and nothing here should ever 500 a status
    read (same reasoning as this module's other best-effort GitHub API
    calls, e.g. app.core.ingestion's SIEM/Jira sends)."""
    try:
        app_jwt = generate_app_jwt(config)
        res = httpx.get(
            "https://api.github.com/app",
            headers={"Authorization": f"Bearer {app_jwt}", "Accept": "application/vnd.github+json"},
            timeout=15,
        )
        res.raise_for_status()
        owner = res.json().get("owner") or {}
        login, owner_type = owner.get("login"), owner.get("type")
        return (login, owner_type) if login and owner_type else None
    except Exception:
        return None


def generate_app_jwt(config: GitHubAppConfig) -> str:
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 9 * 60, "iss": config.app_id}
    private_key_pem = decrypt_secret(config.private_key_pem)
    return jwt.encode(payload, private_key_pem, algorithm="RS256")


def get_installation_token(config: GitHubAppConfig, installation_id: int) -> str:
    app_jwt = generate_app_jwt(config)
    res = httpx.post(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        headers={"Authorization": f"Bearer {app_jwt}", "Accept": "application/vnd.github+json"},
        timeout=15,
    )
    res.raise_for_status()
    return res.json()["token"]


def list_installation_repos(installation_token: str) -> list[dict]:
    repos = []
    page = 1
    while True:
        res = httpx.get(
            "https://api.github.com/installation/repositories",
            headers={"Authorization": f"Bearer {installation_token}", "Accept": "application/vnd.github+json"},
            params={"per_page": 100, "page": page},
            timeout=15,
        )
        res.raise_for_status()
        data = res.json()
        repos.extend(data.get("repositories", []))
        if len(data.get("repositories", [])) < 100:
            break
        page += 1
    return repos


def get_installation_account(config: GitHubAppConfig, installation_id: int) -> dict:
    app_jwt = generate_app_jwt(config)
    res = httpx.get(
        f"https://api.github.com/app/installations/{installation_id}",
        headers={"Authorization": f"Bearer {app_jwt}", "Accept": "application/vnd.github+json"},
        timeout=15,
    )
    res.raise_for_status()
    return res.json()


# --- Multi-App / multi-install resolution (#34) ----------------------------
#
# Before #34 every call site assumed exactly one GitHubAppConfig row and one
# GitHubInstallation row (`select(...).first()`), which broke in two ways:
#   (a) there was no way to select *which* App to use once more than one
#       existed (dev App vs prod App, or different Apps per install target);
#   (b) even installations of a *single* App were broken beyond the first
#       one, repo sync and PR Guardrail token minting always used
#       whichever installation happened to be row #1, silently ignoring
#       every other real installation.
# The helpers below replace every such lookup with a real resolution: an
# installation always knows which App minted it (github_app_config_id), and
# the right installation for a given repo is chosen by matching the repo's
# GitHub owner/org against the candidate installations' account_login.


def resolve_config_for_installation(session: Session, installation: GitHubInstallation) -> GitHubAppConfig | None:
    """Which GitHubAppConfig owns this installation (needed to sign the JWT
    that mints an installation access token).

    (#506) An unlinked (legacy) installation now resolves in workspace-
    aware order: prefer a config scoped to the installation's own
    workspace, then the platform-level default (workspace_id is None),
    and only fall back to the pre-#506 "exactly one config total" guess
    when neither resolves -- keeps an existing single-App deployment
    working unchanged while a multi-App, multi-workspace one resolves
    correctly instead of picking arbitrarily."""
    if installation.github_app_config_id is not None:
        return session.get(GitHubAppConfig, installation.github_app_config_id)
    # Legacy installation row created before github_app_config_id existed.
    # Only safe to guess when a candidate set is unambiguous (exactly one
    # match); with more than one, which App is "the" right one is a real
    # unknown, not a 50/50 the code should pick for the caller.
    configs = session.exec(select(GitHubAppConfig)).all()
    workspace_matches = [c for c in configs if c.workspace_id == installation.workspace_id]
    if len(workspace_matches) == 1:
        return workspace_matches[0]
    if workspace_matches:
        # Ambiguous within the installation's own workspace: falling
        # through to the platform default here would hand this
        # installation credentials from an App that doesn't own it, not a
        # safer guess than the workspace-scoped ambiguity itself.
        return None
    platform_defaults = [c for c in configs if c.workspace_id is None]
    if len(platform_defaults) == 1:
        return platform_defaults[0]
    return configs[0] if len(configs) == 1 else None


def resolve_installation_for_repo(session: Session, workspace_id: int, repo_slug: str) -> GitHubInstallation | None:
    """Pick the installation that actually has access to ``repo_slug``
    (``owner/repo``) among all installations in the target's workspace, by
    matching the repo's owner against each installation's account_login.
    Falls back to the workspace's only installation when there's just one,
    or the repo owner can't be parsed."""
    installations = session.exec(select(GitHubInstallation).where(GitHubInstallation.workspace_id == workspace_id)).all()
    if not installations:
        return None
    owner = repo_slug.split("/")[0] if "/" in repo_slug else None
    if owner:
        for installation in installations:
            if installation.account_login.lower() == owner.lower():
                return installation
    return installations[0]


def target_has_pr_guardrail_coverage(session: Session, target: Target, backend_url: str) -> bool:
    """Whether server-side PR Guardrail actually scans `target`'s PRs today
    -- not just whether the infrastructure *could* work in general.

    webhook_reachable(backend_url) alone is necessary but not sufficient,
    and treating it as sufficient (#245's original double-scan fix) was
    itself a bug: it would block or skip Pipeline Integration for a target
    whose webhook path doesn't actually work, leaving that target with
    *zero* PR scanning coverage from either path -- worse than the
    original double-scan problem this exists to prevent. Three more real
    gaps checked here, each independently able to mean "the webhook fires
    but nothing scans this target's PRs":

      - No GitHub App installation resolves for this target's repo at all
        (a manually-added target, or one whose org was never actually
        installed on).
      - That installation's App has no webhook_secret configured yet
        (app/api/webhooks.py's _verify_signature rejects every delivery
        with a 401 until one is set -- connect-github-card.tsx's own "No
        webhook secret set" warning is this exact state).
      - The target's own *effective* enforcement_mode (inherited from its
        group(s)/workspace, see app.core.enforcement) resolves to
        "disabled" -- PR Guardrail is explicitly turned off for this
        target specifically, regardless of whether the webhook plumbing
        underneath it works.

    Imports enforcement/github lazily to avoid a circular import: neither
    currently imports this module, but this function is reachable from
    app.tasks.pipeline_tasks (a Celery task module) and keeping the
    dependency direction explicit here, not assumed, matches how
    webhook_reachable's own docstring already reasons about this module's
    callers.
    """
    from app.core.enforcement import resolve_enforcement_mode_with_source
    from app.core.github import repo_slug_from_url

    if not webhook_reachable(backend_url):
        return False

    slug = repo_slug_from_url(target.repo_url)
    installation = resolve_installation_for_repo(session, target.workspace_id, slug)
    if not installation:
        return False
    config = resolve_config_for_installation(session, installation)
    if not config or not config.webhook_secret:
        return False

    mode, _source = resolve_enforcement_mode_with_source(session, target)
    if mode == "disabled":
        return False

    return True
