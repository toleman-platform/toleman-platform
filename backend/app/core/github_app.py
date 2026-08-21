import time

import httpx
import jwt
from sqlmodel import Session, select

from app.core.crypto import decrypt_secret
from app.models.models import GitHubAppConfig, GitHubInstallation


def build_manifest(app_url: str, backend_url: str, name_suffix: str, setup_token: str) -> dict:
    """GitHub App Manifest — https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest

    Permissions mirror the architecture doc's Integration & Permissions Matrix:
    contents (clone + commit fixes), pull_requests + statuses (PR Guardrail),
    workflows (issue #66: Pipeline Integration writes files under
    .github/workflows/), metadata read-only (mandatory baseline).

    ``workflows: write`` is required in addition to ``contents: write`` for
    any Contents-API write under ``.github/workflows/`` -- GitHub gates that
    path behind its own separate permission scope regardless of the App's
    general contents access (confirmed live: without it, PUT
    /repos/{owner}/{repo}/contents/.github/workflows/<file> 403s with
    "Resource not accessible by integration" even though creating the
    backing branch via POST git/refs succeeds fine on contents:write alone).
    An App installed before this permission existed needs its installation
    owner to re-approve the updated permission set in GitHub's UI --
    ``setup_on_update: True`` below prompts that on next install/reconfigure,
    but doesn't retroactively grant it to installations that don't revisit
    that flow.

    ``setup_url`` carries ``?cfg=<setup_token>`` baked in at manifest-creation
    time (#34: multi-App support). ``setup_url`` is a fixed property of the
    App once created via the manifest conversion — GitHub calls exactly this
    URL (appending its own ``installation_id``/``setup_action`` params) every
    time *this* App is installed/reconfigured, for the life of the App, so
    the token reliably tells /setup-callback which GitHubAppConfig row a new
    installation belongs to without needing to guess or brute-force it.
    """
    return {
        # (GH-05) "Rikugan", not the pre-rename "OSP DevSecOps". This string
        # is the product's signature on every pull request in an adopting
        # org: GitHub derives the bot login from it, so the old name shipped
        # as `osp-devsecops-*[bot]` on every PR comment. Cosmetic internally,
        # not cosmetic externally.
        #
        # Only affects Apps created from here on -- an App's name is fixed at
        # creation, so an existing installation keeps its old bot login until
        # its owner renames it in GitHub's own App settings.
        "name": f"Rikugan DevSecOps {name_suffix}",
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
        },
        # (GH-03) Subscribe to pull_request so blocking mode is actually
        # automatic. This was `[]` with no hook_attributes, so the App
        # subscribed to nothing: a human had to open PR History and press
        # "Scan This PR" for anything to happen. An external review put it
        # exactly right -- "blocking mode" that depends on someone
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
        # backend_url must be reachable *from GitHub* -- see
        # settings.public_api_url. A localhost value produces an App whose
        # deliveries can never arrive; build_manifest's caller warns about
        # that rather than failing, since creating the App is still useful
        # for on-demand scanning while a tunnel/domain is set up.
        "default_events": ["pull_request"],
        "hook_attributes": {
            "url": f"{backend_url}/api/webhooks/github",
            "active": True,
        },
    }


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
#       one -- repo sync and PR Guardrail token minting always used
#       whichever installation happened to be row #1, silently ignoring
#       every other real installation.
# The helpers below replace every such lookup with a real resolution: an
# installation always knows which App minted it (github_app_config_id), and
# the right installation for a given repo is chosen by matching the repo's
# GitHub owner/org against the candidate installations' account_login.


def resolve_config_for_installation(session: Session, installation: GitHubInstallation) -> GitHubAppConfig | None:
    """Which GitHubAppConfig owns this installation (needed to sign the JWT
    that mints an installation access token)."""
    if installation.github_app_config_id is not None:
        return session.get(GitHubAppConfig, installation.github_app_config_id)
    # Legacy installation row created before github_app_config_id existed.
    # Only safe to guess when there's exactly one App configured -- with
    # multiple Apps an unlinked installation is genuinely ambiguous.
    configs = session.exec(select(GitHubAppConfig)).all()
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
