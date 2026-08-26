import secrets
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.auth import current_user
from app.api.deps import get_session
from app.core.config import settings
from app.core.crypto import encrypt_secret
from app.core.github_app import (
    build_manifest,
    get_installation_account,
    get_installation_token,
    list_installation_repos,
    resolve_config_for_installation,
)
from app.models.models import GitHubAppConfig, GitHubInstallation, Organization, Target, Workspace

# GH-02: were hardcoded localhost literals. The manifest's callback/webhook
# URLs are handed to GitHub, so on any real deployment they must be an
# address GitHub's servers can actually resolve; a localhost value there
# silently produces an App that can never call back.
FRONTEND_URL = settings.public_base_url.rstrip("/")
BACKEND_URL = settings.public_api_url.rstrip("/")

# CSRF-binding for the manifest flow: state issued in /manifest-data must come
# back on /callback before we trust the code exchange. In-memory is fine for
# this single-process dev/OSS deployment; a multi-worker production deploy
# would need this in Redis/DB instead (module state isn't shared across workers).
_pending_states: set[str] = set()

router = APIRouter(prefix="/api/github-app", tags=["github-app"], dependencies=[Depends(current_user)])
public_router = APIRouter(prefix="/api/github-app", tags=["github-app"])


def _get_or_create_workspace(session: Session) -> Workspace:
    workspace = session.exec(select(Workspace)).first()
    if workspace:
        return workspace
    org = Organization(name="default")
    session.add(org)
    session.commit()
    session.refresh(org)
    workspace = Workspace(organization_id=org.id, name="default", api_key=secrets.token_urlsafe(24))
    session.add(workspace)
    session.commit()
    session.refresh(workspace)
    return workspace


@router.get("/manifest-data")
def manifest_data(org: str | None = None):
    """Frontend uses this to build the hidden form it POSTs to GitHub. Requires login."""
    suffix = secrets.token_hex(3)
    state = secrets.token_urlsafe(24)
    _pending_states.add(state)
    # `state` doubles as the App's permanent setup_token (#34); see
    # build_manifest's docstring for why this is safe and durable.
    manifest = build_manifest(FRONTEND_URL, BACKEND_URL, suffix, setup_token=state)
    base = f"https://github.com/organizations/{org}/settings/apps/new" if org else "https://github.com/settings/apps/new"

    # (GH-03) The App now subscribes to pull_request, so PR Guardrail runs
    # automatically; but only if GitHub can reach this backend. A localhost
    # PUBLIC_API_URL creates an App whose webhook deliveries silently never
    # arrive, which looks identical to "the scanner isn't finding anything".
    #
    # Surfaced rather than blocked: creating the App is still worth doing
    # while a tunnel or domain is being set up, since on-demand scanning
    # works regardless. The UI shows this next to the Connect button.
    parsed = urlparse(BACKEND_URL)
    webhook_reachable = (parsed.hostname or "") not in ("localhost", "127.0.0.1", "::1", "0.0.0.0")

    return {
        "manifest": manifest,
        "post_url": f"{base}?state={state}",
        "webhook_url": manifest["hook_attributes"]["url"],
        "webhook_reachable": webhook_reachable,
    }


@router.get("/status")
def status(session: Session = Depends(get_session)):
    """Multi-App aware (#34): returns every registered App and its
    installations under ``apps``, plus the original single-app fields
    (first configured app / first installation) for back-compat with
    existing callers that only care "is anything connected"."""
    configs = session.exec(select(GitHubAppConfig)).all()
    installations = session.exec(select(GitHubInstallation)).all()

    apps = []
    for config in configs:
        config_installations = [
            i for i in installations
            if i.github_app_config_id == config.id
            or (i.github_app_config_id is None and len(configs) == 1)
        ]
        apps.append({
            "id": config.id,
            "app_id": config.app_id,
            "app_slug": config.slug,
            "html_url": config.html_url,
            "webhook_secret_set": bool(config.webhook_secret),
            "installations": [
                {
                    "installation_id": i.installation_id,
                    "account_login": i.account_login,
                    "account_type": i.account_type,
                }
                for i in config_installations
            ],
        })

    return {
        "apps": apps,
        "app_configured": bool(configs),
        "app_slug": configs[0].slug if configs else None,
        "installed": bool(installations),
        "account_login": installations[0].account_login if installations else None,
        "webhook_secret_set": bool(configs and configs[0].webhook_secret),
    }


class UpdateWebhookSecretRequest(BaseModel):
    webhook_secret: str
    config_id: int | None = None


@router.patch("/webhook-secret")
def update_webhook_secret(payload: UpdateWebhookSecretRequest, session: Session = Depends(get_session)):
    """Pairs with the webhook secret set manually in the App's GitHub settings
    page (Settings > Developer settings > GitHub Apps > <app> > Webhook) -
    there's no API to configure a GitHub App's webhook URL/secret post-creation,
    only the Settings UI, so this just needs to match what's entered there.

    ``config_id`` selects which App (#34: there may be more than one); when
    omitted it only succeeds if exactly one App is configured, matching the
    original single-App behavior."""
    if payload.config_id is not None:
        config = session.get(GitHubAppConfig, payload.config_id)
    else:
        configs = session.exec(select(GitHubAppConfig)).all()
        if len(configs) > 1:
            raise HTTPException(status_code=400, detail="multiple GitHub Apps configured, config_id is required")
        config = configs[0] if configs else None
    if not config:
        raise HTTPException(status_code=400, detail="GitHub App not configured yet")
    config.webhook_secret = encrypt_secret(payload.webhook_secret)
    session.add(config)
    session.commit()
    return {"webhook_secret_set": bool(payload.webhook_secret)}


@public_router.get("/callback")
def callback(code: str, state: str | None = None, session: Session = Depends(get_session)):
    """GitHub redirects here after the manifest form is submitted, with a one-time code.

    Unauthenticated by necessity (GitHub, not our frontend, calls this) - the
    `state` param round-tripped from /manifest-data is what proves this request
    traces back to a login session that initiated the flow, not a forged one.
    """
    if not state or state not in _pending_states:
        raise HTTPException(status_code=400, detail="missing or invalid state")
    _pending_states.discard(state)

    res = httpx.post(
        f"https://api.github.com/app-manifests/{code}/conversions",
        headers={"Accept": "application/vnd.github+json"},
        timeout=15,
    )
    res.raise_for_status()
    data = res.json()

    config = GitHubAppConfig(
        app_id=str(data["id"]),
        slug=data["slug"],
        client_id=data["client_id"],
        client_secret=encrypt_secret(data["client_secret"]),
        private_key_pem=encrypt_secret(data["pem"]),
        webhook_secret=encrypt_secret(data.get("webhook_secret") or ""),
        html_url=data["html_url"],
        # Same token used above to CSRF-bind /callback, reused permanently as
        # this App's setup_token so /setup-callback can resolve back to this
        # exact row (#34) every time this App is installed/reconfigured.
        setup_token=state,
    )
    session.add(config)
    session.commit()

    return RedirectResponse(f"https://github.com/apps/{config.slug}/installations/new")


@public_router.get("/setup-callback")
def setup_callback(
    installation_id: int,
    setup_action: str | None = None,
    cfg: str | None = None,
    session: Session = Depends(get_session),
):
    """GitHub redirects here after the app is installed on an account/org. Unauthenticated
    by necessity (GitHub calls this directly) - installation_id is GitHub-issued and only
    usable together with our app's private key, so there's nothing forgeable to gate here.

    ``cfg`` (#34) is the setup_token baked into this specific App's
    setup_url at creation time, so multiple registered Apps each route back
    to their own GitHubAppConfig row instead of assuming there's only one.
    Falls back to "the only configured App" when ``cfg`` is absent/unmatched;
    covers Apps registered before this column existed, whose setup_url on
    GitHub's side has no ``?cfg=`` param and can't be changed after the fact
    without hitting GitHub's App-update API.
    """
    config = None
    if cfg:
        config = session.exec(select(GitHubAppConfig).where(GitHubAppConfig.setup_token == cfg)).first()
    if not config:
        configs = session.exec(select(GitHubAppConfig)).all()
        if len(configs) == 1:
            config = configs[0]
    if not config:
        return RedirectResponse(f"{FRONTEND_URL}/targets?error=app_not_configured")

    account = get_installation_account(config, installation_id)
    existing = session.exec(select(GitHubInstallation).where(GitHubInstallation.installation_id == installation_id)).first()
    if not existing:
        workspace = _get_or_create_workspace(session)
        session.add(GitHubInstallation(
            installation_id=installation_id,
            account_login=account["account"]["login"],
            account_type=account["account"]["type"],
            workspace_id=workspace.id,
            github_app_config_id=config.id,
        ))
        session.commit()
    elif existing.github_app_config_id is None:
        # Backfill a legacy installation row created before this FK existed.
        existing.github_app_config_id = config.id
        session.add(existing)
        session.commit()

    _sync_repos(session)
    return RedirectResponse(f"{FRONTEND_URL}/targets?connected=1")


def _sync_repos(session: Session) -> int:
    """Sync repos for EVERY installation of EVERY registered App (#34);
    previously only the first GitHubInstallation row was ever synced, so a
    platform with more than one real installation (app installed on a second
    org/account, or a second App entirely) silently never saw that
    installation's repos at all."""
    installations = session.exec(select(GitHubInstallation)).all()
    existing_urls = {t.repo_url for t in session.exec(select(Target)).all()}
    created = 0
    for installation in installations:
        config = resolve_config_for_installation(session, installation)
        if not config:
            continue
        token = get_installation_token(config, installation.installation_id)
        repos = list_installation_repos(token)
        for repo in repos:
            clone_url = repo["clone_url"]
            if clone_url in existing_urls:
                continue
            session.add(Target(
                workspace_id=installation.workspace_id,
                name=repo["name"],
                repo_url=clone_url,
                default_branch=repo.get("default_branch", "main"),
                label="Prod" if not repo.get("private") else "Internal",
                criticality_weight=2,
            ))
            existing_urls.add(clone_url)
            created += 1
    session.commit()
    return created


@router.post("/sync")
def sync_now(session: Session = Depends(get_session)):
    created = _sync_repos(session)
    return {"created": created}
