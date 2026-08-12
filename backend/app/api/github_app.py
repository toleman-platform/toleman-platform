import secrets

import httpx
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.auth import current_user
from app.api.deps import get_session
from app.core.crypto import encrypt_secret
from app.core.github_app import (
    build_manifest,
    get_installation_account,
    get_installation_token,
    list_installation_repos,
)
from app.models.models import GitHubAppConfig, GitHubInstallation, Organization, Target, Workspace

FRONTEND_URL = "http://localhost:3000"
BACKEND_URL = "http://localhost:8000"

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
    manifest = build_manifest(FRONTEND_URL, BACKEND_URL, suffix)
    state = secrets.token_urlsafe(24)
    _pending_states.add(state)
    base = f"https://github.com/organizations/{org}/settings/apps/new" if org else "https://github.com/settings/apps/new"
    return {"manifest": manifest, "post_url": f"{base}?state={state}"}


@router.get("/status")
def status(session: Session = Depends(get_session)):
    config = session.exec(select(GitHubAppConfig)).first()
    installation = session.exec(select(GitHubInstallation)).first()
    return {
        "app_configured": config is not None,
        "app_slug": config.slug if config else None,
        "installed": installation is not None,
        "account_login": installation.account_login if installation else None,
        "webhook_secret_set": bool(config and config.webhook_secret),
    }


class UpdateWebhookSecretRequest(BaseModel):
    webhook_secret: str


@router.patch("/webhook-secret")
def update_webhook_secret(payload: UpdateWebhookSecretRequest, session: Session = Depends(get_session)):
    """Pairs with the webhook secret set manually in the App's GitHub settings
    page (Settings > Developer settings > GitHub Apps > <app> > Webhook) -
    there's no API to configure a GitHub App's webhook URL/secret post-creation,
    only the Settings UI, so this just needs to match what's entered there."""
    config = session.exec(select(GitHubAppConfig)).first()
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
    )
    session.add(config)
    session.commit()

    return RedirectResponse(f"https://github.com/apps/{config.slug}/installations/new")


@public_router.get("/setup-callback")
def setup_callback(installation_id: int, setup_action: str | None = None, session: Session = Depends(get_session)):
    """GitHub redirects here after the app is installed on an account/org. Unauthenticated
    by necessity (GitHub calls this directly) - installation_id is GitHub-issued and only
    usable together with our app's private key, so there's nothing forgeable to gate here."""
    config = session.exec(select(GitHubAppConfig)).first()
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
        ))
        session.commit()

    _sync_repos(session)
    return RedirectResponse(f"{FRONTEND_URL}/targets?connected=1")


def _sync_repos(session: Session) -> int:
    config = session.exec(select(GitHubAppConfig)).first()
    installation = session.exec(select(GitHubInstallation)).first()
    if not config or not installation:
        return 0

    token = get_installation_token(config, installation.installation_id)
    repos = list_installation_repos(token)

    existing_urls = {t.repo_url for t in session.exec(select(Target)).all()}
    created = 0
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
        created += 1
    session.commit()
    return created


@router.post("/sync")
def sync_now(session: Session = Depends(get_session)):
    created = _sync_repos(session)
    return {"created": created}
