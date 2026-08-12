import secrets

import httpx
from fastapi import APIRouter, Depends
from fastapi.responses import RedirectResponse
from sqlmodel import Session, select

from app.api.deps import get_session
from app.core.github_app import (
    build_manifest,
    get_installation_account,
    get_installation_token,
    list_installation_repos,
)
from app.models.models import GitHubAppConfig, GitHubInstallation, Organization, Target, Workspace

router = APIRouter(prefix="/api/github-app", tags=["github-app"])

FRONTEND_URL = "http://localhost:3000"
BACKEND_URL = "http://localhost:8000"


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
    """Frontend uses this to build the hidden form it POSTs to GitHub."""
    suffix = secrets.token_hex(3)
    manifest = build_manifest(FRONTEND_URL, BACKEND_URL, suffix)
    target = f"https://github.com/organizations/{org}/settings/apps/new" if org else "https://github.com/settings/apps/new"
    return {"manifest": manifest, "post_url": target}


@router.get("/status")
def status(session: Session = Depends(get_session)):
    config = session.exec(select(GitHubAppConfig)).first()
    installation = session.exec(select(GitHubInstallation)).first()
    return {
        "app_configured": config is not None,
        "app_slug": config.slug if config else None,
        "installed": installation is not None,
        "account_login": installation.account_login if installation else None,
    }


@router.get("/callback")
def callback(code: str, session: Session = Depends(get_session)):
    """GitHub redirects here after the manifest form is submitted, with a one-time code."""
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
        client_secret=data["client_secret"],
        private_key_pem=data["pem"],
        webhook_secret=data.get("webhook_secret") or "",
        html_url=data["html_url"],
    )
    session.add(config)
    session.commit()

    return RedirectResponse(f"https://github.com/apps/{config.slug}/installations/new")


@router.get("/setup-callback")
def setup_callback(installation_id: int, setup_action: str | None = None, session: Session = Depends(get_session)):
    """GitHub redirects here after the app is installed on an account/org."""
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
