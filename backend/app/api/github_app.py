import secrets

import httpx
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from app.api.auth import accessible_workspace_ids, current_user, enforce_workspace_role, require_admin
from app.api.deps import get_session
from app.core.config import settings
from app.core.crypto import encrypt_secret
from app.core.github_app import (
    app_management_url,
    build_manifest,
    fetch_app_owner,
    get_installation_account,
    get_installation_token,
    list_installation_repos,
    resolve_config_for_installation,
    webhook_reachable,
)
from app.models.models import GitHubAppConfig, GitHubInstallation, Organization, Target, User, Workspace, WorkspaceRole
from app.core import target_lifecycle
from app.tasks.sbom_tasks import queue_dependency_graph_sync
from app.tasks.scan_tasks import queue_full_scan

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
#
# (#506) Also carries the workspace_id (if any) the App being created should
# be scoped to, so /callback can set it on the row it creates -- None means
# the platform-level default App, same meaning as
# GitHubAppConfig.workspace_id itself.
_pending_states: dict[str, int | None] = {}

router = APIRouter(prefix="/api/github-app", tags=["github-app"], dependencies=[Depends(current_user)])
public_router = APIRouter(prefix="/api/github-app", tags=["github-app"])


def _require_app_config_manager(session: Session, user: User, config: GitHubAppConfig) -> None:
    """(#506) Platform-default config (workspace_id is None) stays
    require_admin-only, the same gate every write here had before this
    issue. A workspace-scoped config is managed by that workspace's
    security-engineer-or-higher members -- enforce_workspace_role's own
    global-admin bypass still applies, so a platform admin can always
    manage either kind. There is no separate WorkspaceRole.ADMIN on this
    platform; SECURITY_ENGINEER (the top per-workspace rank) is the
    existing precedent for "workspace admin"-class actions (fp_rules.py,
    scoring_weights.py, scan_schedules.py, sla_rules.py all gate the same
    way)."""
    if config.workspace_id is None:
        if user.role != "admin":
            raise HTTPException(status_code=403, detail="admin role required")
        return
    enforce_workspace_role(session, user, WorkspaceRole.SECURITY_ENGINEER, workspace_id=config.workspace_id)


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


def _workspace_for_new_installation(session: Session, config: GitHubAppConfig) -> Workspace:
    """(#506) A fresh install of a workspace-scoped App belongs to that
    workspace, not "whichever workspace happens to be first in the table"
    -- _get_or_create_workspace's original single-tenant assumption, kept
    here as the fallback for the platform-default App (workspace_id is
    None) and for a config whose workspace has since been deleted."""
    if config.workspace_id is not None:
        workspace = session.get(Workspace, config.workspace_id)
        if workspace:
            return workspace
    return _get_or_create_workspace(session)


@router.get("/manifest-data")
def manifest_data(
    org: str | None = None,
    # (#506) Present -> registering a workspace-scoped App, gated to that
    # workspace's security engineers; absent -> the platform-level default
    # App, admin-only. Every existing caller (pre-#506, always omitted this)
    # keeps getting the admin-only platform-default App.
    workspace_id: int | None = None,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Frontend uses this to build the hidden form it POSTs to GitHub. Requires login."""
    if workspace_id is not None:
        enforce_workspace_role(session, user, WorkspaceRole.SECURITY_ENGINEER, workspace_id=workspace_id)
    elif user.role != "admin":
        raise HTTPException(status_code=403, detail="admin role required")
    suffix = secrets.token_hex(3)
    state = secrets.token_urlsafe(24)
    _pending_states[state] = workspace_id
    # `state` doubles as the App's permanent setup_token (#34); see
    # build_manifest's docstring for why this is safe and durable.
    manifest = build_manifest(FRONTEND_URL, BACKEND_URL, suffix, setup_token=state)
    base = f"https://github.com/organizations/{org}/settings/apps/new" if org else "https://github.com/settings/apps/new"

    return {
        "manifest": manifest,
        "post_url": f"{base}?state={state}",
        "webhook_url": manifest["hook_attributes"]["url"],
        # (#355) The frontend reads this from /status now, because it has
        # to warn before any App exists and without minting a state token
        # per page load. Still reported here so anyone POSTing this
        # manifest to GitHub by hand (or any other API client) gets the
        # same answer about whether GitHub will accept it; this endpoint
        # deliberately still returns a complete, submittable manifest, the
        # rejection it would earn is GitHub's to give.
        "webhook_reachable": webhook_reachable(BACKEND_URL),
    }


@router.get("/status")
def status(session: Session = Depends(get_session), user: User = Depends(current_user)):
    """Multi-App aware (#34): returns every registered App and its
    installations under ``apps``, plus the original single-app fields
    (first configured app / first installation) for back-compat with
    existing callers that only care "is anything connected".

    Also carries ``webhook_reachable``/``public_api_url`` (#355), which are
    about the App that does *not* exist yet: whether creating one can work
    at all from this deployment's address. See the return block below.

    (#506) Filtered to the platform-default App plus configs/installations
    in the caller's accessible workspaces -- previously this returned every
    App platform-wide, including another workspace's webhook_secret_set
    state and installation account, to any authenticated viewer."""
    ws_ids = accessible_workspace_ids(session, user)
    configs = session.exec(select(GitHubAppConfig)).all()
    installations = session.exec(select(GitHubInstallation)).all()
    if ws_ids is not None:
        configs = [c for c in configs if c.workspace_id is None or c.workspace_id in ws_ids]
        installations = [i for i in installations if i.workspace_id in ws_ids]

    # (#506 follow-up) So the Integrations card can label each App by its
    # scope -- "Platform default" vs. a specific workspace's name -- instead
    # of the caller having to already know which workspace_id maps to which
    # workspace.
    config_workspace_ids = {c.workspace_id for c in configs if c.workspace_id is not None}
    workspace_names = {
        w.id: w.name
        for w in session.exec(select(Workspace).where(Workspace.id.in_(config_workspace_ids))).all()
    } if config_workspace_ids else {}

    apps = []
    for config in configs:
        # Backfill for GitHubAppConfig rows created before owner_login/
        # owner_type existed (see their docstring) -- without this,
        # app_management_url below guesses "personal account" for an
        # org-owned App and 404s.
        if config.owner_login is None:
            owner = fetch_app_owner(config)
            if owner:
                config.owner_login, config.owner_type = owner
                session.add(config)
                session.commit()

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
            "manage_url": app_management_url(config),
            "webhook_secret_set": bool(config.webhook_secret),
            "workspace_id": config.workspace_id,
            "workspace_name": workspace_names.get(config.workspace_id) if config.workspace_id is not None else None,
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
        # (#355) Everything the Integrations card needs to decide, before
        # any App exists, whether "Connect GitHub" can succeed at all: a
        # localhost PUBLIC_API_URL means GitHub rejects the manifest and
        # creates nothing (see webhook_reachable's docstring). This has to
        # ride on /status rather than /manifest-data, which is where the
        # frontend read it before, for two reasons: /status is what the
        # card loads on mount whether or not any App exists (the old
        # warning rendered only next to already-created Apps, so a fresh
        # install -- the only install that hits this -- never saw it), and
        # /manifest-data mints a CSRF state token into _pending_states on
        # every call, which is not something a page load should do just to
        # render a warning.
        #
        # public_api_url is echoed so the warning can name the offending
        # value instead of telling the operator to go and find it.
        "webhook_reachable": webhook_reachable(BACKEND_URL),
        "public_api_url": BACKEND_URL,
    }


class UpdateWebhookSecretRequest(BaseModel):
    webhook_secret: str
    config_id: int | None = None


@router.patch("/webhook-secret")
def update_webhook_secret(
    payload: UpdateWebhookSecretRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Pairs with the webhook secret set manually in the App's GitHub settings
    page (Settings > Developer settings > GitHub Apps > <app> > Webhook) -
    there's no API to configure a GitHub App's webhook URL/secret post-creation,
    only the Settings UI, so this just needs to match what's entered there.

    ``config_id`` selects which App (#34: there may be more than one); when
    omitted it only succeeds if exactly one App is configured, matching the
    original single-App behavior.

    (#506) Gated by _require_app_config_manager -- previously any
    authenticated user, of any role, could rotate the platform's single
    webhook secret."""
    if payload.config_id is not None:
        config = session.get(GitHubAppConfig, payload.config_id)
    else:
        configs = session.exec(select(GitHubAppConfig)).all()
        if len(configs) > 1:
            raise HTTPException(status_code=400, detail="multiple GitHub Apps configured, config_id is required")
        config = configs[0] if configs else None
    if not config:
        raise HTTPException(status_code=400, detail="GitHub App not configured yet")
    _require_app_config_manager(session, user, config)
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
    workspace_id = _pending_states.pop(state)

    res = httpx.post(
        f"https://api.github.com/app-manifests/{code}/conversions",
        headers={"Accept": "application/vnd.github+json"},
        timeout=15,
    )
    res.raise_for_status()
    data = res.json()

    owner = data.get("owner") or {}
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
        # Which account owns this App -- see GitHubAppConfig.owner_login's
        # docstring for why "Manage on GitHub" needs this.
        owner_login=owner.get("login"),
        owner_type=owner.get("type"),
        # (#506) None -> platform-level default App, same as every App
        # created before this column existed.
        workspace_id=workspace_id,
    )
    session.add(config)
    try:
        session.commit()
    except IntegrityError:
        # (#506) Two concurrent manifest flows for the same scope (the same
        # workspace, or both for the platform default) -- the DB's
        # partial-unique indexes on githubappconfig.workspace_id catch what
        # a race between this request's own `add` and `commit` let through.
        # GitHub already created a real App on its side for this attempt
        # (the manifest-conversion POST above already happened); there is
        # nothing to undo there, so the best recovery is to say so plainly
        # rather than 500 on a raw constraint violation the operator can't
        # act on.
        session.rollback()
        scope = "workspace" if workspace_id is not None else "platform-default"
        return RedirectResponse(f"{FRONTEND_URL}/targets?error=app_already_registered&scope={scope}")

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
        workspace = _workspace_for_new_installation(session, config)
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
    # (#273) Soft-deleted targets are deliberately NOT part of the
    # already-imported set. The dead row still holds that repo_url, so
    # counting it would mean a repository someone deleted could never be
    # re-imported: the sync would skip it forever while the operator saw
    # nothing appear and no error explaining why. Excluding it lets the repo
    # come back as a fresh target (new id, clean history) while the old row
    # and its findings stay put for the audit trail. Deactivated targets DO
    # count as existing -- they weren't removed, they're just switched off,
    # and re-importing would create a confusing duplicate.
    existing_urls = {
        t.repo_url for t in session.exec(target_lifecycle.live_targets(select(Target))).all()
    }
    created = 0
    new_targets: list[Target] = []
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
            target = Target(
                workspace_id=installation.workspace_id,
                name=repo["name"],
                repo_url=clone_url,
                default_branch=repo.get("default_branch", "main"),
                label="Prod" if not repo.get("private") else "Internal",
                criticality_weight=2,
            )
            session.add(target)
            new_targets.append(target)
            existing_urls.add(clone_url)
            created += 1
    session.commit()
    # (#330) Queue the Dependency Graph import for each newly imported repo,
    # after the commit that gives the rows their ids. Async on purpose: an
    # org with hundreds of repos would otherwise hold the App install
    # callback open for hundreds of sequential GitHub calls.
    #
    # queue_dependency_graph_sync commits once per target; expire_on_commit
    # (on by default) would otherwise expire every other Target still
    # waiting in new_targets after each of those commits, turning a large
    # import into a SELECT per remaining target just to re-read attributes
    # this loop already has in memory.
    #
    # GH-07: also queue a full scan of the default branch here, same reason
    # and same async-dispatch shape. Without this, a freshly-synced repo sat
    # with no completed Scan at all until someone happened to click Scan on
    # it -- "no baseline yet" was correct but permanent, and every PR against
    # it kept getting PR Guardrail's honest-but-useless non-answer instead of
    # a real diff. queue_full_scan also commits per target/tool; same
    # expire_on_commit guard applies.
    session.expire_on_commit = False
    try:
        for target in new_targets:
            queue_dependency_graph_sync(session, target)
            queue_full_scan(session, target)
    finally:
        session.expire_on_commit = True
    return created


@router.post("/sync")
def sync_now(session: Session = Depends(get_session), user: User = Depends(require_admin)):
    """Manually re-run the same installation-repos sync the
    installation_repositories webhook triggers automatically (#456).

    Admin-only: this had no auth dependency at all before, and _sync_repos
    iterates every GitHubInstallation platform-wide -- any authenticated
    user could create Target rows and queue scans across every workspace
    with an installation, regardless of their own membership anywhere.
    Matches the platform-default App's existing admin-only bar (see
    delete_app_config's docstring) since this action is platform-wide, not
    scoped to one workspace's App.
    """
    created = _sync_repos(session)
    return {"created": created}


@router.delete("/{config_id}")
def delete_app_config(
    config_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Removes a registered GitHub App and any installation rows tied to it.

    Gated by _require_app_config_manager: the platform-default App stays
    admin-only (this route's original blanket gate), but a workspace's
    security-engineer-or-higher members can now remove their own
    workspace-scoped App without needing global admin (#506). Does not
    revoke or uninstall the App on GitHub's side -- that still has to
    happen in GitHub's own settings -- this only clears Toleman's record of
    it, so a stale or misconfigured App can be removed and re-registered
    instead of accumulating dead rows forever.
    """
    config = session.get(GitHubAppConfig, config_id)
    if not config:
        raise HTTPException(status_code=404, detail="GitHub App not found")
    _require_app_config_manager(session, user, config)
    installations = session.exec(
        select(GitHubInstallation).where(GitHubInstallation.github_app_config_id == config_id)
    ).all()
    for installation in installations:
        session.delete(installation)
    session.delete(config)
    session.commit()
    return {"ok": True}
