import secrets

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlmodel import Session, select

from app.api.deps import get_session
from app.api.auth import accessible_workspace_ids, current_user, require_admin, require_workspace_role
from app.core.enforcement import VALID_ENFORCEMENT_MODES
from app.models.models import Organization, User, Workspace, WorkspaceRole

router = APIRouter(prefix="/api/workspaces", tags=["workspaces"])


class UpdateWorkspaceRequest(BaseModel):
    # PR Guardrail enforcement mode override (issue #62), the workspace-level
    # fallback below any group/target override. Explicit null clears it,
    # falling back to the hardcoded "block" default (see app.core.enforcement).
    enforcement_mode: str | None = None
    # Display name (issue #224: the new Workspaces page lets a workspace be
    # renamed, previously set once at bootstrap and never editable).
    name: str | None = None

    @field_validator("enforcement_mode")
    @classmethod
    def _check_enforcement_mode(cls, v: str | None) -> str | None:
        if v is not None and v not in VALID_ENFORCEMENT_MODES:
            raise ValueError(f"enforcement_mode must be one of {sorted(VALID_ENFORCEMENT_MODES)} or null")
        return v

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: str | None) -> str | None:
        if v is not None and not v.strip():
            raise ValueError("name must not be blank")
        return v.strip() if v is not None else v


@router.get("")
def list_workspaces(session: Session = Depends(get_session), user: User = Depends(current_user)):
    """Workspaces the caller can see (issue #32: the admin workspace-role UI
    needs the full list of *its own* workspaces, not just the ones a target
    happens to already exist under). Was unscoped (returned every
    workspace platform-wide to any authenticated user, including other
    tenants' workspace names and ids) until #224 added a dedicated
    Workspaces management page that surfaces this list directly instead of
    it only feeding an admin dropdown; accessible_workspace_ids() is the
    same tenant-isolation helper every other workspace-owned list route
    uses."""
    ws_ids = accessible_workspace_ids(session, user)
    # Explicit order (issue #224): without it, Postgres is free to return
    # rows in a different order after any UPDATE touches one of them (e.g.
    # renaming a workspace); the new Workspaces page's "selected" row is
    # keyed by id, not position, but the useWorkspacePicker hook's default
    # selection falls back to whichever workspace lands first when no
    # explicit choice has been made yet, so an unstable order could make
    # the picker silently jump to a different workspace right after a
    # rename.
    query = select(Workspace).order_by(Workspace.id)
    if ws_ids is not None:
        if not ws_ids:
            return []
        query = query.where(Workspace.id.in_(ws_ids))
    return session.exec(query).all()


@router.patch("/{workspace_id}")
def update_workspace(
    workspace_id: int,
    payload: UpdateWorkspaceRequest,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    """Partial update for workspace-level settings (issue #62's
    enforcement_mode fallback today; follows the same exclude_unset PATCH
    shape as PATCH /api/targets/{id} and PATCH /api/groups/{id})."""
    workspace = session.get(Workspace, workspace_id)
    if not workspace:
        raise HTTPException(status_code=404, detail="workspace not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(workspace, field, value)
    session.add(workspace)
    session.commit()
    session.refresh(workspace)
    return workspace


@router.get("/{workspace_id}/key")
def get_workspace_key(
    workspace_id: int, session: Session = Depends(get_session), user: User = Depends(current_user)
):
    """Workspace-id-keyed equivalent of GET /api/targets/{id}/workspace-key
    (issue #224): the new Workspaces management page looks up a workspace's
    CI-ingestion API key directly by workspace id, rather than proxying
    through whichever target happens to be selected in a picker."""
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and workspace_id not in ws_ids:
        raise HTTPException(status_code=404, detail="workspace not found")
    workspace = session.get(Workspace, workspace_id)
    if not workspace:
        raise HTTPException(status_code=404, detail="workspace not found")
    return {"workspace_id": workspace.id, "workspace_name": workspace.name, "api_key": workspace.api_key}


@router.post("/{workspace_id}/key/regenerate")
def regenerate_workspace_key_by_id(
    workspace_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    """Workspace-id-keyed equivalent of POST
    /api/targets/{id}/workspace-key/regenerate, same DEVELOPER bar, same
    in-place overwrite with no grace period (see that route's docstring)."""
    workspace = session.get(Workspace, workspace_id)
    if not workspace:
        raise HTTPException(status_code=404, detail="workspace not found")
    workspace.api_key = secrets.token_urlsafe(24)
    session.add(workspace)
    session.commit()
    session.refresh(workspace)
    return {"workspace_id": workspace.id, "workspace_name": workspace.name, "api_key": workspace.api_key}


@router.post("/bootstrap")
def bootstrap(
    org_name: str,
    workspace_name: str,
    session: Session = Depends(get_session),
    _admin: User = Depends(require_admin),
):
    """Local/dev helper to create an Org + Workspace + API key without a full auth flow.

    Creating a brand-new org/workspace (and its API key) is a platform-level
    action, not something scoped to any particular workspace, so this is
    gated to the global admin role (issue #56); not a workspace-scoped
    role from #32's WorkspaceMembership/roles model, layered on top of the
    router's existing login_required so /api/workspaces (list) stays
    reachable by any logged-in user.
    """
    org = session.exec(select(Organization).where(Organization.name == org_name)).first()
    if not org:
        org = Organization(name=org_name)
        session.add(org)
        session.commit()
        session.refresh(org)

    ws = session.exec(select(Workspace).where(Workspace.name == workspace_name, Workspace.organization_id == org.id)).first()
    if not ws:
        ws = Workspace(organization_id=org.id, name=workspace_name, api_key=secrets.token_urlsafe(24))
        session.add(ws)
        session.commit()
        session.refresh(ws)

    return ws
