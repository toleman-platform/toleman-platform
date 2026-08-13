import secrets

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlmodel import Session, select

from app.api.deps import get_session
from app.api.auth import require_admin, require_workspace_role
from app.core.enforcement import VALID_ENFORCEMENT_MODES
from app.models.models import Organization, User, Workspace, WorkspaceRole

router = APIRouter(prefix="/api/workspaces", tags=["workspaces"])


class UpdateWorkspaceRequest(BaseModel):
    # PR Guardrail enforcement mode override (issue #62), the workspace-level
    # fallback below any group/target override. Explicit null clears it,
    # falling back to the hardcoded "block" default (see app.core.enforcement).
    enforcement_mode: str | None = None

    @field_validator("enforcement_mode")
    @classmethod
    def _check_enforcement_mode(cls, v: str | None) -> str | None:
        if v is not None and v not in VALID_ENFORCEMENT_MODES:
            raise ValueError(f"enforcement_mode must be one of {sorted(VALID_ENFORCEMENT_MODES)} or null")
        return v


@router.get("")
def list_workspaces(session: Session = Depends(get_session)):
    """All workspaces (issue #32: the admin workspace-role UI needs the full
    list, not just the ones a target happens to already exist under, since
    this app is no longer assumed single-workspace)."""
    return session.exec(select(Workspace)).all()


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
    gated to the global admin role (issue #56) -- not a workspace-scoped
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
