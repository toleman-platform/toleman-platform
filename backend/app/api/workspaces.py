import secrets

from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from app.api.deps import get_session
from app.api.auth import require_admin
from app.models.models import Organization, User, Workspace

router = APIRouter(prefix="/api/workspaces", tags=["workspaces"])


@router.get("")
def list_workspaces(session: Session = Depends(get_session)):
    """All workspaces (issue #32: the admin workspace-role UI needs the full
    list, not just the ones a target happens to already exist under, since
    this app is no longer assumed single-workspace)."""
    return session.exec(select(Workspace)).all()


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
