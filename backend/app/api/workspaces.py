import secrets

from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from app.api.deps import get_session
from app.models.models import Organization, Workspace

router = APIRouter(prefix="/api/workspaces", tags=["workspaces"])


@router.post("/bootstrap")
def bootstrap(org_name: str, workspace_name: str, session: Session = Depends(get_session)):
    """Local/dev helper to create an Org + Workspace + API key without a full auth flow."""
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
