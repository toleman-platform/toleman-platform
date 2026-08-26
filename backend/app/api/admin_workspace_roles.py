"""Admin management of per-workspace role assignments (issue #32).

Mounted under admin_required in app/main.py, same gate as
app/api/admin.py's user management; assigning who can do what inside a
workspace is itself an admin-only action, consistent with the rest of the
admin surface.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.deps import get_session
from app.models.models import User, Workspace, WorkspaceMembership, WorkspaceRole

router = APIRouter(prefix="/api/admin/workspace-roles", tags=["admin"])


class MembershipOut(BaseModel):
    id: int
    user_id: int
    user_email: str
    user_name: str
    workspace_id: int
    workspace_name: str
    role: WorkspaceRole


class AssignMembershipRequest(BaseModel):
    user_id: int
    workspace_id: int
    role: WorkspaceRole


def _out(m: WorkspaceMembership, user: User, workspace: Workspace) -> MembershipOut:
    return MembershipOut(
        id=m.id,
        user_id=m.user_id,
        user_email=user.email,
        user_name=user.name,
        workspace_id=m.workspace_id,
        workspace_name=workspace.name,
        role=m.role,
    )


@router.get("", response_model=list[MembershipOut])
def list_memberships(workspace_id: int | None = None, session: Session = Depends(get_session)):
    query = select(WorkspaceMembership)
    if workspace_id is not None:
        query = query.where(WorkspaceMembership.workspace_id == workspace_id)
    memberships = session.exec(query).all()

    users = {u.id: u for u in session.exec(select(User)).all()}
    workspaces = {w.id: w for w in session.exec(select(Workspace)).all()}

    out = []
    for m in memberships:
        user = users.get(m.user_id)
        workspace = workspaces.get(m.workspace_id)
        if not user or not workspace:
            continue  # stale row pointing at a deleted user/workspace
        out.append(_out(m, user, workspace))
    return out


@router.put("", response_model=MembershipOut)
def assign_membership(payload: AssignMembershipRequest, session: Session = Depends(get_session)):
    """Upsert: assigning a user a role for a workspace they're already a
    member of updates the existing row rather than creating a duplicate."""
    user = session.get(User, payload.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user not found")
    workspace = session.get(Workspace, payload.workspace_id)
    if not workspace:
        raise HTTPException(status_code=404, detail="workspace not found")

    membership = session.exec(
        select(WorkspaceMembership).where(
            WorkspaceMembership.user_id == payload.user_id,
            WorkspaceMembership.workspace_id == payload.workspace_id,
        )
    ).first()
    if membership:
        membership.role = payload.role
    else:
        membership = WorkspaceMembership(user_id=payload.user_id, workspace_id=payload.workspace_id, role=payload.role)
    session.add(membership)
    session.commit()
    session.refresh(membership)
    return _out(membership, user, workspace)


@router.delete("/{membership_id}")
def remove_membership(membership_id: int, session: Session = Depends(get_session)):
    membership = session.get(WorkspaceMembership, membership_id)
    if not membership:
        raise HTTPException(status_code=404, detail="membership not found")
    session.delete(membership)
    session.commit()
    return {"ok": True}
