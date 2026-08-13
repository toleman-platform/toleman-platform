"""Group CRUD (issue #61): workspace-scoped tags/groups ("production",
"PCI-scope", "internal-tool", ...) for organizing Targets at scale. This is
the foundation for group-level policy (#62) and group-level SLA (#70) --
this issue only covers create/list/update/delete of Group rows and reading
which workspace they belong to. Target<->Group assignment lives in
app/api/targets.py (POST/DELETE /api/targets/{id}/groups/{group_id}) since
those routes are naturally scoped by target_id, mirroring how this codebase
already nests workspace-scoped sub-resources under their parent resource's
router (see pr_guardrail.router's findings/ignore routes under target-scoped
scans).
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlmodel import Session, select

from app.api.auth import accessible_workspace_ids, current_user, enforce_workspace_role
from app.api.deps import get_session
from app.core.enforcement import VALID_ENFORCEMENT_MODES
from app.models.models import Group, TargetGroup, User, WorkspaceRole

router = APIRouter(prefix="/api/groups", tags=["groups"])


class CreateGroupRequest(BaseModel):
    workspace_id: int
    name: str
    color: str = "#6366f1"


class UpdateGroupRequest(BaseModel):
    name: str | None = None
    color: str | None = None
    # PR Guardrail enforcement mode override (issue #62) for every target
    # carrying this group. Explicit null clears the override.
    enforcement_mode: str | None = None

    @field_validator("enforcement_mode")
    @classmethod
    def _check_enforcement_mode(cls, v: str | None) -> str | None:
        if v is not None and v not in VALID_ENFORCEMENT_MODES:
            raise ValueError(f"enforcement_mode must be one of {sorted(VALID_ENFORCEMENT_MODES)} or null")
        return v


@router.get("")
def list_groups(
    workspace_id: int | None = None,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    # Same workspace-scoping shape as GET /api/targets (issue #57):
    # ws_ids is None for a global admin (no filter), [] for a caller with no
    # memberships (empty list, not everything).
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return []
    query = select(Group)
    if workspace_id is not None:
        if ws_ids is not None and workspace_id not in ws_ids:
            return []
        query = query.where(Group.workspace_id == workspace_id)
    elif ws_ids is not None:
        query = query.where(Group.workspace_id.in_(ws_ids))
    return session.exec(query.order_by(Group.name)).all()


@router.post("")
def create_group(
    payload: CreateGroupRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    # workspace_id lives inside the JSON body, not a path/query param, so
    # require_workspace_role's name-binding can't see it -- check explicitly
    # (same reason POST /api/targets does, see targets.py's create_target).
    enforce_workspace_role(session, user, WorkspaceRole.DEVELOPER, workspace_id=payload.workspace_id)
    group = Group(workspace_id=payload.workspace_id, name=payload.name, color=payload.color)
    session.add(group)
    session.commit()
    session.refresh(group)
    return group


@router.patch("/{group_id}")
def update_group(
    group_id: int,
    payload: UpdateGroupRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    group = session.get(Group, group_id)
    if not group:
        raise HTTPException(status_code=404, detail="group not found")
    enforce_workspace_role(session, user, WorkspaceRole.DEVELOPER, workspace_id=group.workspace_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(group, field, value)
    session.add(group)
    session.commit()
    session.refresh(group)
    return group


@router.delete("/{group_id}")
def delete_group(
    group_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    group = session.get(Group, group_id)
    if not group:
        raise HTTPException(status_code=404, detail="group not found")
    enforce_workspace_role(session, user, WorkspaceRole.DEVELOPER, workspace_id=group.workspace_id)
    # Hard-delete along with its assignments -- unlike PolicyRule this isn't
    # an audit-relevant record, it's pure organizational metadata, so there's
    # no soft-delete/active flag to preserve.
    memberships = session.exec(select(TargetGroup).where(TargetGroup.group_id == group_id)).all()
    for m in memberships:
        session.delete(m)
    session.delete(group)
    session.commit()
    return {"ok": True}
