import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlmodel import Session, select

from app.api.auth import accessible_workspace_ids, current_user, enforce_workspace_role, require_workspace_role
from app.api.deps import get_session
from app.models.models import Group, Target, TargetGroup, User, Workspace, WorkspaceRole

router = APIRouter(prefix="/api/targets", tags=["targets"])

# Scan execution clones this URL and runs local tools against the checkout, so
# an unrestricted repo_url is an SSRF / local-file-read primitive (file://,
# internal hosts, cloud metadata IPs). Only allow real GitHub HTTPS clone URLs.
_ALLOWED_REPO_URL = re.compile(r"^https://github\.com/[\w.\-]+/[\w.\-]+(\.git)?/?$")


def _validate_repo_url(url: str) -> str:
    if not _ALLOWED_REPO_URL.match(url):
        raise HTTPException(status_code=400, detail="repo_url must be an https://github.com/<org>/<repo> URL")
    return url


class CreateTargetRequest(BaseModel):
    workspace_id: int
    name: str
    repo_url: str
    default_branch: str = "main"
    label: str = "Dev"
    criticality_weight: int = 1

    @field_validator("repo_url")
    @classmethod
    def _check_repo_url(cls, v: str) -> str:
        return _validate_repo_url(v)


class UpdateTargetRequest(BaseModel):
    name: str | None = None
    default_branch: str | None = None
    label: str | None = None
    criticality_weight: int | None = None


def _groups_by_target(session: Session, target_ids: list[int]) -> dict[int, list[dict]]:
    """Batch-load {target_id: [{id, name, color}, ...]} for embedding group
    badges in target list/detail responses (issue #61), one query instead of
    N+1 per target."""
    if not target_ids:
        return {}
    rows = session.exec(
        select(TargetGroup.target_id, Group)
        .join(Group, Group.id == TargetGroup.group_id)
        .where(TargetGroup.target_id.in_(target_ids))
    ).all()
    out: dict[int, list[dict]] = {tid: [] for tid in target_ids}
    for target_id, group in rows:
        out.setdefault(target_id, []).append({"id": group.id, "name": group.name, "color": group.color})
    return out


def _with_groups(target: Target, groups_by_target: dict[int, list[dict]]) -> dict:
    return {**target.model_dump(), "groups": groups_by_target.get(target.id, [])}


@router.get("")
def list_targets(
    group_id: int | None = None,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    # Issue #57: scope to workspaces the caller is a member of (None = admin,
    # no filter; [] = no memberships yet -> empty list, not everything).
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return []
    query = select(Target)
    if ws_ids is not None:
        query = query.where(Target.workspace_id.in_(ws_ids))
    if group_id is not None:
        # Issue #61: filter to targets carrying this group -- storage with no
        # way to actually query by it would be a foundation nobody can use.
        query = query.join(TargetGroup, TargetGroup.target_id == Target.id).where(TargetGroup.group_id == group_id)
    targets = session.exec(query).all()
    groups_by_target = _groups_by_target(session, [t.id for t in targets])
    return [_with_groups(t, groups_by_target) for t in targets]


@router.post("")
def create_target(
    payload: CreateTargetRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    # workspace_id lives inside the JSON body here, not a path/query param,
    # so require_workspace_role's name-binding trick can't see it -- check
    # explicitly instead (see enforce_workspace_role's docstring).
    enforce_workspace_role(session, user, WorkspaceRole.DEVELOPER, workspace_id=payload.workspace_id)
    target = Target(**payload.model_dump())
    session.add(target)
    session.commit()
    session.refresh(target)
    return target


@router.get("/{target_id}")
def get_target(target_id: int, session: Session = Depends(get_session), user: User = Depends(current_user)):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and target.workspace_id not in ws_ids:
        # 404 rather than 403 to avoid confirming the target exists in a
        # workspace the caller can't see (matches the "not found" wording
        # already used across this codebase for missing resources).
        raise HTTPException(status_code=404, detail="target not found")
    groups_by_target = _groups_by_target(session, [target.id])
    return _with_groups(target, groups_by_target)


@router.patch("/{target_id}")
def update_target(
    target_id: int,
    payload: UpdateTargetRequest,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(target, field, value)
    session.add(target)
    session.commit()
    session.refresh(target)
    return target


@router.get("/{target_id}/workspace-key")
def get_workspace_key(target_id: int, session: Session = Depends(get_session), user: User = Depends(current_user)):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    # Issue #57: this returns the workspace's api_key, so an unscoped check
    # here is worse than the plain read IDOR on the other routes -- it leaks
    # another workspace's secret, not just its data.
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and target.workspace_id not in ws_ids:
        raise HTTPException(status_code=404, detail="target not found")
    workspace = session.get(Workspace, target.workspace_id)
    return {"workspace_id": workspace.id, "workspace_name": workspace.name, "api_key": workspace.api_key}


@router.get("/{target_id}/groups")
def list_target_groups(target_id: int, session: Session = Depends(get_session), user: User = Depends(current_user)):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and target.workspace_id not in ws_ids:
        raise HTTPException(status_code=404, detail="target not found")
    return _groups_by_target(session, [target_id]).get(target_id, [])


@router.post("/{target_id}/groups/{group_id}")
def assign_target_group(
    target_id: int,
    group_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    group = session.get(Group, group_id)
    if not group:
        raise HTTPException(status_code=404, detail="group not found")
    if group.workspace_id != target.workspace_id:
        # A group only makes sense scoped to the same workspace its targets
        # live in -- otherwise a caller with developer access to workspace A
        # could tag a workspace-B target with a workspace-A group, leaking
        # naming/existence across the workspace boundary #57 exists to draw.
        raise HTTPException(status_code=400, detail="group and target must belong to the same workspace")
    existing = session.exec(
        select(TargetGroup).where(TargetGroup.target_id == target_id, TargetGroup.group_id == group_id)
    ).first()
    if not existing:
        session.add(TargetGroup(target_id=target_id, group_id=group_id))
        session.commit()
    return _groups_by_target(session, [target_id]).get(target_id, [])


@router.delete("/{target_id}/groups/{group_id}")
def remove_target_group(
    target_id: int,
    group_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    link = session.exec(
        select(TargetGroup).where(TargetGroup.target_id == target_id, TargetGroup.group_id == group_id)
    ).first()
    if link:
        session.delete(link)
        session.commit()
    return _groups_by_target(session, [target_id]).get(target_id, [])
