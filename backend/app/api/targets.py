from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.deps import get_session
from app.models.models import Target, Workspace

router = APIRouter(prefix="/api/targets", tags=["targets"])


class UpdateTargetRequest(BaseModel):
    name: str | None = None
    default_branch: str | None = None
    label: str | None = None
    criticality_weight: int | None = None


@router.get("")
def list_targets(session: Session = Depends(get_session)):
    return session.exec(select(Target)).all()


@router.post("")
def create_target(target: Target, session: Session = Depends(get_session)):
    session.add(target)
    session.commit()
    session.refresh(target)
    return target


@router.get("/{target_id}")
def get_target(target_id: int, session: Session = Depends(get_session)):
    return session.get(Target, target_id)


@router.patch("/{target_id}")
def update_target(target_id: int, payload: UpdateTargetRequest, session: Session = Depends(get_session)):
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
def get_workspace_key(target_id: int, session: Session = Depends(get_session)):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    workspace = session.get(Workspace, target.workspace_id)
    return {"workspace_id": workspace.id, "workspace_name": workspace.name, "api_key": workspace.api_key}
