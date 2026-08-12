import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlmodel import Session, select

from app.api.deps import get_session
from app.models.models import Target, Workspace

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


@router.get("")
def list_targets(session: Session = Depends(get_session)):
    return session.exec(select(Target)).all()


@router.post("")
def create_target(payload: CreateTargetRequest, session: Session = Depends(get_session)):
    target = Target(**payload.model_dump())
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
