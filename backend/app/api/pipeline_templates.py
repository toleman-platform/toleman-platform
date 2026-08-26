"""Custom Workflow Builder (issue #35, part of the "Mass CI/CD Rollout
Engine + Custom Workflow Builder" item): workspace-scoped CRUD for
`PipelineWorkflowTemplate` rows -- a named, ordered, enable/disable step
list over #66's fixed scanner catalog (semgrep/gitleaks/trivy/gosec),
consumed by `app.core.pipeline_workflow.generate_workflow_yaml` and picked
by id at mass-rollout time (`POST /api/targets/mass-pipeline-rollout`, see
app/api/targets.py).

Same workspace-scoping + role-gating shape as app/api/groups.py (#61):
GET is workspace-filtered via `accessible_workspace_ids`, writes require at
least DEVELOPER on the owning workspace via `enforce_workspace_role` -- the
same bar #66/#68 already apply to actually opening pipeline-integration
PRs, since a template only matters in service of that action.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlmodel import Session, select

from app.api.auth import accessible_workspace_ids, current_user, enforce_workspace_role
from app.api.deps import get_session
from app.core.pipeline_workflow import SUPPORTED_TOOLS
from app.core.time import utcnow
from app.models.models import PipelineWorkflowTemplate, User, WorkspaceRole

router = APIRouter(prefix="/api/pipeline-templates", tags=["pipeline-templates"])


class StepIn(BaseModel):
    tool: str
    enabled: bool = True

    @field_validator("tool")
    @classmethod
    def _check_tool(cls, v: str) -> str:
        if v not in SUPPORTED_TOOLS:
            raise ValueError(f"tool must be one of {SUPPORTED_TOOLS}")
        return v


def _validate_steps(steps: list[StepIn]) -> list[dict]:
    if not steps:
        raise HTTPException(status_code=400, detail="steps must not be empty")
    if not any(s.enabled for s in steps):
        raise HTTPException(status_code=400, detail="at least one step must be enabled")
    seen = set()
    for s in steps:
        if s.tool in seen:
            raise HTTPException(status_code=400, detail=f"duplicate step for tool '{s.tool}'")
        seen.add(s.tool)
    return [s.model_dump() for s in steps]


class CreateTemplateRequest(BaseModel):
    workspace_id: int
    name: str
    steps: list[StepIn]


class UpdateTemplateRequest(BaseModel):
    name: str | None = None
    steps: list[StepIn] | None = None


def _get_template_scoped(session: Session, user: User, template_id: int) -> PipelineWorkflowTemplate:
    template = session.get(PipelineWorkflowTemplate, template_id)
    if not template:
        raise HTTPException(status_code=404, detail="pipeline workflow template not found")
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and template.workspace_id not in ws_ids:
        # Same 404-shaped hiding used throughout this codebase for
        # cross-workspace access rather than a 403 that confirms existence.
        raise HTTPException(status_code=404, detail="pipeline workflow template not found")
    return template


@router.get("")
def list_templates(
    workspace_id: int | None = None,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return []
    query = select(PipelineWorkflowTemplate)
    if workspace_id is not None:
        if ws_ids is not None and workspace_id not in ws_ids:
            return []
        query = query.where(PipelineWorkflowTemplate.workspace_id == workspace_id)
    elif ws_ids is not None:
        query = query.where(PipelineWorkflowTemplate.workspace_id.in_(ws_ids))
    return session.exec(query.order_by(PipelineWorkflowTemplate.name)).all()


@router.get("/{template_id}")
def get_template(template_id: int, session: Session = Depends(get_session), user: User = Depends(current_user)):
    return _get_template_scoped(session, user, template_id)


@router.post("")
def create_template(
    payload: CreateTemplateRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    # enforce_workspace_role raises 403 itself if the caller lacks DEVELOPER+
    # on payload.workspace_id (or the workspace doesn't exist / isn't
    # accessible) -- same bar as #66's single-target pipeline-integrate.
    enforce_workspace_role(session, user, WorkspaceRole.DEVELOPER, workspace_id=payload.workspace_id)
    steps = _validate_steps(payload.steps)
    template = PipelineWorkflowTemplate(
        workspace_id=payload.workspace_id,
        name=payload.name,
        steps=steps,
        created_by_user_id=user.id,
    )
    session.add(template)
    session.commit()
    session.refresh(template)
    return template


@router.patch("/{template_id}")
def update_template(
    template_id: int,
    payload: UpdateTemplateRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    from datetime import UTC, datetime

    template = _get_template_scoped(session, user, template_id)
    enforce_workspace_role(session, user, WorkspaceRole.DEVELOPER, workspace_id=template.workspace_id)
    if payload.name is not None:
        template.name = payload.name
    if payload.steps is not None:
        template.steps = _validate_steps(payload.steps)
    template.updated_at = utcnow()
    session.add(template)
    session.commit()
    session.refresh(template)
    return template


@router.delete("/{template_id}")
def delete_template(template_id: int, session: Session = Depends(get_session), user: User = Depends(current_user)):
    template = _get_template_scoped(session, user, template_id)
    enforce_workspace_role(session, user, WorkspaceRole.DEVELOPER, workspace_id=template.workspace_id)
    session.delete(template)
    session.commit()
    return {"deleted": True}
