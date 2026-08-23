"""`GET`/`PUT /api/tools/assignments` -- per-workspace, per-tool usage
assignment (issue #75): on-demand scan / CI pipeline / API scan / PR
guardrail, backed by WorkspaceToolConfig.

Read is workspace-scoped via accessible_workspace_ids like every other GET/
list endpoint over workspace-owned resources; write is gated at
SECURITY_ENGINEER-or-admin, same trust level as SlaRule/PolicyRule -- which
scanners run where is a security-policy decision, not general repo
housekeeping.
"""
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.auth import accessible_workspace_ids, current_user, enforce_workspace_role
from app.api.deps import get_session
from app.core.tool_registry import TOOL_REGISTRY, USAGE_SURFACES, default_usage_for
from app.models.models import User, WorkspaceRole, WorkspaceToolConfig

router = APIRouter()


class ToolAssignmentOut(BaseModel):
    tool: str
    on_demand_scan: bool
    ci_pipeline: bool
    api_scan: bool
    pr_guardrail: bool
    is_default: bool


class UpsertAssignmentRequest(BaseModel):
    workspace_id: int
    tool: str
    on_demand_scan: bool
    ci_pipeline: bool
    api_scan: bool
    pr_guardrail: bool


@router.get("/assignments", response_model=list[ToolAssignmentOut])
def list_assignments(
    workspace_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Per-tool usage assignment for a workspace (issue #75) -- one row per
    registered tool, real saved WorkspaceToolConfig where one exists, else
    the tool's built-in default (`is_default: true` distinguishes the two
    for the UI, e.g. to show "not customized" vs. an explicit save)."""
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and workspace_id not in ws_ids:
        raise HTTPException(status_code=404, detail="workspace not found")

    saved = {
        c.tool: c
        for c in session.exec(
            select(WorkspaceToolConfig).where(WorkspaceToolConfig.workspace_id == workspace_id)
        ).all()
    }

    out = []
    for entry in TOOL_REGISTRY:
        tool = entry["tool"]
        cfg = saved.get(tool)
        if cfg:
            out.append(ToolAssignmentOut(
                tool=tool,
                on_demand_scan=cfg.on_demand_scan,
                ci_pipeline=cfg.ci_pipeline,
                api_scan=cfg.api_scan,
                pr_guardrail=cfg.pr_guardrail,
                is_default=False,
            ))
        else:
            defaults = default_usage_for(tool)
            out.append(ToolAssignmentOut(tool=tool, is_default=True, **defaults))
    return out


@router.put("/assignments", response_model=ToolAssignmentOut)
def upsert_assignment(
    payload: UpsertAssignmentRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    if payload.tool not in {e["tool"] for e in TOOL_REGISTRY}:
        raise HTTPException(status_code=422, detail=f"unknown tool: {payload.tool!r}")

    # workspace_id lives inside the JSON body -- same reason
    # sla_rules.create_sla_rule checks explicitly instead of a
    # Depends-based require_workspace_role.
    enforce_workspace_role(session, user, WorkspaceRole.SECURITY_ENGINEER, workspace_id=payload.workspace_id)

    cfg = session.exec(
        select(WorkspaceToolConfig).where(
            WorkspaceToolConfig.workspace_id == payload.workspace_id,
            WorkspaceToolConfig.tool == payload.tool,
        )
    ).first()
    if not cfg:
        cfg = WorkspaceToolConfig(workspace_id=payload.workspace_id, tool=payload.tool)

    for surface in USAGE_SURFACES:
        setattr(cfg, surface, getattr(payload, surface))
    cfg.updated_at = datetime.now(UTC).replace(tzinfo=None)

    session.add(cfg)
    session.commit()
    session.refresh(cfg)

    return ToolAssignmentOut(
        tool=cfg.tool,
        on_demand_scan=cfg.on_demand_scan,
        ci_pipeline=cfg.ci_pipeline,
        api_scan=cfg.api_scan,
        pr_guardrail=cfg.pr_guardrail,
        is_default=False,
    )
