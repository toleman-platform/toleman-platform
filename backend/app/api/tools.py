"""Tool marketplace / health page (issue #75).

Extends the original Sprint 1 `GET /health` (which only checked the four
already-integrated scanners) with:
  - `GET /registry`: every OSS tool Rikugan knows about (see
    app.core.tool_registry.TOOL_REGISTRY), each merged with a real
    version/health check the same way `/health` always has -- not a static
    "supported" list divorced from what's actually on this host.
  - `GET /assignments` / `PUT /assignments`: per-workspace, per-tool usage
    assignment (on-demand scan / CI pipeline / API scan / PR guardrail),
    backed by WorkspaceToolConfig. Read is workspace-scoped via
    accessible_workspace_ids like every other GET/list endpoint over
    workspace-owned resources; write is gated at SECURITY_ENGINEER-or-admin,
    same trust level as SlaRule/PolicyRule -- which scanners run where is a
    security-policy decision, not general repo housekeeping.

Deliberately does NOT add a literal "install this tool" endpoint that
shells out to a package manager from a web request -- see
app.core.tool_registry's module docstring for why that's treated as a
human-check-in item rather than auto-implemented.
"""
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.auth import accessible_workspace_ids, current_user, enforce_workspace_role
from app.api.deps import get_session
from app.core.tool_registry import TOOL_REGISTRY, USAGE_SURFACES, default_usage_for, registry_with_integration_status
from app.models.models import User, WorkspaceRole, WorkspaceToolConfig

router = APIRouter(prefix="/api/tools", tags=["tools"])

# Kept for backwards compatibility with the original Sprint 1 /health shape
# (frontend's existing ToolsHealth component + any external caller relying
# on it) -- /registry below supersedes it for the new marketplace page but
# there's no reason to break this one.
VERSION_COMMANDS = {
    "semgrep": ["semgrep", "--version"],
    "gitleaks": ["gitleaks", "version"],
    "trivy": ["trivy", "--version"],
    "gosec": ["gosec", "--version"],
}


def _check_one(tool: str, cmd: list[str]) -> dict:
    binary_path = shutil.which(cmd[0])
    if not binary_path:
        return {"tool": tool, "installed": False, "version": None, "response_ms": None}

    start = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        elapsed_ms = round((time.monotonic() - start) * 1000)
        output = (proc.stdout or proc.stderr).strip().splitlines()
        version = output[0] if output else "unknown"
        return {"tool": tool, "installed": True, "version": version, "response_ms": elapsed_ms}
    except (subprocess.TimeoutExpired, OSError):
        return {"tool": tool, "installed": True, "version": None, "response_ms": None}


@router.get("/health")
def tools_health():
    """Real version + reachability check for each of the 4 originally
    integrated scanners -- no simulated status. See /registry for the full
    tool marketplace (issue #75), which includes this same live check for
    every registered tool, not just these four."""
    return [_check_one(tool, cmd) for tool, cmd in VERSION_COMMANDS.items()]


@router.get("/registry")
def tools_registry():
    """Full tool marketplace registry (issue #75): every supported OSS
    security tool across SAST/SCA/Secrets/Container/IaC/License/AI-ML, each
    merged with a real live health check (subprocess `--version`, exactly
    like /health) and an `integrated` flag (whether Rikugan can actually
    dispatch a scan for it today via app.scanners.runner.TOOL_COMMANDS)."""
    entries = registry_with_integration_status()
    # Issue #187: the checks run concurrently rather than in sequence. They
    # are independent blocking `--version` subprocesses, so serial cost was
    # their sum rather than their max.
    #
    # Measured on a dev box, serial: semgrep 2061ms, trivy 111ms,
    # trivy-license 107ms, gosec 71ms, gitleaks 21ms = 2371ms total.
    # `semgrep --version` dominates because it pays full Python interpreter
    # startup, and that is the real cost of this endpoint -- parallelising
    # takes it to roughly max() instead of sum(), about 2.37s -> 2.06s.
    # A modest win today, and it stops the endpoint degrading linearly as
    # the registry grows.
    #
    # Note the five AI/ML entries added in this issue cost essentially
    # nothing: _check_one short-circuits on shutil.which() before spawning
    # anything, so an uninstalled tool is a path lookup, not a process.
    # Thread pool rather than async because subprocess.run blocks.
    with ThreadPoolExecutor(max_workers=min(16, len(entries) or 1)) as pool:
        healths = list(pool.map(lambda e: _check_one(e["tool"], e["version_cmd"]), entries))
    return [{**entry, **health} for entry, health in zip(entries, healths)]


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

    from datetime import datetime

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
    cfg.updated_at = datetime.utcnow()

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
