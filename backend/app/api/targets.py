import re
import secrets
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from sqlmodel import Session, select

from app.api.auth import accessible_workspace_ids, current_user, enforce_workspace_role, require_workspace_role
from app.api.deps import get_session
from app.core.enforcement import VALID_ENFORCEMENT_MODES, resolve_enforcement_mode_with_source
from app.core.pipeline_pr import PipelinePrError, open_pipeline_pr
from app.core.pipeline_workflow import generate_workflow_yaml
from app.core.security_score import OPEN_STATES
from app.core.staleness import mark_stale_if_needed
from app.models.models import (
    WORKSPACE_ROLE_RANK,
    Finding,
    Group,
    PipelineIntegrationBatch,
    PipelineIntegrationBatchItem,
    PipelineWorkflowTemplate,
    Severity,
    Target,
    TargetGroup,
    User,
    Workspace,
    WorkspaceMembership,
    WorkspaceRole,
)
from app.tasks.pipeline_tasks import run_pipeline_integration_batch

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
    # PR Guardrail enforcement mode override (issue #62). Explicit null
    # clears the override (falls back to inheriting from the target's
    # group(s)/workspace) -- exclude_unset in update_target below means
    # simply omitting the field leaves the existing value untouched.
    enforcement_mode: str | None = None

    # Issue #72: the live base URL active API scanning combines with
    # already-discovered routes -- see Target.api_base_url's docstring in
    # app/models/models.py for why this is the only allowed source of a
    # scan target host. Explicit null clears it (same exclude_unset
    # semantics as enforcement_mode above).
    api_base_url: str | None = None

    @field_validator("enforcement_mode")
    @classmethod
    def _check_enforcement_mode(cls, v: str | None) -> str | None:
        if v is not None and v not in VALID_ENFORCEMENT_MODES:
            raise ValueError(f"enforcement_mode must be one of {sorted(VALID_ENFORCEMENT_MODES)} or null")
        return v

    @field_validator("api_base_url")
    @classmethod
    def _check_api_base_url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("api_base_url must be a real http(s):// URL with a host")
        return v


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


@router.get("/summary")
def targets_summary(
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Per-target open-finding counts for the Repo Sync inventory (#174),
    keyed by target_id (string, matching /api/scans/summary's convention so
    both summaries index the same way on the client).

    Repo Sync previously showed only a name, a clone URL and a bare
    `weight N`, so the page couldn't answer the one question it exists to
    answer -- which of these repos actually needs attention. This is the
    same default-branch + open-state scoping the Posture dashboard and the
    security score already use (app.core.security_score.OPEN_STATES), so the
    number here can't disagree with those surfaces.

    Declared before /{target_id} so "summary" isn't captured as a target id.
    One query for findings plus one for targets, not N+1.
    """
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return {}

    target_query = select(Target)
    if ws_ids is not None:
        target_query = target_query.where(Target.workspace_id.in_(ws_ids))
    targets = session.exec(target_query).all()
    if not targets:
        return {}

    default_branch_by_target = {t.id: t.default_branch for t in targets}
    finding_rows = session.exec(
        select(Finding.target_id, Finding.severity, Finding.branch).where(
            Finding.target_id.in_(list(default_branch_by_target.keys())),
            Finding.state.in_(OPEN_STATES),
        )
    ).all()

    summary: dict[int, dict] = {t.id: {"open": 0, "critical": 0, "high": 0} for t in targets}
    for target_id, severity, branch in finding_rows:
        if branch != default_branch_by_target.get(target_id):
            continue
        entry = summary[target_id]
        entry["open"] += 1
        if severity == Severity.CRITICAL:
            entry["critical"] += 1
        elif severity == Severity.HIGH:
            entry["high"] += 1

    return {str(target_id): counts for target_id, counts in summary.items()}


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
    out = _with_groups(target, groups_by_target)
    # Issue #62: surface the *effective* resolved enforcement mode (and
    # where it came from) alongside the target's own raw override, so the
    # frontend can show "Enforcement: Block (inherited from workspace)"
    # without re-implementing the resolution logic client-side.
    effective_mode, source = resolve_enforcement_mode_with_source(session, target)
    out["effective_enforcement_mode"] = effective_mode
    out["enforcement_mode_source"] = source
    return out


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


@router.post("/{target_id}/workspace-key/regenerate")
def regenerate_workspace_key(
    target_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    """Issue #129: the workspace API key (X-API-Key, used for CI push
    ingestion via /api/ingest/{target_id} -- see app.api.deps.require_workspace)
    had no rotation path at all. Rotating a CI-push-capable credential is at
    least as sensitive as the other workspace-settings writes gated at
    DEVELOPER (PATCH /api/targets/{id}, PATCH /api/workspaces/{id}) via
    require_workspace_role, so this matches that bar rather than inventing a
    new one -- require_workspace_role's dependency already resolves the
    workspace from this route's target_id path param.

    The old key is overwritten in place (not soft-revoked/kept around), so
    it stops authenticating against require_workspace (app/api/deps.py)
    immediately on commit -- no grace period, since none of the existing
    secret-rotation patterns in this codebase (e.g. session token_version
    bump on password change) leave a stale credential valid.
    """
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    workspace = session.get(Workspace, target.workspace_id)
    if not workspace:
        raise HTTPException(status_code=404, detail="workspace not found")
    workspace.api_key = secrets.token_urlsafe(24)
    session.add(workspace)
    session.commit()
    session.refresh(workspace)
    return {"workspace_id": workspace.id, "workspace_name": workspace.name, "api_key": workspace.api_key}


def _get_target_scoped(target_id: int, session: Session, user: User) -> Target:
    """404-not-403 workspace scoping, same pattern used throughout this
    file and app/api/pr_guardrail.py."""
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and target.workspace_id not in ws_ids:
        raise HTTPException(status_code=404, detail="target not found")
    return target


@router.get("/{target_id}/pipeline-workflow")
def get_pipeline_workflow(target_id: int, session: Session = Depends(get_session), user: User = Depends(current_user)):
    """Issue #66: real, target-specific GitHub Actions workflow YAML that
    runs Semgrep/Gitleaks/Trivy (+ gosec for Go repos, detected from this
    target's own scan history or, failing that, GitHub's languages API)
    natively in the runner and pushes results back to Rikugan via
    POST /api/ingest. Generation only -- doesn't write anything to GitHub;
    see POST .../pipeline-integrate for that."""
    target = _get_target_scoped(target_id, session, user)
    return generate_workflow_yaml(session, target)


@router.post("/{target_id}/pipeline-integrate")
def integrate_pipeline(
    target_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    """Issue #66: opens a real PR on the target's GitHub repo (via the
    GitHub App's installation token) adding the generated
    .github/workflows/rikugan-scan.yml, and records the outcome on the Target
    row so the frontend can show integration status without re-hitting
    GitHub every page load."""
    target = _get_target_scoped(target_id, session, user)
    try:
        result = open_pipeline_pr(session, target)
    except PipelinePrError as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    target.pipeline_integrated = True
    target.pipeline_pr_url = result["pr_url"]
    session.add(target)
    session.commit()
    session.refresh(target)
    return {
        "pipeline_integrated": target.pipeline_integrated,
        "pipeline_pr_url": target.pipeline_pr_url,
        "pr_number": result["pr_number"],
        "branch": result["branch"],
    }


class BulkPipelineIntegrateRequest(BaseModel):
    target_ids: list[int]


def _caller_can_integrate(session: Session, user: User, target: Target) -> bool:
    """Same bar as the single-target POST .../pipeline-integrate
    (require_workspace_role(DEVELOPER)), applied per-target here since a
    bulk selection can span multiple workspaces at once."""
    if user.role == "admin":
        return True
    membership = session.exec(
        select(WorkspaceMembership).where(
            WorkspaceMembership.user_id == user.id,
            WorkspaceMembership.workspace_id == target.workspace_id,
        )
    ).first()
    return bool(membership) and WORKSPACE_ROLE_RANK[membership.role] >= WORKSPACE_ROLE_RANK[WorkspaceRole.DEVELOPER]


@router.post("/bulk-pipeline-integrate")
def bulk_pipeline_integrate(
    payload: BulkPipelineIntegrateRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Issue #68: multi-select wrapper around #66's per-target pipeline
    integration. Accepts a list of target_ids, silently drops any the
    caller can't see or doesn't hold at least DEVELOPER on (same
    404-shaped hiding this file uses everywhere else -- see
    _get_target_scoped), and dispatches the rest as one Celery batch
    instead of blocking the request thread on N sequential real GitHub API
    calls (branch create + contents write + PR open per target, same
    "don't block the request thread" reasoning as #59's scan/discovery/sbom
    offload). Returns 202 with a batch_id to poll via
    GET /bulk-pipeline-integrate/{batch_id}.
    """
    if not payload.target_ids:
        raise HTTPException(status_code=400, detail="target_ids must not be empty")

    ws_ids = accessible_workspace_ids(session, user)
    unique_ids = list(dict.fromkeys(payload.target_ids))
    targets = session.exec(select(Target).where(Target.id.in_(unique_ids))).all()
    targets_by_id = {t.id: t for t in targets}

    eligible_ids: list[int] = []
    for tid in unique_ids:
        target = targets_by_id.get(tid)
        if not target:
            continue
        if ws_ids is not None and target.workspace_id not in ws_ids:
            continue
        if not _caller_can_integrate(session, user, target):
            continue
        eligible_ids.append(tid)

    if not eligible_ids:
        raise HTTPException(status_code=403, detail="no accessible targets with sufficient role in the selection")

    batch = PipelineIntegrationBatch(created_by_user_id=user.id, total=len(eligible_ids), status="running")
    session.add(batch)
    session.commit()
    session.refresh(batch)

    for tid in eligible_ids:
        session.add(PipelineIntegrationBatchItem(batch_id=batch.id, target_id=tid, status="pending"))
    session.commit()

    run_pipeline_integration_batch.delay(batch_id=batch.id)

    return JSONResponse(
        status_code=202,
        content={"batch_id": batch.id, "total": batch.total, "status": batch.status},
    )


@router.get("/bulk-pipeline-integrate/{batch_id}")
def get_bulk_pipeline_integrate_batch(
    batch_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Poll target for the async batch dispatched by POST above. Item
    detail is workspace-scoped the same way as everything else in this
    file -- items for targets outside the caller's accessible workspaces
    (relevant if role/membership changed after the batch was created) are
    left out of the returned items list."""
    batch = session.get(PipelineIntegrationBatch, batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="batch not found")
    mark_stale_if_needed(session, batch)

    ws_ids = accessible_workspace_ids(session, user)
    items = session.exec(
        select(PipelineIntegrationBatchItem).where(PipelineIntegrationBatchItem.batch_id == batch_id)
    ).all()
    target_ids = [i.target_id for i in items]
    targets_by_id = {t.id: t for t in session.exec(select(Target).where(Target.id.in_(target_ids))).all()}

    item_payload = []
    for item in items:
        target = targets_by_id.get(item.target_id)
        if target and ws_ids is not None and target.workspace_id not in ws_ids:
            continue
        item_payload.append(
            {
                "target_id": item.target_id,
                "target_name": target.name if target else None,
                "repo_url": target.repo_url if target else None,
                "status": item.status,
                "error": item.error,
                "pr_url": item.pr_url,
                "pr_number": item.pr_number,
                "completed_at": item.completed_at,
            }
        )

    return {
        "batch_id": batch.id,
        "status": batch.status,
        "total": batch.total,
        "succeeded": batch.succeeded,
        "failed": batch.failed,
        "already_integrated": batch.already_integrated,
        "started_at": batch.started_at,
        "completed_at": batch.completed_at,
        "items": item_payload,
        # "" for #68's original manual-selection batches; set for #35's
        # scope-based mass rollout (see mass_pipeline_rollout below).
        "scope_label": batch.scope_label,
        "workflow_template_id": batch.workflow_template_id,
    }


class MassPipelineRolloutRequest(BaseModel):
    """Issue #35 (Mass CI/CD Rollout Engine): resolve an entire *scope*
    (a workspace, a repo Group, or every repo the caller can see) into a
    target set instead of requiring an explicit checkbox selection like
    #68's bulk_pipeline_integrate above -- the "fleet-wide" part of the
    issue. `workflow_template_id` is the Custom Workflow Builder half:
    optionally use a saved PipelineWorkflowTemplate's step list instead of
    #66's fixed default scanner set for every item in this rollout."""

    scope: str
    workspace_id: int | None = None
    group_id: int | None = None
    workflow_template_id: int | None = None

    @field_validator("scope")
    @classmethod
    def _check_scope(cls, v: str) -> str:
        if v not in ("workspace", "group", "all"):
            raise ValueError("scope must be one of 'workspace', 'group', 'all'")
        return v


@router.post("/mass-pipeline-rollout")
def mass_pipeline_rollout(
    payload: MassPipelineRolloutRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Issue #35: scope-based sibling to #68's bulk_pipeline_integrate.
    Resolves `payload.scope` into a target_id set fleet-wide (instead of an
    explicit target_ids list), applies the exact same per-target
    eligibility bar as the manual bulk flow (_caller_can_integrate --
    DEVELOPER+ on the target's workspace), then reuses #68's
    PipelineIntegrationBatch/BatchItem tracking rows and
    run_pipeline_integration_batch Celery task verbatim -- the only new
    pieces are scope resolution and an optional workflow_template_id
    (Custom Workflow Builder) recorded on the batch so the task generates
    each item's YAML from that template's step list (see
    app.tasks.pipeline_tasks) instead of #66's fixed default set.
    """
    ws_ids = accessible_workspace_ids(session, user)

    if payload.scope == "workspace":
        if payload.workspace_id is None:
            raise HTTPException(status_code=400, detail="workspace_id is required for scope='workspace'")
        if ws_ids is not None and payload.workspace_id not in ws_ids:
            raise HTTPException(status_code=404, detail="workspace not found")
        workspace = session.get(Workspace, payload.workspace_id)
        if not workspace:
            raise HTTPException(status_code=404, detail="workspace not found")
        candidates = session.exec(select(Target).where(Target.workspace_id == payload.workspace_id)).all()
        scope_label = f"Workspace: {workspace.name}"
    elif payload.scope == "group":
        if payload.group_id is None:
            raise HTTPException(status_code=400, detail="group_id is required for scope='group'")
        group = session.get(Group, payload.group_id)
        if not group:
            raise HTTPException(status_code=404, detail="group not found")
        if ws_ids is not None and group.workspace_id not in ws_ids:
            raise HTTPException(status_code=404, detail="group not found")
        member_ids = session.exec(
            select(TargetGroup.target_id).where(TargetGroup.group_id == payload.group_id)
        ).all()
        candidates = (
            session.exec(select(Target).where(Target.id.in_(member_ids))).all() if member_ids else []
        )
        scope_label = f"Group: {group.name}"
    else:  # "all" -- every target across every accessible workspace (or literally all, for an admin)
        query = select(Target)
        if ws_ids is not None:
            candidates = session.exec(query.where(Target.workspace_id.in_(ws_ids))).all() if ws_ids else []
        else:
            candidates = session.exec(query).all()
        scope_label = "All accessible repositories"

    template = None
    if payload.workflow_template_id is not None:
        template = session.get(PipelineWorkflowTemplate, payload.workflow_template_id)
        if not template:
            raise HTTPException(status_code=404, detail="pipeline workflow template not found")
        if ws_ids is not None and template.workspace_id not in ws_ids:
            raise HTTPException(status_code=404, detail="pipeline workflow template not found")

    eligible_ids = [t.id for t in candidates if _caller_can_integrate(session, user, t)]
    if not eligible_ids:
        raise HTTPException(status_code=404, detail="no accessible, eligible targets found for this scope")

    batch = PipelineIntegrationBatch(
        created_by_user_id=user.id,
        total=len(eligible_ids),
        status="running",
        scope_label=scope_label,
        workflow_template_id=template.id if template else None,
    )
    session.add(batch)
    session.commit()
    session.refresh(batch)

    for tid in eligible_ids:
        session.add(PipelineIntegrationBatchItem(batch_id=batch.id, target_id=tid, status="pending"))
    session.commit()

    run_pipeline_integration_batch.delay(batch_id=batch.id)

    return JSONResponse(
        status_code=202,
        content={
            "batch_id": batch.id,
            "total": batch.total,
            "status": batch.status,
            "scope_label": batch.scope_label,
        },
    )


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
