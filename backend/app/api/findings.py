import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, func, or_, select

from app.api.auth import accessible_workspace_ids, current_user, enforce_workspace_role, require_workspace_role
from app.api.deps import get_session
from app.core.cve_enrichment import get_cve_enrichment
from app.models.models import Finding, FindingState, FindingStateLog, Severity, Target, TargetGroup, User, WorkspaceRole

router = APIRouter(prefix="/api/findings", tags=["findings"])

DEFAULT_PAGE_SIZE = 25


class FindingListResponse(BaseModel):
    items: list[Finding]
    total: int


class BulkTriageRequest(BaseModel):
    finding_ids: list[int]
    to_state: FindingState
    reason: str = ""
    actor: str = "user"


class FindingEnrichmentResponse(BaseModel):
    """No-AI enrichment (issue #71): real CWE/CVSS/description from NVD and
    known fixed versions from OSV.dev, both keyed off Finding.cve_id.
    Fields are null when not applicable (e.g. a secrets-detection or SAST
    finding with no cve_id has no CVE/OSV data at all -- that's correct, not
    a bug) or when the upstream source didn't have data for this CVE.
    Distinct from AI Analysis (app/api/ai.py) -- this always works with zero
    AI provider configured."""
    finding_id: int
    cve_id: str | None = None
    cve_description: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cwe_ids: list[str] | None = None
    references: list[str] | None = None
    fix_versions: list[dict] | None = None
    fetched_at: datetime | None = None


def _apply_triage(finding: Finding, to_state: FindingState, reason: str, actor: str, session: Session) -> Finding:
    """Shared single-finding state-transition + audit-log logic, used by
    both the single triage endpoint and the bulk triage endpoint."""
    log = FindingStateLog(finding_id=finding.id, from_state=finding.state, to_state=to_state, reason=reason, actor=actor)
    finding.state = to_state
    session.add(finding)
    session.add(log)
    return finding


@router.get("")
def list_findings(
    target_id: int | None = None,
    group_id: int | None = None,
    branch: str | None = None,
    state: FindingState | None = None,
    severity: Severity | None = None,
    tool: str | None = None,
    search: str | None = None,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
) -> FindingListResponse:
    # Issue #57: scope to workspaces the caller is a member of (None = admin,
    # no filter). A caller with no memberships gets ws_ids == [] below, which
    # short-circuits to an empty page rather than every workspace's findings.
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return FindingListResponse(items=[], total=0)

    query = select(Finding)
    if ws_ids is not None:
        query = query.join(Target, Target.id == Finding.target_id).where(Target.workspace_id.in_(ws_ids))
    if group_id is not None:
        # Issue #61: findings for targets tagged with this group. Joined on
        # Finding.target_id directly (not via the Target join above, which
        # only happens when ws_ids is not None) so this works regardless of
        # whether the caller is an admin.
        query = query.join(TargetGroup, TargetGroup.target_id == Finding.target_id).where(
            TargetGroup.group_id == group_id
        )
    if target_id is not None:
        query = query.where(Finding.target_id == target_id)
    if branch is not None:
        query = query.where(Finding.branch == branch)
    if state is not None:
        query = query.where(Finding.state == state)
    if severity is not None:
        query = query.where(Finding.severity == severity)
    if tool is not None:
        query = query.where(Finding.tool == tool)
    if search:
        like = f"%{search}%"
        query = query.where(
            or_(
                Finding.title.ilike(like),
                Finding.file_path.ilike(like),
                Finding.rule_id.ilike(like),
            )
        )

    total = session.exec(select(func.count()).select_from(query.subquery())).one()

    page = max(page, 1)
    page_size = max(min(page_size, 500), 1)
    query = query.order_by(Finding.priority_score.desc()).offset((page - 1) * page_size).limit(page_size)
    items = session.exec(query).all()
    return FindingListResponse(items=items, total=total)


@router.get("/facets/tools")
def list_tool_facets(session: Session = Depends(get_session), user: User = Depends(current_user)) -> list[str]:
    """Distinct tool names across findings visible to the caller (issue #57),
    for populating the tool filter."""
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return []
    query = select(Finding.tool).distinct()
    if ws_ids is not None:
        query = query.join(Target, Target.id == Finding.target_id).where(Target.workspace_id.in_(ws_ids))
    rows = session.exec(query).all()
    return sorted(rows)


@router.get("/{finding_id}")
def get_finding(finding_id: int, session: Session = Depends(get_session), user: User = Depends(current_user)):
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None:
        # 404 rather than 403 to avoid confirming the finding exists in a
        # workspace the caller can't see (matches the "not found" wording
        # already used across this codebase for missing resources).
        target = session.get(Target, finding.target_id)
        if not target or target.workspace_id not in ws_ids:
            raise HTTPException(status_code=404, detail="finding not found")
    return finding


@router.get("/{finding_id}/enrichment")
def get_finding_enrichment(
    finding_id: int, session: Session = Depends(get_session), user: User = Depends(current_user)
) -> FindingEnrichmentResponse:
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None:
        target = session.get(Target, finding.target_id)
        if not target or target.workspace_id not in ws_ids:
            raise HTTPException(status_code=404, detail="finding not found")

    if not finding.cve_id:
        # No CVE on this finding (SAST/secrets finding) -- nothing to
        # enrich from NVD/OSV. Correct, not a bug: return an all-null body
        # rather than a 404, so the frontend can render "no enrichment
        # available" instead of treating it as an error.
        return FindingEnrichmentResponse(finding_id=finding_id)

    row = get_cve_enrichment(session, finding.cve_id)

    references: list[str] = []
    if row.nvd_references:
        references.extend(json.loads(row.nvd_references))
    if row.osv_references:
        references.extend(json.loads(row.osv_references))
    deduped_references = list(dict.fromkeys(references))  # de-dup, preserve order

    return FindingEnrichmentResponse(
        finding_id=finding_id,
        cve_id=finding.cve_id,
        cve_description=row.nvd_description,
        cvss_score=row.cvss_score,
        cvss_vector=row.cvss_vector,
        cwe_ids=json.loads(row.cwe_ids) if row.cwe_ids else None,
        references=deduped_references or None,
        fix_versions=json.loads(row.fixed_versions) if row.fixed_versions else None,
        fetched_at=row.fetched_at,
    )


@router.post("/bulk-triage")
def bulk_triage_findings(
    payload: BulkTriageRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    updated = []
    for finding_id in payload.finding_ids:
        finding = session.get(Finding, finding_id)
        if not finding:
            continue
        # finding_id is inside the request body's finding_ids list, and each
        # one can belong to a different target/workspace -- check per finding
        # rather than once, the same reason create_target checks explicitly
        # instead of using require_workspace_role (see its comment).
        enforce_workspace_role(session, user, WorkspaceRole.DEVELOPER, finding_id=finding_id)
        updated.append(_apply_triage(finding, payload.to_state, payload.reason, payload.actor, session))
    session.commit()
    for finding in updated:
        session.refresh(finding)
    return {"updated": len(updated), "items": updated}


@router.post("/{finding_id}/triage")
def triage_finding(
    finding_id: int,
    to_state: FindingState,
    reason: str = "",
    actor: str = "user",
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    finding = session.get(Finding, finding_id)
    if not finding:
        return {"error": "not found"}
    _apply_triage(finding, to_state, reason, actor, session)
    session.commit()
    session.refresh(finding)
    return finding


@router.get("/{finding_id}/history")
def finding_history(finding_id: int, session: Session = Depends(get_session), user: User = Depends(current_user)):
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None:
        target = session.get(Target, finding.target_id)
        if not target or target.workspace_id not in ws_ids:
            raise HTTPException(status_code=404, detail="finding not found")
    return session.exec(select(FindingStateLog).where(FindingStateLog.finding_id == finding_id).order_by(FindingStateLog.created_at)).all()
