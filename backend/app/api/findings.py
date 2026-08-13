from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlmodel import Session, func, or_, select

from app.api.auth import current_user, enforce_workspace_role, require_workspace_role
from app.api.deps import get_session
from app.models.models import Finding, FindingState, FindingStateLog, Severity, User, WorkspaceRole

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
    branch: str | None = None,
    state: FindingState | None = None,
    severity: Severity | None = None,
    tool: str | None = None,
    search: str | None = None,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    session: Session = Depends(get_session),
) -> FindingListResponse:
    query = select(Finding)
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
def list_tool_facets(session: Session = Depends(get_session)) -> list[str]:
    """Distinct tool names across all findings, for populating the tool filter."""
    rows = session.exec(select(Finding.tool).distinct()).all()
    return sorted(rows)


@router.get("/{finding_id}")
def get_finding(finding_id: int, session: Session = Depends(get_session)):
    return session.get(Finding, finding_id)


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
def finding_history(finding_id: int, session: Session = Depends(get_session)):
    return session.exec(select(FindingStateLog).where(FindingStateLog.finding_id == finding_id).order_by(FindingStateLog.created_at)).all()
