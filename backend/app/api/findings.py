from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from app.api.deps import get_session
from app.models.models import Finding, FindingState, FindingStateLog

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("")
def list_findings(
    target_id: int | None = None,
    branch: str | None = None,
    state: FindingState | None = None,
    session: Session = Depends(get_session),
):
    query = select(Finding)
    if target_id is not None:
        query = query.where(Finding.target_id == target_id)
    if branch is not None:
        query = query.where(Finding.branch == branch)
    if state is not None:
        query = query.where(Finding.state == state)
    query = query.order_by(Finding.priority_score.desc())
    return session.exec(query).all()


@router.get("/{finding_id}")
def get_finding(finding_id: int, session: Session = Depends(get_session)):
    return session.get(Finding, finding_id)


@router.post("/{finding_id}/triage")
def triage_finding(finding_id: int, to_state: FindingState, reason: str = "", actor: str = "user", session: Session = Depends(get_session)):
    finding = session.get(Finding, finding_id)
    if not finding:
        return {"error": "not found"}
    log = FindingStateLog(finding_id=finding.id, from_state=finding.state, to_state=to_state, reason=reason, actor=actor)
    finding.state = to_state
    session.add(finding)
    session.add(log)
    session.commit()
    session.refresh(finding)
    return finding


@router.get("/{finding_id}/history")
def finding_history(finding_id: int, session: Session = Depends(get_session)):
    return session.exec(select(FindingStateLog).where(FindingStateLog.finding_id == finding_id).order_by(FindingStateLog.created_at)).all()
