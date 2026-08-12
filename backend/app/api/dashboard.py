from fastapi import APIRouter, Depends
from sqlmodel import Session, select, func

from app.api.deps import get_session
from app.models.models import Finding, FindingState, Target

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/posture")
def posture(session: Session = Depends(get_session)):
    """Main Posture Dashboard: org health, default branches only."""
    targets = session.exec(select(Target)).all()
    result = []
    for t in targets:
        rows = session.exec(
            select(Finding.severity, Finding.state, func.count())
            .where(Finding.target_id == t.id, Finding.branch == t.default_branch)
            .group_by(Finding.severity, Finding.state)
        ).all()
        breakdown = {}
        for severity, state, count in rows:
            breakdown.setdefault(severity, {})[state] = count
        result.append({"target": t, "breakdown": breakdown})
    return result


@router.get("/summary")
def summary(session: Session = Depends(get_session)):
    total = session.exec(select(func.count()).select_from(Finding)).one()
    open_count = session.exec(select(func.count()).select_from(Finding).where(Finding.state == FindingState.OPEN)).one()
    mitigated = session.exec(select(func.count()).select_from(Finding).where(Finding.state == FindingState.MITIGATED)).one()
    return {"total": total, "open": open_count, "mitigated": mitigated}
