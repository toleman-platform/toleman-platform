from fastapi import APIRouter, Depends
from sqlmodel import Session, select, func

from app.api.deps import get_session
from app.models.models import Finding, FindingState, Target

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats")
def stats(session: Session = Depends(get_session)):
    """Aggregate counts for dashboard charts. Default-branch, Open findings only."""
    targets = {t.id: t for t in session.exec(select(Target)).all()}

    open_findings = session.exec(select(Finding).where(Finding.state == FindingState.OPEN)).all()
    open_default_branch = [f for f in open_findings if targets.get(f.target_id) and f.branch == targets[f.target_id].default_branch]

    severity_counts: dict[str, int] = {}
    tool_counts: dict[str, int] = {}
    for f in open_default_branch:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        tool_counts[f.tool] = tool_counts.get(f.tool, 0) + 1

    return {
        "open": len(open_default_branch),
        "by_severity": severity_counts,
        "by_tool": tool_counts,
    }


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
