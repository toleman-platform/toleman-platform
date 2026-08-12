from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from app.api.deps import get_session
from app.models.models import FindingStateLog, Finding, Scan, Target

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("/log")
def audit_log(limit: int = 100, session: Session = Depends(get_session)):
    """Global audit trail: finding triage transitions + scan runs, real DB records."""
    findings = {f.id: f for f in session.exec(select(Finding)).all()}
    targets = {t.id: t for t in session.exec(select(Target)).all()}

    events = []

    triage_logs = session.exec(select(FindingStateLog).order_by(FindingStateLog.created_at.desc()).limit(limit)).all()
    for log in triage_logs:
        finding = findings.get(log.finding_id)
        events.append({
            "type": "triage",
            "timestamp": log.created_at.isoformat(),
            "actor": log.actor,
            "summary": f"{log.from_state} -> {log.to_state}"
                       + (f": {finding.title}" if finding else ""),
            "reason": log.reason,
        })

    scans = session.exec(select(Scan).order_by(Scan.started_at.desc()).limit(limit)).all()
    for scan in scans:
        target = targets.get(scan.target_id)
        events.append({
            "type": "scan",
            "timestamp": scan.started_at.isoformat(),
            "actor": "system",
            "summary": f"{scan.tool} scan on {target.name if target else scan.target_id}: {scan.status} ({scan.findings_count} findings)",
            "reason": "",
        })

    events.sort(key=lambda e: e["timestamp"], reverse=True)
    return events[:limit]
