from datetime import datetime, time

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.deps import get_session
from app.models.models import FindingStateLog, Finding, Scan, Target

router = APIRouter(prefix="/api/audit", tags=["audit"])

DEFAULT_PAGE_SIZE = 25


class AuditEventExpandItem(BaseModel):
    """One original row folded into a grouped bulk-action entry."""

    finding_id: int
    title: str | None
    from_state: str
    to_state: str
    timestamp: str


class AuditEventOut(BaseModel):
    type: str
    timestamp: str
    actor: str
    summary: str
    reason: str
    # Issue #123: a bulk-triage action fans out into N FindingStateLog rows
    # sharing one batch_id. grouped_count > 1 means this item represents
    # that whole batch collapsed into one feed entry; expand carries the
    # individual rows for an on-demand "▸ expand" disclosure instead of
    # flooding the feed with N near-identical cards.
    grouped_count: int = 1
    expand: list[AuditEventExpandItem] | None = None


class AuditLogResponse(BaseModel):
    items: list[AuditEventOut]
    total: int


def _parse_date_bound(value: str | None, *, end_of_day: bool) -> datetime | None:
    """Parse a plain 'YYYY-MM-DD' (or full ISO) date-range boundary from a
    query param. Never raises on a malformed value; an unparseable filter
    is simply ignored rather than 500ing the whole feed."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if end_of_day and "T" not in value:
        parsed = datetime.combine(parsed.date(), time.max)
    return parsed


@router.get("/log")
def audit_log(
    event_type: str | None = None,
    actor: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    session: Session = Depends(get_session),
) -> AuditLogResponse:
    """Global audit trail: finding triage transitions + scan runs, real DB
    records. Supports the same filter-bar + real-pagination pattern as
    findings.list_findings (issue #123), date range, event type, actor.
    """
    findings = {f.id: f for f in session.exec(select(Finding)).all()}
    targets = {t.id: t for t in session.exec(select(Target)).all()}

    dt_from = _parse_date_bound(date_from, end_of_day=False)
    dt_to = _parse_date_bound(date_to, end_of_day=True)

    events: list[dict] = []

    if event_type in (None, "", "triage"):
        query = select(FindingStateLog)
        if actor:
            query = query.where(FindingStateLog.actor == actor)
        if dt_from:
            query = query.where(FindingStateLog.created_at >= dt_from)
        if dt_to:
            query = query.where(FindingStateLog.created_at <= dt_to)
        triage_logs = session.exec(query.order_by(FindingStateLog.created_at.desc())).all()

        grouped: dict[str, list[FindingStateLog]] = {}
        ungrouped: list[FindingStateLog] = []
        for log in triage_logs:
            if log.batch_id:
                grouped.setdefault(log.batch_id, []).append(log)
            else:
                ungrouped.append(log)

        for log in ungrouped:
            finding = findings.get(log.finding_id)
            events.append({
                "type": "triage",
                "timestamp": log.created_at.isoformat(),
                "actor": log.actor,
                "summary": f"{log.from_state} -> {log.to_state}"
                           + (f": {finding.title}" if finding else ""),
                "reason": log.reason,
                "grouped_count": 1,
                "expand": None,
            })

        for logs in grouped.values():
            logs.sort(key=lambda l: l.created_at, reverse=True)
            first = logs[0]
            example = findings.get(first.finding_id)
            summary = f"{len(logs)} findings {first.from_state} -> {first.to_state}"
            if example:
                summary += f" (e.g. {example.title})"
            events.append({
                "type": "triage",
                "timestamp": first.created_at.isoformat(),
                "actor": first.actor,
                "summary": summary,
                "reason": first.reason,
                "grouped_count": len(logs),
                "expand": [
                    {
                        "finding_id": l.finding_id,
                        "title": findings[l.finding_id].title if l.finding_id in findings else None,
                        "from_state": l.from_state,
                        "to_state": l.to_state,
                        "timestamp": l.created_at.isoformat(),
                    }
                    for l in logs
                ],
            })

    if event_type in (None, "", "scan"):
        # Scans are always actor="system"; an explicit non-"system" actor
        # filter should exclude scan events entirely rather than silently
        # ignoring the filter and returning them anyway.
        if not actor or actor == "system":
            query = select(Scan)
            if dt_from:
                query = query.where(Scan.started_at >= dt_from)
            if dt_to:
                query = query.where(Scan.started_at <= dt_to)
            scans = session.exec(query.order_by(Scan.started_at.desc())).all()
            for scan in scans:
                target = targets.get(scan.target_id)
                events.append({
                    "type": "scan",
                    "timestamp": scan.started_at.isoformat(),
                    "actor": "system",
                    "summary": f"{scan.tool} scan on {target.name if target else scan.target_id}: {scan.status} ({scan.findings_count} findings)",
                    "reason": "",
                    "grouped_count": 1,
                    "expand": None,
                })

    events.sort(key=lambda e: e["timestamp"], reverse=True)
    total = len(events)

    page = max(page, 1)
    page_size = max(min(page_size, 200), 1)
    start = (page - 1) * page_size
    page_items = events[start : start + page_size]

    return AuditLogResponse(items=[AuditEventOut(**e) for e in page_items], total=total)


@router.get("/actors")
def list_actors(session: Session = Depends(get_session)) -> list[str]:
    """Distinct actors across the triage audit trail, for populating the
    Audit Log actor filter; same 'real facet from real data' pattern as
    findings.list_tool_facets."""
    rows = session.exec(select(FindingStateLog.actor).distinct()).all()
    return sorted(rows)
