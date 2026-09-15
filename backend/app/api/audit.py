from datetime import datetime, time

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.auth import accessible_workspace_ids, current_user
from app.api.deps import get_session
from app.models.models import FindingStateLog, Finding, McpAuditLog, Scan, Target, User

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


def _scoped_targets_and_findings(
    session: Session, ws_ids: list[int] | None
) -> tuple[dict[int, Target], dict[int, Finding]]:
    """Issue #506: the audit trail joins raw FindingStateLog/Scan/McpAuditLog
    rows against these dicts to render titles/names -- for a non-admin they
    also double as the visibility filter (a row referencing a target/finding
    absent from these dicts is outside the caller's accessible workspaces and
    gets dropped, not just rendered without a title)."""
    if ws_ids is None:
        targets = {t.id: t for t in session.exec(select(Target)).all()}
        findings = {f.id: f for f in session.exec(select(Finding)).all()}
        return targets, findings
    targets = {
        t.id: t
        for t in session.exec(select(Target).where(Target.workspace_id.in_(ws_ids))).all()
    }
    findings = {
        f.id: f
        for f in session.exec(
            select(Finding)
            .join(Target, Target.id == Finding.target_id)
            .where(Target.workspace_id.in_(ws_ids))
        ).all()
    }
    return targets, findings


def _mcp_event_visible(
    log: McpAuditLog,
    *,
    ws_ids: list[int] | None,
    viewer_id: int,
    targets: dict[int, Target],
    findings: dict[int, Finding],
) -> bool:
    """MCP calls carry nullable target_id/finding_id (not every tool call is
    scoped to one -- e.g. list_targets). When one is present, resolve the
    workspace through it and apply the normal filter. When neither is
    present the call can't be workspace-attributed at all: an admin still
    sees it, a non-admin only sees their own (you can always see what you
    did), closing the leak without hiding a caller's own history."""
    if log.target_id is not None:
        return log.target_id in targets
    if log.finding_id is not None:
        return log.finding_id in findings
    if ws_ids is None:
        return True
    return log.user_id == viewer_id


@router.get("/log")
def audit_log(
    event_type: str | None = None,
    actor: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
) -> AuditLogResponse:
    """Global audit trail: finding triage transitions + scan runs + MCP/
    public-API actions, real DB records. Supports the same filter-bar +
    real-pagination pattern as findings.list_findings (issue #123), date
    range, event type, actor.

    Issue #506: scoped to the caller's accessible workspaces (plus, for the
    minority of MCP events that carry no target/finding to scope by, to
    their own actions) -- previously every authenticated viewer saw every
    workspace's triage/scan/MCP history here regardless of membership.
    """
    ws_ids = accessible_workspace_ids(session, user)
    targets, findings = _scoped_targets_and_findings(session, ws_ids)

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
        if ws_ids is not None:
            triage_logs = [log for log in triage_logs if log.finding_id in findings]

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
            if ws_ids is not None:
                scans = [s for s in scans if s.target_id in targets]
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

    if event_type in (None, "", "mcp"):
        # McpAuditLog rows (app.core.mcp_audit): every call to
        # /api/public/v1/*, the Toleman MCP server's own surface -- who
        # (actor, the token's owner) and what agent software did what.
        # actor here filters by the user's email, not a stored string
        # column, so it needs a join rather than a plain where().
        query = select(McpAuditLog)
        if actor:
            query = query.join(User, User.id == McpAuditLog.user_id).where(User.email == actor)
        if dt_from:
            query = query.where(McpAuditLog.created_at >= dt_from)
        if dt_to:
            query = query.where(McpAuditLog.created_at <= dt_to)
        mcp_logs = session.exec(query.order_by(McpAuditLog.created_at.desc())).all()
        mcp_logs = [
            log
            for log in mcp_logs
            if _mcp_event_visible(log, ws_ids=ws_ids, viewer_id=user.id, targets=targets, findings=findings)
        ]
        user_ids = {log.user_id for log in mcp_logs}
        actor_users = {
            u.id: u for u in session.exec(select(User).where(User.id.in_(user_ids))).all()
        } if user_ids else {}
        for log in mcp_logs:
            actor_user = actor_users.get(log.user_id)
            events.append({
                "type": "mcp",
                "timestamp": log.created_at.isoformat(),
                "actor": actor_user.email if actor_user else f"user#{log.user_id}",
                "summary": f"[{log.tool}] {log.summary}" + ("" if log.success else " (failed)"),
                "reason": f"via {log.agent}" + (f": {log.error}" if log.error else ""),
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
def list_actors(session: Session = Depends(get_session), user: User = Depends(current_user)) -> list[str]:
    """Distinct actors across the triage + MCP audit trails, for
    populating the Audit Log actor filter; same 'real facet from real
    data' pattern as findings.list_tool_facets. A user who's only ever
    acted through an MCP token (never triaged a finding in the UI) has no
    FindingStateLog row at all, so that trail alone would silently omit
    them from the filter -- join in McpAuditLog's own distinct users too.

    Issue #506: scoped the same way as GET /log, so the actor filter never
    offers (or reveals the existence of) an actor whose only activity is on
    a workspace the caller can't see.
    """
    ws_ids = accessible_workspace_ids(session, user)
    targets, findings = _scoped_targets_and_findings(session, ws_ids)

    triage_query = select(FindingStateLog.actor).distinct()
    if ws_ids is not None:
        triage_query = (
            select(FindingStateLog.actor)
            .join(Finding, Finding.id == FindingStateLog.finding_id)
            .join(Target, Target.id == Finding.target_id)
            .where(Target.workspace_id.in_(ws_ids))
            .distinct()
        )
    triage_actors = set(session.exec(triage_query).all())

    mcp_logs = session.exec(select(McpAuditLog)).all()
    mcp_logs = [
        log
        for log in mcp_logs
        if _mcp_event_visible(log, ws_ids=ws_ids, viewer_id=user.id, targets=targets, findings=findings)
    ]
    mcp_user_ids = {log.user_id for log in mcp_logs}
    if mcp_user_ids:
        mcp_actors = session.exec(select(User.email).where(User.id.in_(mcp_user_ids))).all()
        triage_actors.update(mcp_actors)
    return sorted(triage_actors)
