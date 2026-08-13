from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select, func

from app.api.auth import accessible_workspace_ids, current_user
from app.api.deps import get_session
from app.core.sla import compute_sla_status
from app.core.widgets import WIDGET_CATALOG, build_default_layout
from app.models.models import DashboardLayout, Finding, FindingState, Target, User

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


def _scoped_targets_query(ws_ids: list[int] | None):
    query = select(Target)
    if ws_ids is not None:
        query = query.where(Target.workspace_id.in_(ws_ids))
    return query


@router.get("/stats")
def stats(session: Session = Depends(get_session), user: User = Depends(current_user)):
    """Aggregate counts for dashboard charts. Default-branch, Open findings
    only, scoped to the caller's workspaces (issue #57 -- admins still see
    everything)."""
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return {"open": 0, "by_severity": {}, "by_tool": {}}

    targets = {t.id: t for t in session.exec(_scoped_targets_query(ws_ids)).all()}

    open_findings = session.exec(select(Finding).where(Finding.state == FindingState.OPEN)).all()
    open_default_branch = [
        f for f in open_findings if targets.get(f.target_id) and f.branch == targets[f.target_id].default_branch
    ]

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
def posture(session: Session = Depends(get_session), user: User = Depends(current_user)):
    """Main Posture Dashboard: org health, default branches only, scoped to
    the caller's workspaces (issue #57)."""
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return []

    targets = session.exec(_scoped_targets_query(ws_ids)).all()
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
def summary(session: Session = Depends(get_session), user: User = Depends(current_user)):
    """Scoped to the caller's workspaces (issue #57)."""
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return {"total": 0, "open": 0, "mitigated": 0}

    base = select(Finding)
    if ws_ids is not None:
        base = base.join(Target, Target.id == Finding.target_id).where(Target.workspace_id.in_(ws_ids))

    total = session.exec(select(func.count()).select_from(base.subquery())).one()
    open_count = session.exec(select(func.count()).select_from(base.where(Finding.state == FindingState.OPEN).subquery())).one()
    mitigated = session.exec(select(func.count()).select_from(base.where(Finding.state == FindingState.MITIGATED).subquery())).one()
    return {"total": total, "open": open_count, "mitigated": mitigated}


@router.get("/sla-compliance")
def sla_compliance(session: Session = Depends(get_session), user: User = Depends(current_user)):
    """SLA compliance summary (issue #70): among OPEN (and Reopened, still
    unresolved) findings that a real SlaRule actually applies to, how many
    are past their days-to-fix window. Computed live via
    app.core.sla.compute_sla_status (query-time, no background job) --
    scoped to the caller's workspaces (issue #57)."""
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return {"with_sla": 0, "in_violation": 0, "compliant": 0}

    query = select(Finding).where(Finding.state.in_([FindingState.OPEN, FindingState.REOPENED]))
    if ws_ids is not None:
        query = query.join(Target, Target.id == Finding.target_id).where(Target.workspace_id.in_(ws_ids))
    open_findings = session.exec(query).all()

    with_sla = 0
    in_violation = 0
    for f in open_findings:
        sla_days, violated = compute_sla_status(session, f)
        if sla_days is None:
            continue
        with_sla += 1
        if violated:
            in_violation += 1

    return {"with_sla": with_sla, "in_violation": in_violation, "compliant": with_sla - in_violation}


# ---------------------------------------------------------------------------
# Configurable dashboard (issue #69)
# ---------------------------------------------------------------------------


class LayoutWidget(BaseModel):
    id: str
    widget_id: str
    config: dict = {}


class LayoutOut(BaseModel):
    widgets: list[LayoutWidget]


class LayoutIn(BaseModel):
    widgets: list[LayoutWidget]


@router.get("/widgets")
def list_widget_catalog():
    """The full widget catalog (issue #69) -- what's available to add to a
    layout, not a specific user's current layout. Deliberately a small,
    concrete list (see app.core.widgets docstring), not a generic
    chart-builder schema."""
    return [
        {"widget_id": wid, "name": entry["name"], "description": entry["description"]}
        for wid, entry in WIDGET_CATALOG.items()
    ]


@router.get("/layout")
def get_layout(session: Session = Depends(get_session), user: User = Depends(current_user)) -> LayoutOut:
    """The caller's saved dashboard composition, or a sensible default set
    of widgets if none has been saved yet (issue #69) -- never an empty
    dashboard just because no row exists."""
    row = session.exec(select(DashboardLayout).where(DashboardLayout.user_id == user.id)).first()
    if row and row.widgets:
        return LayoutOut(widgets=row.widgets)
    return LayoutOut(widgets=build_default_layout())


@router.put("/layout")
def put_layout(
    body: LayoutIn, session: Session = Depends(get_session), user: User = Depends(current_user)
) -> LayoutOut:
    """Persist the caller's dashboard composition (add/remove/reorder all
    collapse to "save this ordered list"). One row per user -- upserted."""
    for w in body.widgets:
        if w.widget_id not in WIDGET_CATALOG:
            raise HTTPException(status_code=400, detail=f"unknown widget_id: {w.widget_id}")

    widgets_data = [w.model_dump() for w in body.widgets]
    row = session.exec(select(DashboardLayout).where(DashboardLayout.user_id == user.id)).first()
    if row:
        row.widgets = widgets_data
        row.updated_at = datetime.utcnow()
    else:
        row = DashboardLayout(user_id=user.id, widgets=widgets_data)
    session.add(row)
    session.commit()
    session.refresh(row)
    return LayoutOut(widgets=row.widgets)


@router.get("/widget-data")
def widget_data(session: Session = Depends(get_session), user: User = Depends(current_user)):
    """Batch data fetch (issue #69) -- one round-trip for every widget
    currently in the caller's layout (or the default set if unsaved),
    rather than the frontend making one request per widget. Each widget's
    real query logic lives in app.core.widgets and is reused as-is, not
    duplicated here. A single widget instance's resolver failing (e.g. a
    malformed config) doesn't take the rest of the dashboard down with it
    -- it surfaces as {"error": ...} for just that instance."""
    ws_ids = accessible_workspace_ids(session, user)
    row = session.exec(select(DashboardLayout).where(DashboardLayout.user_id == user.id)).first()
    widgets = row.widgets if row and row.widgets else build_default_layout()

    if ws_ids is not None and not ws_ids:
        return {"widgets": {w["id"]: {"widget_id": w["widget_id"], "data": None} for w in widgets}}

    result: dict[str, dict] = {}
    for w in widgets:
        widget_id = w.get("widget_id")
        entry = WIDGET_CATALOG.get(widget_id)
        if not entry:
            result[w["id"]] = {"widget_id": widget_id, "error": "unknown widget_id"}
            continue
        try:
            result[w["id"]] = {"widget_id": widget_id, "data": entry["resolver"](session, ws_ids, w.get("config") or {})}
        except Exception as exc:  # noqa: BLE001 -- isolate one widget's failure from the rest
            result[w["id"]] = {"widget_id": widget_id, "error": str(exc)}
    return {"widgets": result}
