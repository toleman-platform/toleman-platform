"""ScanSchedule read/write (issue #306): the scheduling surface behind the
per-target panel on the target detail page and the workspace defaults in
Control Plane.

Shaped as an upsert rather than create/update/delete CRUD (the shape
sla_rules.py uses), because a schedule is not a list someone curates: there
is exactly one schedule per (scope, scan type), it always has an effective
value whether or not a row exists, and "delete" has a meaning that is not
"gone" -- it is "stop overriding, go back to inheriting". Modelling that as
DELETE-the-row is the honest implementation, so it is exposed as an
explicit "reset to inherited" instead of a destructive-sounding verb.

Gated at SECURITY_ENGINEER for writes, the same level as sla_rules.py and
policies: choosing how often (or whether) a target is scanned is a security
posture decision, and turning a schedule off is the one change here that can
quietly stop the platform from noticing anything new about a repo. Reads are
open to any workspace member, since the next/last run times are exactly the
"is this actually running?" answer a viewer needs.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.auth import accessible_workspace_ids, current_user, enforce_workspace_role
from app.api.deps import get_session
from app.core.scan_schedules import (
    SHIPPED_DEFAULTS,
    ResolvedScanSchedule,
    ScanScheduleError,
    advance_next_run_at,
    resolve_scan_schedule,
    target_row,
    validate_interval_hours,
    workspace_default_row,
)
from app.core.time import utcnow
from app.models.models import ScanSchedule, ScanScheduleType, Target, User, Workspace, WorkspaceRole

router = APIRouter(prefix="/api/scan-schedules", tags=["scan-schedules"])


class UpsertScanScheduleRequest(BaseModel):
    """Both fields are tri-state on purpose and the distinction is the whole
    inheritance model, so it survives all the way to the wire:

      * field omitted   -> leave whatever is stored alone (exclude_unset).
      * field null      -> inherit from the level above (clear the override).
      * field has value -> this level decides.

    Same semantics as UpdateTargetRequest's enforcement_mode in
    app/api/targets.py; stated again here because getting "null" confused
    with "false" would silently disable scanning for a workspace that only
    meant to stop overriding the cadence.
    """
    enabled: Optional[bool] = None
    interval_hours: Optional[int] = None


def _serialize(resolved: ResolvedScanSchedule, row: Optional[ScanSchedule]) -> dict:
    """One payload carrying both the effective answer and the raw override,
    because the UI needs both: the switch renders the stored value (null =
    "Inherit"), the sentence underneath renders the effective one ("every
    24h, inherited from the workspace default")."""
    return {
        "scan_type": resolved.scan_type.value,
        # The effective answer, after inheritance.
        "enabled": resolved.enabled,
        "interval_hours": resolved.interval_hours,
        "enabled_source": resolved.enabled_source,
        "interval_source": resolved.interval_source,
        # The raw override stored at the scope being addressed; null means
        # "inheriting", which is a different thing from false/0 and has to
        # stay distinguishable in the client.
        "override_enabled": row.enabled if row else None,
        "override_interval_hours": row.interval_hours if row else None,
        "schedule_id": resolved.schedule_id,
        # Honesty fields. last_run_at null means "has never fired"; the
        # frontend says so in words rather than rendering an empty cell.
        "last_run_at": resolved.last_run_at,
        "last_dispatched_count": resolved.last_dispatched_count,
        "next_run_at": resolved.next_run_at,
    }


def _resolve_for_workspace(session: Session, workspace_id: int, scan_type: ScanScheduleType) -> dict:
    """Workspace-level view. Deliberately NOT resolve_scan_schedule (which
    needs a target): at this scope there is no target row to overlay, so the
    effective value is the shipped default overlaid with this workspace's
    own row and nothing else."""
    row = workspace_default_row(session, workspace_id, scan_type)
    shipped = SHIPPED_DEFAULTS[scan_type]
    enabled = row.enabled if (row and row.enabled is not None) else shipped.enabled
    interval = row.interval_hours if (row and row.interval_hours is not None) else shipped.interval_hours
    resolved = ResolvedScanSchedule(
        scan_type=scan_type,
        enabled=enabled,
        interval_hours=interval,
        enabled_source="workspace" if (row and row.enabled is not None) else "default",
        interval_source="workspace" if (row and row.interval_hours is not None) else "default",
        schedule_id=row.id if row else None,
        last_run_at=row.last_run_at if row else None,
        last_dispatched_count=row.last_dispatched_count if row else None,
        next_run_at=(row.next_run_at if row and enabled else None),
    )
    return _serialize(resolved, row)


def _parse_scan_type(raw: str) -> ScanScheduleType:
    try:
        return ScanScheduleType(raw)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"unknown scan_type {raw!r}; expected one of {[t.value for t in ScanScheduleType]}",
        )


@router.get("/workspace/{workspace_id}")
def get_workspace_schedules(
    workspace_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Every scan type's workspace-level schedule, including the types with
    no row yet (they report the shipped default with schedule_id null, which
    is the truth: nothing is stored, and the dispatcher will materialise a
    row on its next pass)."""
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and workspace_id not in ws_ids:
        raise HTTPException(status_code=404, detail="workspace not found")
    if session.get(Workspace, workspace_id) is None:
        raise HTTPException(status_code=404, detail="workspace not found")
    return {
        "workspace_id": workspace_id,
        "schedules": [_resolve_for_workspace(session, workspace_id, t) for t in ScanScheduleType],
    }


@router.get("/target/{target_id}")
def get_target_schedules(
    target_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Every scan type's effective schedule for one target, with the source
    of each effective value so the UI can say "inherited from the workspace
    default" rather than presenting an inherited cadence as this target's own
    decision."""
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and target.workspace_id not in ws_ids:
        raise HTTPException(status_code=404, detail="target not found")

    out = []
    for scan_type in ScanScheduleType:
        resolved = resolve_scan_schedule(session, target, scan_type)
        out.append(_serialize(resolved, target_row(session, target_id, scan_type)))
    return {
        "target_id": target_id,
        "workspace_id": target.workspace_id,
        # The one thing a scheduling panel cannot infer: active API scanning
        # is only ever dispatched against an explicitly configured host (see
        # Target.api_base_url / app.core.api_scan_targets). Surfaced so the
        # UI can say "scheduled, but this target has no API base URL, so
        # nothing will be probed" instead of showing a schedule that looks
        # armed and silently does nothing.
        "api_base_url_configured": bool(target.api_base_url),
        "schedules": out,
    }


def _apply(
    session: Session,
    row: Optional[ScanSchedule],
    *,
    workspace_id: int,
    target_id: Optional[int],
    scan_type: ScanScheduleType,
    payload: UpsertScanScheduleRequest,
    fields_set: set[str],
) -> ScanSchedule:
    now = utcnow()
    if row is None:
        row = ScanSchedule(
            workspace_id=workspace_id,
            target_id=target_id,
            scan_type=scan_type,
            created_at=now,
            updated_at=now,
        )
    if "enabled" in fields_set:
        row.enabled = payload.enabled
    if "interval_hours" in fields_set:
        row.interval_hours = validate_interval_hours(payload.interval_hours)
    row.updated_at = now
    session.add(row)
    session.commit()
    session.refresh(row)

    # Recompute the due clock from the (possibly new) effective interval.
    # From `now`, not from the stored next_run_at: shortening an interval
    # must not leave a schedule that was mid-cycle sitting overdue and fire
    # the moment the dispatcher next ticks, and lengthening it must not
    # leave a stale earlier due time. Creating a row does the same, so
    # switching a schedule on never triggers an immediate fan-out across
    # every target it covers -- the "Scan now" button is what someone wants
    # when they mean right now.
    advance_next_run_at(session, row, now=now)
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


@router.put("/workspace/{workspace_id}/{scan_type}")
def upsert_workspace_schedule(
    workspace_id: int,
    scan_type: str,
    payload: UpsertScanScheduleRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Set (or clear) this workspace's default schedule for one scan type."""
    parsed = _parse_scan_type(scan_type)
    if session.get(Workspace, workspace_id) is None:
        raise HTTPException(status_code=404, detail="workspace not found")
    # workspace_id is a path param but the role check still has to be
    # explicit rather than a require_workspace_role dependency, because the
    # write also has to be legal for the *target* variant below where the
    # workspace is only reachable through the target.
    enforce_workspace_role(session, user, WorkspaceRole.SECURITY_ENGINEER, workspace_id=workspace_id)

    row = workspace_default_row(session, workspace_id, parsed)
    try:
        row = _apply(
            session,
            row,
            workspace_id=workspace_id,
            target_id=None,
            scan_type=parsed,
            payload=payload,
            fields_set=payload.model_fields_set,
        )
    except ScanScheduleError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return _resolve_for_workspace(session, workspace_id, parsed)


@router.put("/target/{target_id}/{scan_type}")
def upsert_target_schedule(
    target_id: int,
    scan_type: str,
    payload: UpsertScanScheduleRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Set (or clear) one target's override for one scan type."""
    parsed = _parse_scan_type(scan_type)
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    enforce_workspace_role(session, user, WorkspaceRole.SECURITY_ENGINEER, workspace_id=target.workspace_id)

    row = target_row(session, target_id, parsed)
    try:
        _apply(
            session,
            row,
            workspace_id=target.workspace_id,
            target_id=target_id,
            scan_type=parsed,
            payload=payload,
            fields_set=payload.model_fields_set,
        )
    except ScanScheduleError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    resolved = resolve_scan_schedule(session, target, parsed)
    return _serialize(resolved, target_row(session, target_id, parsed))


@router.delete("/target/{target_id}/{scan_type}")
def reset_target_schedule(
    target_id: int,
    scan_type: str,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Drop this target's override so it inherits the workspace default
    again.

    The row genuinely goes away rather than being blanked to
    (enabled=None, interval_hours=None), because those two are not quite the
    same thing: a row with both columns NULL still removes its target from
    the workspace-default row's coverage set (see
    app.core.scan_schedules.targets_covered_by), so the target would inherit
    the workspace's *values* while keeping a separate run clock. Deleting is
    the only thing that means "this target is back under the workspace
    default in every sense".
    """
    parsed = _parse_scan_type(scan_type)
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    enforce_workspace_role(session, user, WorkspaceRole.SECURITY_ENGINEER, workspace_id=target.workspace_id)

    row = target_row(session, target_id, parsed)
    if row is not None:
        session.delete(row)
        session.commit()
    resolved = resolve_scan_schedule(session, target, parsed)
    return _serialize(resolved, None)


@router.get("")
def list_scan_schedules(
    workspace_id: Optional[int] = None,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Raw rows, workspace-scoped the same way GET /api/sla-rules is.

    The resolved views above are what the UI renders; this is the "show me
    every override that exists" list, which is the question an operator asks
    when a target is not being scanned and they want to know which level
    turned it off.
    """
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return []
    query = select(ScanSchedule)
    if workspace_id is not None:
        if ws_ids is not None and workspace_id not in ws_ids:
            return []
        query = query.where(ScanSchedule.workspace_id == workspace_id)
    elif ws_ids is not None:
        query = query.where(ScanSchedule.workspace_id.in_(ws_ids))
    return session.exec(query.order_by(ScanSchedule.workspace_id, ScanSchedule.scan_type)).all()
