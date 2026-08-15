from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.auth import accessible_workspace_ids, current_user, require_workspace_role
from app.api.deps import get_session
from app.core.api_scan_targets import ApiScanConfigError, build_scan_urls
from app.core.staleness import mark_stale_if_needed
from app.models.models import Scan, Target, User, WorkspaceRole
from app.tasks.api_scan_tasks import run_api_scan

router = APIRouter(prefix="/api/api-scan", tags=["api-scan"])


def _get_target(target_id: int, session: Session) -> Target:
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    return target


class RunApiScanRequest(BaseModel):
    # None = scan every endpoint discovered for this target's default
    # branch; a list narrows to a specific selection (e.g. checkboxes in
    # the UI). Ids that don't belong to this target+branch are silently
    # dropped by app.core.api_scan_targets.build_scan_urls, never used to
    # reach into another target's endpoints.
    endpoint_ids: list[int] | None = None


@router.post("/{target_id}")
def trigger_api_scan(
    target_id: int,
    payload: RunApiScanRequest = RunApiScanRequest(),
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    """Issue #72: dispatch an active API scan (nuclei) against endpoints
    already discovered for this target (Sprint 1's API Discovery). Async,
    same POST-creates-tracking-row-and-.delay()s pattern as
    POST /api/scans/run -- creates a Scan row (tool="api-scan",
    status="running") and returns its id immediately; poll
    GET /api/scans/{scan_id} until status leaves "running".

    Refuses outright (400, before any Scan row or Celery task exists) if
    the target has no api_base_url configured or has zero scannable
    endpoints for its current selection -- this is active scanning against
    a real network endpoint, so it must fail loud and immediately on
    obviously-unscannable input rather than silently creating a scan that
    can only ever fail once a worker picks it up.
    """
    target = _get_target(target_id, session)
    try:
        urls, endpoints = build_scan_urls(session, target, payload.endpoint_ids)
    except ApiScanConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not urls:
        raise HTTPException(
            status_code=400,
            detail="no scannable endpoints -- run API Discovery first, or check the endpoint selection",
        )

    scan = Scan(target_id=target_id, tool="api-scan", branch=target.default_branch, status="running")
    session.add(scan)
    session.commit()
    session.refresh(scan)

    run_api_scan.delay(target_id=target_id, scan_id=scan.id, endpoint_ids=payload.endpoint_ids)

    return JSONResponse(
        status_code=202,
        content={"scan_id": scan.id, "target_id": target_id, "status": scan.status, "endpoint_count": len(endpoints)},
    )


@router.get("/{target_id}/latest")
def get_latest_api_scan(target_id: int, session: Session = Depends(get_session), user: User = Depends(current_user)):
    """Most recent tool="api-scan" Scan row for this target, so the frontend
    can show 'last scanned' state on page load without holding a scan_id in
    client state across a reload -- same rationale as discovery/sbom's
    persisted-GET pattern, just backed by the shared Scan table instead of a
    dedicated *Run model, since active-scan results reuse the normal Finding
    table (tool="api-scan") rather than a bespoke schema."""
    target = _get_target(target_id, session)
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and target.workspace_id not in ws_ids:
        raise HTTPException(status_code=404, detail="target not found")

    scan = session.exec(
        select(Scan)
        .where(Scan.target_id == target_id, Scan.tool == "api-scan")
        .order_by(Scan.started_at.desc())
    ).first()
    if not scan:
        return {"target_id": target_id, "scan": None}
    mark_stale_if_needed(session, scan)
    return {
        "target_id": target_id,
        "scan": {
            "scan_id": scan.id,
            "target_id": scan.target_id,
            "tool": scan.tool,
            "branch": scan.branch,
            "status": scan.status,
            "findings_count": scan.findings_count,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "error_message": scan.error,
        },
    }
