from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.auth import accessible_workspace_ids, current_user, require_workspace_role
from app.api.deps import get_session
from app.core.async_jobs import create_running_row
from app.core.discovery_ingestion import upsert_endpoints  # noqa: F401, re-exported, see docstring below
from app.core.staleness import mark_stale_if_needed
from app.core import target_lifecycle
from app.models.models import ApiEndpoint, DiscoveryRun, Target, User, WorkspaceRole
from app.tasks.discovery_tasks import run_discovery as run_discovery_task

router = APIRouter(prefix="/api/discovery", tags=["discovery"])

# upsert_endpoints used to be defined in this module; it now lives in
# app.core.discovery_ingestion (#59) so app.tasks.discovery_tasks (which
# does the actual clone+discover work on a Celery worker) can import it
# without an app.api.discovery <-> app.tasks.discovery_tasks import cycle.
# Re-imported above (not re-implemented) so `from app.api.discovery import
# upsert_endpoints` (used by tests) keeps working unchanged.


def _get_target(target_id: int, session: Session, user: User) -> Target:
    target = session.get(Target, target_id)
    # (#273) Soft-deleted targets 404; deactivation is checked at the
    # dispatching route only, so already-discovered endpoints stay readable.
    if not target or target_lifecycle.is_deleted(target):
        raise HTTPException(status_code=404, detail="target not found")
    # (#57-shaped gap) The two GET routes below used to call this helper
    # with no workspace check at all -- any authenticated user could read
    # another workspace's discovered API surface by target_id. 404, not
    # 403: a caller outside this target's workspace must not learn the id
    # is valid.
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and target.workspace_id not in ws_ids:
        raise HTTPException(status_code=404, detail="target not found")
    return target


@router.post("/{target_id}")
def run_discovery(
    target_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    """Dispatch an async API Discovery run (#59) instead of cloning+grepping
    synchronously inside the request handler, a handful of concurrent
    requests here used to be enough to exhaust FastAPI's threadpool. Creates
    a DiscoveryRun row (status="running"), hands the actual clone+discover
    work to app.tasks.discovery_tasks.run_discovery via .delay(), and
    returns immediately with the run's id. Poll
    GET /api/discovery/{target_id}/runs/{run_id} until status leaves
    "running" to get the same endpoints/new_count payload this used to
    return synchronously."""
    target = _get_target(target_id, session, user)
    # (#273) API Discovery clones the repo and greps the checkout, so it is a
    # scan by every definition that matters here (it starts work against a
    # repository the operator switched off, and its output feeds Active API
    # Scanning). Refused for the same reason POST /api/scans/run is.
    refusal = target_lifecycle.scan_refusal_reason(target)
    if refusal:
        raise HTTPException(status_code=409, detail=refusal)

    run = create_running_row(
        session, DiscoveryRun(target_id=target_id, branch=target.default_branch, status="running")
    )

    run_discovery_task.delay(target_id=target_id, run_id=run.id)

    return JSONResponse(
        status_code=202,
        content={"run_id": run.id, "target_id": target_id, "status": run.status},
    )


@router.get("/{target_id}/runs/{run_id}")
def get_discovery_run(
    target_id: int,
    run_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Poll target for an async discovery run dispatched by POST above.
    Once status leaves "running", also returns the same endpoints/new_count
    payload the old synchronous POST used to return directly."""
    run = session.get(DiscoveryRun, run_id)
    if not run or run.target_id != target_id:
        raise HTTPException(status_code=404, detail="discovery run not found")
    mark_stale_if_needed(session, run)

    target = _get_target(target_id, session, user)
    payload = {
        "run_id": run.id,
        "target_id": run.target_id,
        "status": run.status,
        "count": run.count,
        "new_count": run.new_count,
        "error": run.error,
        "started_at": run.started_at,
        "completed_at": run.completed_at,
    }
    if run.status != "running":
        new_id_set = {int(x) for x in run.new_ids.split(",") if x}
        all_endpoints = session.exec(
            select(ApiEndpoint).where(
                ApiEndpoint.target_id == target_id, ApiEndpoint.branch == target.default_branch
            )
        ).all()
        payload["endpoints"] = [
            {
                "id": e.id,
                "framework": e.framework,
                "method": e.method,
                "route": e.route,
                "file": e.file_path,
                "line": e.line,
                "is_new": e.id in new_id_set,
                "first_seen": e.first_seen,
                "last_seen": e.last_seen,
            }
            for e in all_endpoints
        ]
    return payload


@router.get("/{target_id}")
def list_discovered_endpoints(
    target_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Persisted results without re-running a scan; the page should show
    real state on load, not force a re-scan every visit."""
    target = _get_target(target_id, session, user)
    endpoints = session.exec(
        select(ApiEndpoint)
        .where(ApiEndpoint.target_id == target_id, ApiEndpoint.branch == target.default_branch)
        .order_by(ApiEndpoint.route)
    ).all()
    return {
        "target_id": target_id,
        "count": len(endpoints),
        "endpoints": [
            {
                "id": e.id,
                "framework": e.framework,
                "method": e.method,
                "route": e.route,
                "file": e.file_path,
                "line": e.line,
                "is_new": False,
                "first_seen": e.first_seen,
                "last_seen": e.last_seen,
                "excluded": e.excluded,
                "exclusion_reason": e.exclusion_reason,
            }
            for e in endpoints
        ],
    }


class UpdateEndpointScopeRequest(BaseModel):
    excluded: bool
    # Free text, not an enum: the useful reasons ("wipes the staging
    # tenant", "bills per call", "owned by another team") are not a set
    # anyone can enumerate ahead of time, and an enum would push every real
    # answer into "other".
    reason: str | None = None


@router.patch("/{target_id}/endpoints/{endpoint_id}")
def set_endpoint_scope(
    target_id: int,
    endpoint_id: int,
    payload: UpdateEndpointScopeRequest,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    """Mark a discovered endpoint in or out of scope for active scanning
    (#469).

    DEVELOPER rather than a read-level role, and the same bar as
    triggering the scan itself: this decides whether real traffic is ever
    sent at a real route, so it is not a display preference.

    The endpoint must belong to this target, by id AND by the target's
    current default branch, for the same reason build_scan_urls checks it:
    an id from another target must never be reachable by guessing.
    """
    target = _get_target(target_id, session, user)
    endpoint = session.get(ApiEndpoint, endpoint_id)
    if not endpoint or endpoint.target_id != target_id or endpoint.branch != target.default_branch:
        raise HTTPException(status_code=404, detail="endpoint not found for this target")

    endpoint.excluded = payload.excluded
    # Cleared when an endpoint comes back into scope, so a stale reason
    # from a previous exclusion cannot be read as the current state.
    endpoint.exclusion_reason = payload.reason if payload.excluded else None
    session.add(endpoint)
    session.commit()
    session.refresh(endpoint)

    return {
        "id": endpoint.id,
        "method": endpoint.method,
        "route": endpoint.route,
        "excluded": endpoint.excluded,
        "exclusion_reason": endpoint.exclusion_reason,
    }
