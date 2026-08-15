from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlmodel import Session, select

from app.api.auth import require_workspace_role
from app.api.deps import get_session
from app.core.discovery_ingestion import upsert_endpoints  # noqa: F401 -- re-exported, see docstring below
from app.core.staleness import mark_stale_if_needed
from app.models.models import ApiEndpoint, DiscoveryRun, Target, User, WorkspaceRole
from app.tasks.discovery_tasks import run_discovery as run_discovery_task

router = APIRouter(prefix="/api/discovery", tags=["discovery"])

# upsert_endpoints used to be defined in this module; it now lives in
# app.core.discovery_ingestion (#59) so app.tasks.discovery_tasks -- which
# does the actual clone+discover work on a Celery worker -- can import it
# without an app.api.discovery <-> app.tasks.discovery_tasks import cycle.
# Re-imported above (not re-implemented) so `from app.api.discovery import
# upsert_endpoints` (used by tests) keeps working unchanged.


def _get_target(target_id: int, session: Session) -> Target:
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    return target


@router.post("/{target_id}")
def run_discovery(
    target_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    """Dispatch an async API Discovery run (#59) instead of cloning+grepping
    synchronously inside the request handler -- a handful of concurrent
    requests here used to be enough to exhaust FastAPI's threadpool. Creates
    a DiscoveryRun row (status="running"), hands the actual clone+discover
    work to app.tasks.discovery_tasks.run_discovery via .delay(), and
    returns immediately with the run's id. Poll
    GET /api/discovery/{target_id}/runs/{run_id} until status leaves
    "running" to get the same endpoints/new_count payload this used to
    return synchronously."""
    target = _get_target(target_id, session)

    run = DiscoveryRun(target_id=target_id, branch=target.default_branch, status="running")
    session.add(run)
    session.commit()
    session.refresh(run)

    run_discovery_task.delay(target_id=target_id, run_id=run.id)

    return JSONResponse(
        status_code=202,
        content={"run_id": run.id, "target_id": target_id, "status": run.status},
    )


@router.get("/{target_id}/runs/{run_id}")
def get_discovery_run(target_id: int, run_id: int, session: Session = Depends(get_session)):
    """Poll target for an async discovery run dispatched by POST above.
    Once status leaves "running", also returns the same endpoints/new_count
    payload the old synchronous POST used to return directly."""
    run = session.get(DiscoveryRun, run_id)
    if not run or run.target_id != target_id:
        raise HTTPException(status_code=404, detail="discovery run not found")
    mark_stale_if_needed(session, run)

    target = _get_target(target_id, session)
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
def list_discovered_endpoints(target_id: int, session: Session = Depends(get_session)):
    """Persisted results without re-running a scan -- the page should show
    real state on load, not force a re-scan every visit."""
    target = _get_target(target_id, session)
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
            }
            for e in endpoints
        ],
    }
