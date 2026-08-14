from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlmodel import Session, select

from app.api.auth import accessible_workspace_ids, current_user
from app.api.deps import get_session
from app.core.rate_limit import enforce_rate_limit
from app.models.models import Scan, Target, User
from app.scanners import parsers
from app.tasks.scan_tasks import run_scan

router = APIRouter(prefix="/api/scans", tags=["scans"])

PARSER_MAP = parsers.PARSER_MAP


@router.get("/summary")
def scans_summary(
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Per-target scan history summary for the Scans page rebuild (#120):
    last-scanned timestamp + the distinct set of tools ever run against each
    target, keyed by target_id. The old flat scan-trigger grid had no way to
    show this at all; the new filter bar's "last scanned" filter and each
    target card's sub-line both need real data here, not a guess.

    Workspace-scoped like every other GET/list endpoint over workspace-owned
    resources (accessible_workspace_ids: None = admin/no filter, [] = no
    memberships yet -> nothing to summarize).
    """
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return {}

    query = select(Scan.target_id, Scan.tool, Scan.started_at, Scan.completed_at)
    if ws_ids is not None:
        query = query.join(Target, Target.id == Scan.target_id).where(Target.workspace_id.in_(ws_ids))
    rows = session.exec(query).all()

    summary: dict[int, dict] = {}
    for target_id, tool, started_at, completed_at in rows:
        entry = summary.setdefault(target_id, {"last_scan_at": None, "tools": set()})
        entry["tools"].add(tool)
        # A still-"running" scan has no completed_at yet -- fall back to
        # started_at so "last scanned" reflects the most recent attempt, not
        # just settled ones.
        ts = completed_at or started_at
        if ts is not None and (entry["last_scan_at"] is None or ts > entry["last_scan_at"]):
            entry["last_scan_at"] = ts

    return {
        str(target_id): {
            # started_at/completed_at are naive UTC datetimes (datetime.utcnow(),
            # see the Scan model) -- append "Z" explicitly so the frontend's
            # `new Date(...)` (lib/utils.ts's timeAgo) parses this as UTC
            # instead of local time, which would silently skew "last scanned"
            # by the server's UTC offset.
            "last_scan_at": v["last_scan_at"].isoformat() + "Z" if v["last_scan_at"] else None,
            "tools": sorted(v["tools"]),
        }
        for target_id, v in summary.items()
    }

# Each request here dispatches a Celery task that clones the target repo and
# spawns a scanner subprocess, so this needs a tighter limit than plain API
# reads -- generous enough for a human triggering ad-hoc scans, tight enough
# to bound concurrent clone+subprocess load on the worker pool.
SCAN_RUN_RATE_LIMIT = 10
SCAN_RUN_RATE_WINDOW_SECONDS = 60


@router.post("/run")
def run_native_scan(
    target_id: int,
    tool: str,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Pull/Native scan: dispatch a Celery task to clone the target repo,
    execute the CLI tool, and ingest results (#59).

    Previously ran the clone+scan synchronously inside this handler -- a
    plain `def` route, so FastAPI ran it in its threadpool, but a handful of
    concurrent scan requests was enough to exhaust that pool and stall the
    whole API. Now this just validates input, creates the Scan row
    (status="running"), dispatches app.tasks.scan_tasks.run_scan via
    .delay(), and returns immediately with the scan's id. Poll
    GET /api/scans/{scan_id} until status leaves "running".
    """
    enforce_rate_limit(
        key=f"scan_run:user:{user.id}",
        limit=SCAN_RUN_RATE_LIMIT,
        window_seconds=SCAN_RUN_RATE_WINDOW_SECONDS,
    )

    target = session.get(Target, target_id)
    if not target:
        return {"error": "target not found"}
    if tool not in PARSER_MAP:
        return {"error": f"unsupported tool: {tool}"}

    scan = Scan(target_id=target.id, tool=tool, branch=target.default_branch, status="running")
    session.add(scan)
    session.commit()
    session.refresh(scan)

    run_scan.delay(target_id=target.id, tool=tool, scan_id=scan.id)

    return JSONResponse(status_code=202, content={"scan_id": scan.id, "status": scan.status})


@router.get("/{scan_id}")
def get_scan(
    scan_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Poll target for the async scan dispatched by POST /run above."""
    scan = session.get(Scan, scan_id)
    if not scan:
        return {"error": "scan not found"}
    return {
        "scan_id": scan.id,
        "target_id": scan.target_id,
        "tool": scan.tool,
        "branch": scan.branch,
        "status": scan.status,
        "findings_count": scan.findings_count,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
    }
