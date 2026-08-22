from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlmodel import Session, func, select

from app.api.auth import accessible_workspace_ids, current_user
from app.api.deps import get_session
from app.core import scan_eta
from app.core.async_jobs import create_running_row
from app.core.rate_limit import enforce_rate_limit
from app.core.staleness import mark_stale_if_needed
from app.models.models import Scan, Target, User
from app.core.tool_usage import tools_for_surface
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

    Aggregated in SQL rather than in Python (senior-review pass, #220): the
    original version selected every Scan row -- target_id, tool,
    started_at, completed_at -- for every accessible target and grouped it
    in the app process. That scales with total scan history, not with the
    number of targets: a target scanned nightly by CI for a year sends
    hundreds of near-identical rows over the wire on every single page
    load of the Scans page, just to be collapsed back down to one
    timestamp and a handful of tool names. The two queries below return
    at most one row per (target, tool) pair and one row per target,
    respectively, regardless of how many times each has actually run.
    Response shape is byte-for-byte identical -- see
    tests/test_scans_summary.py, written against the old implementation
    before this rewrite specifically so behavior could be pinned rather
    than re-derived.
    """
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return {}

    def scoped(query):
        if ws_ids is not None:
            return query.join(Target, Target.id == Scan.target_id).where(Target.workspace_id.in_(ws_ids))
        return query

    # One row per (target, tool) ever run, not one row per scan -- this is
    # the query that used to return the whole table.
    tool_rows = session.exec(
        scoped(select(Scan.target_id, Scan.tool).distinct())
    ).all()

    # A still-"running" scan has no completed_at yet -- coalesce to
    # started_at in SQL so "last scanned" reflects the most recent attempt
    # per target, not just settled ones, without pulling every row to do
    # that comparison in Python.
    last_scan_column = func.coalesce(Scan.completed_at, Scan.started_at)
    last_scan_rows = session.exec(
        scoped(select(Scan.target_id, func.max(last_scan_column)).group_by(Scan.target_id))
    ).all()

    tools_by_target: dict[int, set[str]] = {}
    for target_id, tool in tool_rows:
        tools_by_target.setdefault(target_id, set()).add(tool)

    last_scan_by_target = dict(last_scan_rows)

    return {
        str(target_id): {
            # started_at/completed_at are naive UTC datetimes (datetime.utcnow(),
            # see the Scan model) -- append "Z" explicitly so the frontend's
            # `new Date(...)` (lib/utils.ts's timeAgo) parses this as UTC
            # instead of local time, which would silently skew "last scanned"
            # by the server's UTC offset.
            "last_scan_at": (
                last_scan_by_target[target_id].isoformat() + "Z"
                if last_scan_by_target.get(target_id) is not None
                else None
            ),
            "tools": sorted(tools),
        }
        for target_id, tools in tools_by_target.items()
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
    # (#232) The request always names a tool explicitly -- there is no
    # "tools omitted, use the workspace default" case for this endpoint,
    # since each button in the UI dispatches one specific tool. So the
    # assignment's role here is a gate, not a default: an explicitly
    # requested tool that the workspace has disabled for on_demand_scan is
    # refused loudly, the same way an unsupported tool already is above --
    # never silently run anyway (that would be GH-01 again) and never
    # silently swapped for something else (that would drop what the user
    # actually asked for, which the issue calls out as its own version of
    # the same bug).
    if tool not in tools_for_surface(session, target.workspace_id, "on_demand_scan"):
        return {"error": f"{tool} is disabled for on-demand scanning in this workspace"}

    scan = create_running_row(
        session, Scan(target_id=target.id, tool=tool, branch=target.default_branch, status="running")
    )

    run_scan.delay(target_id=target.id, tool=tool, scan_id=scan.id)

    return JSONResponse(status_code=202, content={"scan_id": scan.id, "status": scan.status})


@router.get("/active")
def active_scans(
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Every scan currently running, grouped by target (#212).

    A scan dispatched from the Scans page used to be invisible everywhere
    else in the app: Targets showed "last scanned 3 days ago" while a scan
    was in flight, and the target detail page showed nothing at all. This is
    what lets any surface render running state without having been the one
    that triggered it.

    Stale rows are swept here as well as in the single-scan poll. This
    endpoint is read by list views, so it is often the first thing to touch a
    row that a dead worker left "running" -- without the sweep those rows
    would render as permanently in-flight, which is indistinguishable from a
    hung platform.

    Workspace-scoped like every other GET/list over workspace-owned
    resources (None = admin/no filter, [] = no memberships yet).
    """
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return {}

    query = select(Scan).where(Scan.status == "running")
    if ws_ids is not None:
        query = query.join(Target, Target.id == Scan.target_id).where(Target.workspace_id.in_(ws_ids))
    running = session.exec(query).all()

    by_target: dict[int, list] = {}
    for scan in running:
        # Re-check after the sweep: a row that just timed out is no longer
        # active and must not be reported as such.
        if mark_stale_if_needed(session, scan):
            continue
        by_target.setdefault(scan.target_id, []).append(
            {
                "scan_id": scan.id,
                "tool": scan.tool,
                "branch": scan.branch,
                "started_at": scan.started_at.isoformat() + "Z",
                **scan_eta.progress_for(session, scan),
            }
        )

    return {str(target_id): scans for target_id, scans in by_target.items()}


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
    # A row swept to "failed" here carries its timeout reason in `error`,
    # which the response already surfaces as error_message -- the UI shows
    # that instead of a spinner that would never resolve.
    mark_stale_if_needed(session, scan)
    return {
        "scan_id": scan.id,
        "target_id": scan.target_id,
        "tool": scan.tool,
        "branch": scan.branch,
        "status": scan.status,
        "findings_count": scan.findings_count,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "error_message": scan.error,
        **scan_eta.progress_for(session, scan),
    }
