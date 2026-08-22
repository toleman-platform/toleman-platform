"""Issue #109: the public API -- versioned, token-authenticated
(`Authorization: Bearer <token>`, see app.api.auth.current_api_token_user),
for third-party/scripted integrations. Distinct from the internal `/api/*`
routers the frontend calls (session-cookie authenticated).

v1 is deliberately a curated read-mostly surface (targets/findings/scans)
plus one write endpoint (trigger a scan, gated by a read_write-scoped
token) rather than exposing every internal endpoint -- narrower surface to
secure and keep stable across internal refactors. `/api/public/v1` so a
breaking v2 can exist alongside v1 rather than forcing every integration
to update in lockstep.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from app.api.auth import accessible_workspace_ids, current_api_token_user, require_api_token_write_scope
from app.api.deps import get_session
from app.core.rate_limit import enforce_rate_limit
from app.models.models import Finding, Scan, Target, User
from app.scanners import parsers
from app.core.tool_usage import tools_for_surface
from app.tasks.scan_tasks import run_scan

router = APIRouter(prefix="/api/public/v1", tags=["public-api"])

PARSER_MAP = parsers.PARSER_MAP


def _get_target_scoped(target_id: int, session: Session, user: User) -> Target:
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and target.workspace_id not in ws_ids:
        raise HTTPException(status_code=404, detail="target not found")
    return target


@router.get("/targets")
def list_targets(session: Session = Depends(get_session), user: User = Depends(current_api_token_user)):
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return []
    query = select(Target)
    if ws_ids is not None:
        query = query.where(Target.workspace_id.in_(ws_ids))
    return session.exec(query).all()


@router.get("/targets/{target_id}")
def get_target(target_id: int, session: Session = Depends(get_session), user: User = Depends(current_api_token_user)):
    return _get_target_scoped(target_id, session, user)


@router.get("/findings")
def list_findings(
    target_id: int | None = None,
    severity: str | None = None,
    state: str | None = None,
    page: int = 1,
    page_size: int = 25,
    session: Session = Depends(get_session),
    user: User = Depends(current_api_token_user),
):
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return {"items": [], "total": 0}

    query = select(Finding)
    if ws_ids is not None:
        query = query.join(Target, Target.id == Finding.target_id).where(Target.workspace_id.in_(ws_ids))
    if target_id is not None:
        query = query.where(Finding.target_id == target_id)
    if severity is not None:
        query = query.where(Finding.severity == severity)
    if state is not None:
        query = query.where(Finding.state == state)

    total = len(session.exec(query).all())
    page_size = max(1, min(page_size, 100))
    items = session.exec(query.offset((max(page, 1) - 1) * page_size).limit(page_size)).all()
    return {"items": items, "total": total}


@router.get("/findings/{finding_id}")
def get_finding(finding_id: int, session: Session = Depends(get_session), user: User = Depends(current_api_token_user)):
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    # A finding has no workspace_id of its own -- scope via its target,
    # same 404-shaped hiding as every other workspace-owned resource.
    _get_target_scoped(finding.target_id, session, user)
    return finding


@router.get("/scans/{scan_id}")
def get_scan(scan_id: int, session: Session = Depends(get_session), user: User = Depends(current_api_token_user)):
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    _get_target_scoped(scan.target_id, session, user)
    return scan


# Same limit as the internal POST /api/scans/run -- a public-API token
# dispatching scans still clones+shells a scanner subprocess per call, the
# rate concern this limit exists for doesn't change based on caller type.
SCAN_RUN_RATE_LIMIT = 10
SCAN_RUN_RATE_WINDOW_SECONDS = 60


@router.post("/scans")
def trigger_scan(
    target_id: int,
    tool: str,
    session: Session = Depends(get_session),
    user: User = Depends(current_api_token_user),
    _write_scope: None = Depends(require_api_token_write_scope),
):
    """Requires a read_write-scoped token (see require_api_token_write_scope)
    -- the default token scope is read-only, so a caller must have
    deliberately requested write access at token-creation time."""
    enforce_rate_limit(
        key=f"public_api_scan_run:user:{user.id}",
        limit=SCAN_RUN_RATE_LIMIT,
        window_seconds=SCAN_RUN_RATE_WINDOW_SECONDS,
    )

    target = _get_target_scoped(target_id, session, user)
    if tool not in PARSER_MAP:
        raise HTTPException(status_code=400, detail=f"unsupported tool: {tool}")
    # (#232) Same gate as the internal POST /api/scans/run -- an assignment
    # disabling a tool for on_demand_scan must hold regardless of which
    # authenticated caller is asking, or a public API token becomes a way to
    # route around a workspace's own configuration.
    if tool not in tools_for_surface(session, target.workspace_id, "on_demand_scan"):
        raise HTTPException(
            status_code=400, detail=f"{tool} is disabled for on-demand scanning in this workspace"
        )

    scan = Scan(target_id=target.id, tool=tool, branch=target.default_branch, status="running")
    session.add(scan)
    session.commit()
    session.refresh(scan)

    run_scan.delay(target_id=target.id, tool=tool, scan_id=scan.id)

    return {"scan_id": scan.id, "status": scan.status}
