from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from app.api.auth import require_workspace_role
from app.api.deps import get_session
from app.core.config import settings
from app.models.models import ApiEndpoint, Target, User, WorkspaceRole
from app.scanners import runner
from app.scanners.discovery import discover_endpoints

router = APIRouter(prefix="/api/discovery", tags=["discovery"])


def _get_target(target_id: int, session: Session) -> Target:
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    return target


def upsert_endpoints(session: Session, target_id: int, branch: str, discovered: list[dict]) -> list[ApiEndpoint]:
    """Persist discovered endpoints (upsert on target+branch+method+route+file_path),
    returning the subset that are new since the last run (first_seen == last_seen
    on this call, i.e. just created) -- same net-new pattern already used for
    Finding dedup and PR Guardrail."""
    existing = {
        (e.method, e.route, e.file_path): e
        for e in session.exec(
            select(ApiEndpoint).where(ApiEndpoint.target_id == target_id, ApiEndpoint.branch == branch)
        ).all()
    }

    now = datetime.utcnow()
    new_endpoints: list[ApiEndpoint] = []
    for item in discovered:
        key = (item["method"], item["route"], item["file"])
        existing_row = existing.get(key)
        if existing_row:
            existing_row.last_seen = now
            existing_row.line = item.get("line")
            session.add(existing_row)
        else:
            row = ApiEndpoint(
                target_id=target_id,
                branch=branch,
                framework=item["framework"],
                method=item["method"],
                route=item["route"],
                file_path=item["file"],
                line=item.get("line"),
                first_seen=now,
                last_seen=now,
            )
            session.add(row)
            new_endpoints.append(row)
            existing[key] = row

    session.commit()
    for row in new_endpoints:
        session.refresh(row)
    return new_endpoints


@router.post("/{target_id}")
def run_discovery(
    target_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    """Run discovery against the target's default branch, upsert results, and
    report which endpoints are new since the last run."""
    target = _get_target(target_id, session)
    repo_path = runner.clone_repo(target.repo_url, target.default_branch, settings.github_token)
    discovered = discover_endpoints(repo_path)
    new_endpoints = upsert_endpoints(session, target_id, target.default_branch, discovered)

    all_endpoints = session.exec(
        select(ApiEndpoint).where(ApiEndpoint.target_id == target_id, ApiEndpoint.branch == target.default_branch)
    ).all()
    new_ids = {e.id for e in new_endpoints}
    return {
        "target_id": target_id,
        "count": len(all_endpoints),
        "new_count": len(new_endpoints),
        "endpoints": [
            {
                "id": e.id,
                "framework": e.framework,
                "method": e.method,
                "route": e.route,
                "file": e.file_path,
                "line": e.line,
                "is_new": e.id in new_ids,
                "first_seen": e.first_seen,
                "last_seen": e.last_seen,
            }
            for e in all_endpoints
        ],
    }


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
