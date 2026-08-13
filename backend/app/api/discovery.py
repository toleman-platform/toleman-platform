from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from app.api.deps import get_session
from app.core.config import settings
from app.models.models import DiscoveredEndpoint, Target
from app.scanners import runner
from app.scanners.discovery import discover_endpoints

router = APIRouter(prefix="/api/discovery", tags=["discovery"])


def _dedup_key(framework: str, method: str, route: str, file: str) -> str:
    return f"{framework}|{method}|{route}|{file}"


def _serialize(e: DiscoveredEndpoint, is_new: bool) -> dict:
    return {
        "id": e.id,
        "framework": e.framework,
        "method": e.method,
        "route": e.route,
        "file": e.file,
        "line": e.line,
        "is_new": is_new,
        "first_seen": e.first_seen.isoformat(),
        "last_seen": e.last_seen.isoformat(),
    }


@router.get("/{target_id}")
def get_discovered_endpoints(target_id: int, session: Session = Depends(get_session)):
    """Read-only: returns the persisted results of the last scan, no scan triggered."""
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")

    endpoints = session.exec(
        select(DiscoveredEndpoint).where(DiscoveredEndpoint.target_id == target_id)
    ).all()
    endpoints.sort(key=lambda e: (e.file, e.line))

    return {
        "target_id": target_id,
        "count": len(endpoints),
        "endpoints": [_serialize(e, is_new=False) for e in endpoints],
    }


@router.post("/{target_id}")
def run_discovery(target_id: int, session: Session = Depends(get_session)):
    """Runs a real scan, upserts persisted results (same dedup/net-new pattern
    as Finding ingestion: hash exists -> update last_seen, hash new -> create row)."""
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")

    repo_path = runner.clone_repo(target.repo_url, target.default_branch, settings.github_token)
    scanned = discover_endpoints(repo_path)

    new_count = 0
    result_rows: list[tuple[DiscoveredEndpoint, bool]] = []
    seen_keys = set()

    for item in scanned:
        key = _dedup_key(item["framework"], item["method"], item["route"], item["file"])
        seen_keys.add(key)

        existing = session.exec(
            select(DiscoveredEndpoint).where(
                DiscoveredEndpoint.target_id == target_id,
                DiscoveredEndpoint.dedup_key == key,
            )
        ).first()

        if existing:
            existing.last_seen = datetime.utcnow()
            existing.line = item["line"]
            session.add(existing)
            session.commit()
            session.refresh(existing)
            result_rows.append((existing, False))
            continue

        endpoint = DiscoveredEndpoint(
            target_id=target_id,
            dedup_key=key,
            framework=item["framework"],
            method=item["method"],
            route=item["route"],
            file=item["file"],
            line=item["line"],
        )
        session.add(endpoint)
        session.commit()
        session.refresh(endpoint)
        new_count += 1
        result_rows.append((endpoint, True))

    result_rows.sort(key=lambda pair: (pair[0].file, pair[0].line))

    return {
        "target_id": target_id,
        "count": len(result_rows),
        "new_count": new_count,
        "endpoints": [_serialize(e, is_new=is_new) for e, is_new in result_rows],
    }
