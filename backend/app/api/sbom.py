from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from app.api.deps import get_session
from app.core.config import settings
from app.models.models import SbomComponent, Target
from app.scanners import runner
from app.scanners.parsers import parse_trivy_sbom

router = APIRouter(prefix="/api/sbom", tags=["sbom"])


def _get_target(target_id: int, session: Session) -> Target:
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    return target


def upsert_components(session: Session, target_id: int, branch: str, discovered: list[dict]) -> list[SbomComponent]:
    """Persist SBOM components (upsert on target+branch+name+version+purl),
    returning the subset that are new since the last run -- same net-new
    pattern used for ApiEndpoint (see upsert_endpoints() in discovery.py)."""
    existing = {
        (c.name, c.version, c.purl): c
        for c in session.exec(
            select(SbomComponent).where(SbomComponent.target_id == target_id, SbomComponent.branch == branch)
        ).all()
    }

    now = datetime.utcnow()
    new_components: list[SbomComponent] = []
    for item in discovered:
        key = (item["name"], item["version"], item["purl"])
        existing_row = existing.get(key)
        if existing_row:
            existing_row.last_seen = now
            existing_row.package_type = item.get("package_type", "")
            session.add(existing_row)
        else:
            row = SbomComponent(
                target_id=target_id,
                branch=branch,
                name=item["name"],
                version=item["version"],
                package_type=item.get("package_type", ""),
                purl=item["purl"],
                first_seen=now,
                last_seen=now,
            )
            session.add(row)
            new_components.append(row)

    session.commit()
    for row in new_components:
        session.refresh(row)
    return new_components


def _serialize(components: list[SbomComponent], new_ids: set[int]) -> list[dict]:
    return [
        {
            "id": c.id,
            "name": c.name,
            "version": c.version,
            "package_type": c.package_type,
            "purl": c.purl,
            "is_new": c.id in new_ids,
            "first_seen": c.first_seen,
            "last_seen": c.last_seen,
        }
        for c in components
    ]


@router.post("/{target_id}")
def generate_sbom(target_id: int, session: Session = Depends(get_session)):
    """Clone the target's default branch, run trivy's CycloneDX SBOM scan,
    upsert components, and report which are new since the last run."""
    target = _get_target(target_id, session)
    repo_path = runner.clone_repo(target.repo_url, target.default_branch, settings.github_token)
    raw = runner.run_tool("trivy-sbom", repo_path)
    discovered = parse_trivy_sbom(raw)
    new_components = upsert_components(session, target_id, target.default_branch, discovered)

    all_components = session.exec(
        select(SbomComponent).where(SbomComponent.target_id == target_id, SbomComponent.branch == target.default_branch)
    ).all()
    new_ids = {c.id for c in new_components}
    return {
        "target_id": target_id,
        "count": len(all_components),
        "new_count": len(new_components),
        "components": _serialize(all_components, new_ids),
    }


@router.get("/{target_id}")
def list_sbom_components(target_id: int, session: Session = Depends(get_session)):
    """Persisted results without re-running a scan -- same GET-reads-persisted-
    state pattern as GET /api/discovery/{target_id}."""
    target = _get_target(target_id, session)
    components = session.exec(
        select(SbomComponent)
        .where(SbomComponent.target_id == target_id, SbomComponent.branch == target.default_branch)
        .order_by(SbomComponent.name)
    ).all()
    return {
        "target_id": target_id,
        "count": len(components),
        "components": _serialize(components, set()),
    }
