import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
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


def _aggregate_org_components(session: Session) -> tuple[list[dict], dict, list[Target], dict[int, Target]]:
    """Group every persisted SbomComponent (default branch, per target) by
    (name, version, purl) across all targets -- read-only, no scans triggered.
    Mirrors the per-target GET's persisted-state-only pattern, just widened to
    every Target row (this app has no workspace-scoping on list_targets() yet,
    so 'org-wide' here means every Target in the DB, matching that)."""
    targets = session.exec(select(Target)).all()
    targets_by_id = {t.id: t for t in targets}

    # Only the target's own default branch counts as "current" SBOM state,
    # same as the per-target GET/export -- fetch per target rather than one
    # unscoped query so a stale non-default-branch row never leaks in.
    groups: dict[tuple[str, str, str], dict] = {}
    targets_with_sbom: set[int] = set()
    for target in targets:
        components = session.exec(
            select(SbomComponent).where(
                SbomComponent.target_id == target.id, SbomComponent.branch == target.default_branch
            )
        ).all()
        if components:
            targets_with_sbom.add(target.id)
        for c in components:
            key = (c.name, c.version, c.purl)
            group = groups.get(key)
            if group is None:
                group = {
                    "name": c.name,
                    "version": c.version,
                    "purl": c.purl,
                    "package_type": c.package_type,
                    "target_ids": [],
                }
                groups[key] = group
            if target.id not in group["target_ids"]:
                group["target_ids"].append(target.id)

    ordered = sorted(groups.values(), key=lambda g: (g["name"], g["version"]))
    summary = {
        "targets_with_sbom_count": len(targets_with_sbom),
        "total_targets_count": len(targets),
        "unique_component_count": len(ordered),
    }
    return ordered, summary, targets, targets_by_id


# NOTE: these two literal routes ("/org", "/org/export") MUST be registered
# before the "/{target_id}" routes below. The path is declared as a bare
# "/{target_id}" (no ":int" converter in the path itself), so Starlette's
# routing matches it against ANY string first -- "org" would otherwise match
# "/{target_id}" and only fail afterwards, at FastAPI's int-parsing
# validation step, returning a 422 instead of ever reaching this handler.
@router.get("/org")
def get_org_sbom(session: Session = Depends(get_session)):
    """Aggregate ALREADY-PERSISTED SbomComponent rows across every target's
    default branch -- read-only, does not trigger any scan. Lets a security
    engineer answer 'which of my repos still use package X@version' across
    the whole account at once."""
    ordered, summary, _targets, targets_by_id = _aggregate_org_components(session)
    components = [
        {
            "name": g["name"],
            "version": g["version"],
            "purl": g["purl"],
            "package_type": g["package_type"],
            "targets": [
                {"id": tid, "name": targets_by_id[tid].name} for tid in g["target_ids"] if tid in targets_by_id
            ],
        }
        for g in ordered
    ]
    return {**summary, "components": components}


@router.get("/org/export")
def export_org_sbom(session: Session = Depends(get_session)):
    """Downloadable JSON of the org-wide aggregation -- same persisted data as
    GET /api/sbom/org, just as a file. Not CycloneDX since it spans multiple
    repos; a custom schema is reasonable here."""
    ordered, summary, targets, _targets_by_id = _aggregate_org_components(session)
    document = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "targets": [{"id": t.id, "name": t.name} for t in targets],
        "components": [
            {
                "name": g["name"],
                "version": g["version"],
                "purl": g["purl"],
                "package_type": g["package_type"],
                "target_ids": g["target_ids"],
            }
            for g in ordered
        ],
        **summary,
    }
    return JSONResponse(
        content=document,
        headers={"Content-Disposition": 'attachment; filename="sbom-org-wide.json"'},
    )


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


@router.get("/{target_id}/export")
def export_sbom(target_id: int, session: Session = Depends(get_session)):
    """Downloadable CycloneDX 1.5 SBOM built from persisted components --
    the same real data shown on the page, not a re-fetch or re-scan."""
    target = _get_target(target_id, session)
    components = session.exec(
        select(SbomComponent)
        .where(SbomComponent.target_id == target_id, SbomComponent.branch == target.default_branch)
        .order_by(SbomComponent.name)
    ).all()

    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "component": {"type": "application", "name": target.name},
        },
        "components": [
            {
                "type": "library",
                "name": c.name,
                "version": c.version,
                "purl": c.purl,
                "properties": [{"name": "osp:packageType", "value": c.package_type}],
            }
            for c in components
        ],
    }

    filename = f"sbom-{target.name}-{target.default_branch}.json"
    return JSONResponse(
        content=document,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
