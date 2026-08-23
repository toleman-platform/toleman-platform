from datetime import UTC, datetime

from sqlmodel import Session, select

from app.models.models import SbomComponent


def upsert_components(
    session: Session,
    target_id: int,
    branch: str,
    discovered: list[dict],
    source: str = "github",
) -> list[SbomComponent]:
    """Persist SBOM components (upsert on target+branch+name+version+purl),
    returning the subset that are new since the last run -- same net-new
    pattern used for ApiEndpoint (see upsert_endpoints() in
    app/core/discovery_ingestion.py).

    Extracted from app/api/sbom.py (#59) so both the API layer and
    app.tasks.sbom_tasks.run_sbom_generation (the Celery task that now does
    the actual clone+scan work) call the exact same logic instead of two
    copies drifting apart -- app.api.sbom still re-exports this name so
    existing imports/tests keep working.
    """
    existing = {
        (c.name, c.version, c.purl): c
        for c in session.exec(
            select(SbomComponent).where(SbomComponent.target_id == target_id, SbomComponent.branch == branch)
        ).all()
    }

    now = datetime.now(UTC).replace(tzinfo=None)
    new_components: list[SbomComponent] = []
    for item in discovered:
        key = (item["name"], item["version"], item["purl"])
        existing_row = existing.get(key)
        if existing_row:
            existing_row.last_seen = now
            existing_row.package_type = item.get("package_type", "")
            # (#227) Union, not overwrite. A component both GitHub's
            # Dependency Graph and an uploaded SBOM report should end up
            # "github,upload" rather than whichever source happened to run
            # second -- the whole point of multiple sources is knowing which
            # found what, and last-writer-wins would erase exactly that.
            existing_row.source = _merge_sources(existing_row.source, source)
            session.add(existing_row)
        else:
            row = SbomComponent(
                target_id=target_id,
                branch=branch,
                name=item["name"],
                version=item["version"],
                package_type=item.get("package_type", ""),
                purl=item["purl"],
                source=source,
                first_seen=now,
                last_seen=now,
            )
            session.add(row)
            new_components.append(row)

    session.commit()
    for row in new_components:
        session.refresh(row)
    return new_components

# Stable ordering so the stored value is comparable across runs -- "a,b" and
# "b,a" describing the same thing would defeat any query or UI grouping on it.
_SOURCE_ORDER = ("github", "upload")


def _merge_sources(existing: str, incoming: str) -> str:
    seen = {s for s in (existing or "").split(",") if s}
    seen.update(s for s in (incoming or "").split(",") if s)
    known = [s for s in _SOURCE_ORDER if s in seen]
    # Anything unrecognised is preserved rather than dropped: a source added
    # later without updating _SOURCE_ORDER should degrade to unordered, not
    # to silently discarded provenance.
    return ",".join(known + sorted(seen - set(_SOURCE_ORDER)))
