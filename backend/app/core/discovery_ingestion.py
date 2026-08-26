from datetime import UTC, datetime
from app.core.time import utcnow

from sqlmodel import Session, select

from app.models.models import ApiEndpoint


def upsert_endpoints(session: Session, target_id: int, branch: str, discovered: list[dict]) -> list[ApiEndpoint]:
    """Persist discovered endpoints (upsert on target+branch+method+route+file_path),
    returning the subset that are new since the last run (first_seen == last_seen
    on this call, i.e. just created) -- same net-new pattern already used for
    Finding dedup and PR Guardrail.

    Extracted from app/api/discovery.py (#59) so both the API layer and
    app.tasks.discovery_tasks.run_discovery (the Celery task that now does
    the actual clone+discover work) call the exact same logic instead of two
    copies drifting apart -- app.api.discovery still re-exports this name so
    existing imports/tests keep working.
    """
    existing = {
        (e.method, e.route, e.file_path): e
        for e in session.exec(
            select(ApiEndpoint).where(ApiEndpoint.target_id == target_id, ApiEndpoint.branch == branch)
        ).all()
    }

    now = utcnow()
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
