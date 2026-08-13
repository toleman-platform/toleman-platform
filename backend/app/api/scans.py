from fastapi import APIRouter, Depends, Request
from sqlmodel import Session

from app.api.auth import current_user
from app.api.deps import get_session
from app.core.config import settings
from app.core.ingestion import ingest_findings
from app.core.rate_limit import enforce_rate_limit
from app.models.models import Scan, Target, User
from app.scanners import parsers, runner

router = APIRouter(prefix="/api/scans", tags=["scans"])

PARSER_MAP = parsers.PARSER_MAP

# Each request here clones the target repo and spawns a scanner subprocess,
# so this needs a tighter limit than plain API reads -- generous enough for
# a human triggering ad-hoc scans, tight enough to bound concurrent
# clone+subprocess load per user.
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
    """Pull/Native scan: clone target repo, execute CLI tool, ingest results.

    Runs synchronously for MVP simplicity; production path is the Celery task
    in app/tasks/scan_tasks.py (used by scheduled cron scans).
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

    try:
        repo_path = runner.clone_repo(target.repo_url, target.default_branch, settings.github_token)
        raw = runner.run_tool(tool, repo_path)
        parsed = PARSER_MAP[tool](raw)
        count = ingest_findings(session, target, scan, tool=tool, branch=target.default_branch, parsed=parsed)
        return {"scan_id": scan.id, "ingested": count}
    except Exception as exc:
        scan.status = "failed"
        session.add(scan)
        session.commit()
        return {"error": str(exc), "scan_id": scan.id}
