from fastapi import APIRouter, Depends
from sqlmodel import Session

from app.api.deps import get_session, require_workspace
from app.core.ingestion import ingest_findings
from app.core.rate_limit import enforce_rate_limit
from app.models.models import Scan, Target, Workspace
from app.scanners.parsers import parse_sarif

router = APIRouter(prefix="/api/ingest", tags=["ingest"])

# Generous enough not to break a normal CI pipeline (multiple tools/jobs
# pushing SARIF per commit) while still bounding ingestion volume per
# workspace key.
INGEST_RATE_LIMIT = 60
INGEST_RATE_WINDOW_SECONDS = 60


@router.post("/{target_id}")
def push_ingest(
    target_id: int,
    payload: dict,
    tool: str = "sarif",
    branch: str = "main",
    session: Session = Depends(get_session),
    workspace: Workspace = Depends(require_workspace),
):
    """CI/CD push endpoint: accepts SARIF from GitHub Actions/GitLab CI/Jenkins.

    Secured via Workspace API Key (X-API-Key header) per architecture spec.
    """
    enforce_rate_limit(
        key=f"ingest:workspace:{workspace.id}",
        limit=INGEST_RATE_LIMIT,
        window_seconds=INGEST_RATE_WINDOW_SECONDS,
    )

    target = session.get(Target, target_id)
    if not target or target.workspace_id != workspace.id:
        return {"error": "target not found in this workspace"}

    parsed = parse_sarif(payload)
    scan = Scan(target_id=target.id, tool=tool, branch=branch, status="running")
    session.add(scan)
    session.commit()
    session.refresh(scan)

    count = ingest_findings(session, target, scan, tool=tool, branch=branch, parsed=parsed)
    return {"scan_id": scan.id, "ingested": count}
