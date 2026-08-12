from fastapi import APIRouter, Depends
from sqlmodel import Session

from app.api.deps import get_session
from app.core.config import settings
from app.core.ingestion import ingest_findings
from app.models.models import Scan, Target
from app.scanners import parsers, runner

router = APIRouter(prefix="/api/scans", tags=["scans"])

PARSER_MAP = {
    "semgrep": parsers.parse_semgrep,
    "gitleaks": parsers.parse_gitleaks,
    "trivy": parsers.parse_trivy,
    "gosec": parsers.parse_gosec,
}


@router.post("/run")
def run_native_scan(target_id: int, tool: str, session: Session = Depends(get_session)):
    """Pull/Native scan: clone target repo, execute CLI tool, ingest results.

    Runs synchronously for MVP simplicity; production path is the Celery task
    in app/tasks/scan_tasks.py (used by scheduled cron scans).
    """
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
