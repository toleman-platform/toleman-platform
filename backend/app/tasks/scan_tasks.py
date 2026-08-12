from sqlmodel import Session

from app.core.config import settings
from app.core.db import engine
from app.core.ingestion import ingest_findings
from app.models.models import Scan, Target
from app.scanners import parsers, runner
from app.tasks.celery_app import celery_app

PARSER_MAP = {
    "semgrep": parsers.parse_semgrep,
    "gitleaks": parsers.parse_gitleaks,
    "trivy": parsers.parse_trivy,
    "gosec": parsers.parse_gosec,
}


@celery_app.task(name="app.tasks.scan_tasks.run_scan")
def run_scan(target_id: int, tool: str):
    """Async native scan — used by scheduled cron jobs (e.g. 'Run Trivy Daily at 2 AM')."""
    with Session(engine) as session:
        target = session.get(Target, target_id)
        if not target:
            return {"error": "target not found"}

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
