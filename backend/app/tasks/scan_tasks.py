import subprocess

from sqlmodel import Session

from app.core.config import settings
from app.core.db import engine
from app.core.ingestion import ingest_findings
from app.models.models import Scan, Target
from app.scanners import parsers, runner
from app.tasks.celery_app import celery_app

PARSER_MAP = parsers.PARSER_MAP

# Only subprocess.CalledProcessError is auto-retried: today it can only come from
# runner.clone_repo()'s `git clone` (the only subprocess call in this path that uses
# check=True), which fails on transient network/remote issues (DNS blip, timeout,
# remote 5xx) -- retrying with backoff is exactly the self-healing we want there.
# Other failure classes are NOT retried because a retry can't fix them:
#   - FileNotFoundError (git/semgrep/gitleaks/trivy/gosec binary missing) -- an
#     installation problem, will fail identically every time.
#   - ValueError (unsupported tool) / KeyError (bad PARSER_MAP entry) -- programmer
#     error / bad input, deterministic.
#   - runner.RepoCloneError (invalid repo_url/branch, rejected by clone_repo's
#     validation before subprocess ever runs) -- deterministic bad input, same
#     as the ValueError/KeyError cases above.
#   - json parsing issues are already swallowed inside runner.run_tool.
RETRYABLE_EXCEPTIONS = (subprocess.CalledProcessError,)


@celery_app.task(
    name="app.tasks.scan_tasks.run_scan",
    bind=True,
    autoretry_for=RETRYABLE_EXCEPTIONS,
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True,
    max_retries=3,
)
def run_scan(self, target_id: int, tool: str, scan_id: int | None = None):
    """Async native scan.

    Two callers:
      - Scheduled cron jobs (e.g. 'Run Trivy Daily at 2 AM') call this with
        no scan_id -- the task creates its own Scan row.
      - POST /api/scans/run (#59) creates the Scan row itself (so it can
        return the id immediately) and passes scan_id here so the task
        updates that same row instead of creating a second one.
    """
    with Session(engine) as session:
        target = session.get(Target, target_id)
        if not target:
            if scan_id is not None:
                existing = session.get(Scan, scan_id)
                if existing:
                    existing.status = "failed"
                    session.add(existing)
                    session.commit()
            return {"error": "target not found"}

        if scan_id is not None:
            scan = session.get(Scan, scan_id)
            if not scan:
                return {"error": "scan not found"}
        else:
            scan = Scan(target_id=target.id, tool=tool, branch=target.default_branch, status="running")
            session.add(scan)
            session.commit()
            session.refresh(scan)

        try:
            repo_path = runner.clone_repo(
                target.repo_url, target.default_branch, settings.github_token, scan_id=scan.id
            )
            raw = runner.run_tool(tool, repo_path)
            parsed = PARSER_MAP[tool](raw)
            for item in parsed:
                item["file_path"] = runner.normalize_file_path(item.get("file_path", ""), repo_path)
            count = ingest_findings(session, target, scan, tool=tool, branch=target.default_branch, parsed=parsed)
            return {"scan_id": scan.id, "ingested": count}
        except RETRYABLE_EXCEPTIONS:
            # Transient failure: only mark the scan permanently failed once retries are
            # exhausted. Otherwise let it propagate so Celery's autoretry_for schedules
            # the next attempt with backoff -- this scan row stays "running" until then.
            if self.request.retries >= self.max_retries:
                scan.status = "failed"
                session.add(scan)
                session.commit()
            raise
        except Exception as exc:
            # Non-transient failure -- retrying would fail the same way, so fail now.
            scan.status = "failed"
            session.add(scan)
            session.commit()
            # runner.clone_error_message avoids echoing raw subprocess argv/paths
            # (and, historically, an embedded GitHub token) back into scan state.
            return {"error": runner.clone_error_message(exc), "scan_id": scan.id}
