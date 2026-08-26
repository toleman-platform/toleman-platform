import logging
import subprocess
from datetime import UTC, datetime

from sqlmodel import Session

from app.core.db import engine
from app.core.ai_repo_status import effective_is_ai_repo, refresh_ai_repo_status
from app.core.github import repo_slug_from_url
from app.core.github_token import resolve_github_token
from app.core.ingestion import ingest_findings
from app.core.notifications import dispatch_notification
from app.core.time import utcnow
from app.models.models import NotificationEventType, Scan, Target
from app.scanners import parsers, runner
from app.tasks.celery_app import celery_app

PARSER_MAP = parsers.PARSER_MAP

# Tools that only make sense against an AI/ML repo (#185 gates them). On any
# other target they record a completed scan with zero findings rather than
# running: modelscan would find no model files, and the LLM ruleset would
# find no LLM calls, so running them everywhere is wasted scan budget.
AI_ONLY_TOOLS = ("modelscan", "semgrep-llm")

logger = logging.getLogger(__name__)

# Only subprocess.CalledProcessError is auto-retried: today it can only come from
# runner.clone_repo()'s `git clone` (the only subprocess call in this path that uses
# check=True), which fails on transient network/remote issues (DNS blip, timeout,
# remote 5xx) -- retrying with backoff is exactly the self-healing we want there.
# Other failure classes are NOT retried because a retry can't fix them:
#   - FileNotFoundError (git/semgrep/gitleaks/trivy/gosec binary missing) -- an
#     installation problem, will fail identically every time.
#   - ValueError (unsupported tool) / KeyError (bad PARSER_MAP entry) -- programmer
#     error / bad input, deterministic.
#   - runner.RepoCloneError -- deterministic bad input, same as the
#     ValueError/KeyError cases above. Two sources: clone_repo's own
#     validation (invalid repo_url/branch, rejected before subprocess runs),
#     and a git failure whose stderr names a permanent cause -- missing
#     credentials, deleted repo, nonexistent branch, access denied. That
#     second source is why _classify_clone_stderr exists: those all exit 128
#     like a network blip does, and retrying them four times with backoff
#     bought nothing but fifty identical tracebacks.
#   - json parsing issues are already swallowed inside runner.run_tool.
RETRYABLE_EXCEPTIONS = (subprocess.CalledProcessError,)


def _notify_scan_failure(session: Session, target: Target, tool: str, error: str) -> None:
    """Issue #73 scan_failure trigger: fires once a Scan row is permanently
    marked "failed" (after retries are exhausted, or on a non-transient
    error) -- never on a transient failure that's about to be retried, since
    that isn't really "failed" yet from a user's perspective."""
    try:
        dispatch_notification(
            session,
            workspace_id=target.workspace_id,
            event_type=NotificationEventType.SCAN_FAILURE,
            subject=f"Scan failed: {target.name} ({tool})",
            detail=error,
        )
    except Exception:
        logger.exception("scan_failure notification dispatch failed for target %s", target.id)


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
                target.repo_url, target.default_branch,
                resolve_github_token(session, target.workspace_id, repo_slug_from_url(target.repo_url)) or "",
                scan_id=scan.id,
            )
            # Issue #185: recompute AI-repo detection from the fresh
            # checkout while we have one. Best-effort -- a detection failure
            # must never fail a scan that otherwise succeeded, so the flag
            # simply keeps its previous value.
            try:
                refresh_ai_repo_status(session, target, repo_path=repo_path)
            except Exception:
                logger.exception("AI-repo detection failed for target %s", target.id)

            # Issue #186: modelscan only runs on AI/ML repos. Skipping is
            # recorded as a real completed scan with zero findings rather
            # than a failure -- "this repo has no models to scan" is a
            # legitimate clean result, and a silent skip would leave no
            # evidence the decision was made.
            if tool in AI_ONLY_TOOLS and not effective_is_ai_repo(target):
                scan.status = "completed"
                scan.completed_at = utcnow()
                session.add(scan)
                session.commit()
                return {"scan_id": scan.id, "ingested": 0, "skipped": "not an AI/ML repo"}

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
                scan.error = "git clone failed after retries"
                session.add(scan)
                session.commit()
                _notify_scan_failure(session, target, tool, "git clone failed after retries")
            raise
        except Exception as exc:
            # Non-transient failure -- retrying would fail the same way, so fail now.
            # runner.clone_error_message avoids echoing raw subprocess argv/paths
            # (and, historically, an embedded GitHub token) back into scan state.
            error_message = runner.clone_error_message(exc)
            scan.status = "failed"
            scan.error = error_message
            session.add(scan)
            session.commit()
            _notify_scan_failure(session, target, tool, error_message)
            return {"error": error_message, "scan_id": scan.id}
