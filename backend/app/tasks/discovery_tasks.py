import logging
import subprocess
from datetime import datetime

from sqlmodel import Session, select

from app.core.config import settings
from app.core.db import engine
from app.core.discovery_ingestion import upsert_endpoints
from app.core.notifications import dispatch_notification
from app.models.models import ApiEndpoint, DiscoveryRun, NotificationEventType, Target
from app.scanners import runner
from app.scanners.discovery import discover_endpoints
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

# Same retry rationale as app/tasks/scan_tasks.py's RETRYABLE_EXCEPTIONS:
# only a `git clone` failure whose cause looks transient (network/remote
# issue) is worth retrying. RepoCloneError -- bad repo_url/branch, or a
# permanent remote failure classified by runner._classify_clone_stderr
# (missing credentials, deleted repo, nonexistent branch, access denied) --
# and anything else are deterministic and will fail identically on retry.
RETRYABLE_EXCEPTIONS = (subprocess.CalledProcessError,)


def _notify_discovery_failure(session: Session, target: Target, error: str) -> None:
    """Issue #73 scan_failure trigger, same pattern as
    app.tasks.scan_tasks._notify_scan_failure: fires once a DiscoveryRun is
    permanently marked "failed", never on a transient retry."""
    try:
        dispatch_notification(
            session,
            workspace_id=target.workspace_id,
            event_type=NotificationEventType.SCAN_FAILURE,
            subject=f"API discovery failed: {target.name}",
            detail=error,
        )
    except Exception:
        logger.exception("scan_failure notification dispatch failed for target %s", target.id)


@celery_app.task(
    name="app.tasks.discovery_tasks.run_discovery",
    bind=True,
    autoretry_for=RETRYABLE_EXCEPTIONS,
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True,
    max_retries=3,
)
def run_discovery(self, target_id: int, run_id: int):
    """Async counterpart to the previously-synchronous POST
    /api/discovery/{target_id} handler (#59): clone the target's default
    branch, run discover_endpoints() (static route extraction), upsert the
    results, and update the DiscoveryRun row the endpoint already created
    so GET /api/discovery/{target_id}/runs/{run_id} can report completion.
    """
    with Session(engine) as session:
        run = session.get(DiscoveryRun, run_id)
        if not run:
            return {"error": "discovery run not found"}

        target = session.get(Target, target_id)
        if not target:
            run.status = "failed"
            run.error = "target not found"
            run.completed_at = datetime.utcnow()
            session.add(run)
            session.commit()
            return {"error": "target not found", "run_id": run.id}

        try:
            repo_path = runner.clone_repo(
                target.repo_url, target.default_branch, settings.github_token, scan_id=f"discovery-{run.id}"
            )
            discovered = discover_endpoints(repo_path)
            new_endpoints = upsert_endpoints(session, target_id, target.default_branch, discovered)

            all_count = len(
                session.exec(
                    select(ApiEndpoint).where(
                        ApiEndpoint.target_id == target_id, ApiEndpoint.branch == target.default_branch
                    )
                ).all()
            )

            run.status = "completed"
            run.count = all_count
            run.new_count = len(new_endpoints)
            run.new_ids = ",".join(str(e.id) for e in new_endpoints)
            run.completed_at = datetime.utcnow()
            session.add(run)
            session.commit()
            return {"run_id": run.id, "count": all_count, "new_count": len(new_endpoints)}
        except RETRYABLE_EXCEPTIONS:
            # Transient failure: only mark the run permanently failed once
            # retries are exhausted -- otherwise let it propagate so
            # Celery's autoretry_for schedules the next attempt.
            if self.request.retries >= self.max_retries:
                run.status = "failed"
                run.error = "git clone failed after retries"
                run.completed_at = datetime.utcnow()
                session.add(run)
                session.commit()
                _notify_discovery_failure(session, target, run.error)
            raise
        except Exception as exc:
            run.status = "failed"
            # runner.clone_error_message avoids echoing raw subprocess argv/paths
            # (and, historically, an embedded GitHub token) back into run state.
            run.error = runner.clone_error_message(exc)
            run.completed_at = datetime.utcnow()
            session.add(run)
            session.commit()
            _notify_discovery_failure(session, target, run.error)
            return {"error": run.error, "run_id": run.id}
