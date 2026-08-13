import subprocess
from datetime import datetime

from sqlmodel import Session, select

from app.core.config import settings
from app.core.db import engine
from app.core.discovery_ingestion import upsert_endpoints
from app.models.models import ApiEndpoint, DiscoveryRun, Target
from app.scanners import runner
from app.scanners.discovery import discover_endpoints
from app.tasks.celery_app import celery_app

# Same retry rationale as app/tasks/scan_tasks.py's RETRYABLE_EXCEPTIONS:
# only a `git clone` failure (transient network/remote issue) is worth
# retrying. RepoCloneError (bad repo_url/branch) and anything else are
# deterministic and will fail identically on retry.
RETRYABLE_EXCEPTIONS = (subprocess.CalledProcessError,)


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
            raise
        except Exception as exc:
            run.status = "failed"
            # runner.clone_error_message avoids echoing raw subprocess argv/paths
            # (and, historically, an embedded GitHub token) back into run state.
            run.error = runner.clone_error_message(exc)
            run.completed_at = datetime.utcnow()
            session.add(run)
            session.commit()
            return {"error": run.error, "run_id": run.id}
