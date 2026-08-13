import subprocess
from datetime import datetime

from sqlmodel import Session, select

from app.core.config import settings
from app.core.db import engine
from app.core.sbom_ingestion import upsert_components
from app.models.models import SbomComponent, SbomRun, Target
from app.scanners import runner
from app.scanners.parsers import parse_trivy_sbom
from app.tasks.celery_app import celery_app

# Same retry rationale as app/tasks/scan_tasks.py's RETRYABLE_EXCEPTIONS:
# only a `git clone` failure (transient network/remote issue) is worth
# retrying. RepoCloneError (bad repo_url/branch) and anything else are
# deterministic and will fail identically on retry.
RETRYABLE_EXCEPTIONS = (subprocess.CalledProcessError,)


@celery_app.task(
    name="app.tasks.sbom_tasks.run_sbom_generation",
    bind=True,
    autoretry_for=RETRYABLE_EXCEPTIONS,
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True,
    max_retries=3,
)
def run_sbom_generation(self, target_id: int, run_id: int):
    """Async counterpart to the previously-synchronous POST
    /api/sbom/{target_id} handler (#59): clone the target's default branch,
    run trivy's CycloneDX SBOM scan, upsert the components, and update the
    SbomRun row the endpoint already created so
    GET /api/sbom/{target_id}/runs/{run_id} can report completion.
    """
    with Session(engine) as session:
        run = session.get(SbomRun, run_id)
        if not run:
            return {"error": "sbom run not found"}

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
                target.repo_url, target.default_branch, settings.github_token, scan_id=f"sbom-{run.id}"
            )
            raw = runner.run_tool("trivy-sbom", repo_path)
            discovered = parse_trivy_sbom(raw)
            new_components = upsert_components(session, target_id, target.default_branch, discovered)

            all_count = len(
                session.exec(
                    select(SbomComponent).where(
                        SbomComponent.target_id == target_id, SbomComponent.branch == target.default_branch
                    )
                ).all()
            )

            run.status = "completed"
            run.count = all_count
            run.new_count = len(new_components)
            run.new_ids = ",".join(str(c.id) for c in new_components)
            run.completed_at = datetime.utcnow()
            session.add(run)
            session.commit()
            return {"run_id": run.id, "count": all_count, "new_count": len(new_components)}
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
