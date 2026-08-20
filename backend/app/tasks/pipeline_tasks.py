import logging
import time
from datetime import datetime

from sqlmodel import Session, select

from app.core.crypto import SecretDecryptionError
from app.core.db import engine
from app.core.pipeline_pr import PipelinePrError, open_pipeline_pr
from app.models.models import PipelineIntegrationBatch, PipelineIntegrationBatchItem, PipelineWorkflowTemplate, Target
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

# Each item does a real GitHub API call sequence (branch create + contents
# write + PR open, see app.core.pipeline_pr.open_pipeline_pr) -- firing 20-30
# of those back to back with no pause risks tripping GitHub's secondary rate
# limits. A small fixed delay between items is a much simpler and safer bar
# for a first version than real rate-limit-aware concurrency (parsing
# X-RateLimit-Remaining/Retry-After and backing off dynamically) -- sequential
# processing already keeps this off the request thread (the point of #59's
# Celery pattern), this delay is just being a good citizen towards GitHub on
# top of that.
INTER_ITEM_DELAY_SECONDS = 1.5


@celery_app.task(name="app.tasks.pipeline_tasks.run_pipeline_integration_batch", bind=True)
def run_pipeline_integration_batch(self, batch_id: int):
    """Issue #68: bulk wrapper around #66's per-target open_pipeline_pr.
    Processes every PipelineIntegrationBatchItem for this batch
    sequentially (see INTER_ITEM_DELAY_SECONDS above for why not
    concurrent), skipping targets already `pipeline_integrated` rather than
    re-running/erroring on them, and records a real per-item outcome
    (succeeded/failed/already_integrated) so the batch never just "goes
    away" on a partial failure -- one bad target's 403/network error
    doesn't crash the rest of the batch or leave it stuck at "running"."""
    with Session(engine) as session:
        batch = session.get(PipelineIntegrationBatch, batch_id)
        if not batch:
            return {"error": "batch not found"}

        # Custom Workflow Builder (#35): resolve the batch's chosen template
        # (if any) once, up front -- every item in a rollout shares the same
        # step selection. None (#68's original manual bulk-integrate never
        # sets workflow_template_id) means "use #66's fixed default set",
        # exactly the pre-#35 behavior.
        template_steps: list[str] | None = None
        if batch.workflow_template_id is not None:
            template = session.get(PipelineWorkflowTemplate, batch.workflow_template_id)
            if template:
                template_steps = [s["tool"] for s in template.steps if s.get("enabled")]

        item_rows = session.exec(
            select(PipelineIntegrationBatchItem).where(PipelineIntegrationBatchItem.batch_id == batch_id)
        ).all()

        for idx, item in enumerate(item_rows):
            target = session.get(Target, item.target_id)
            if not target:
                item.status = "failed"
                item.error = "target not found"
                item.completed_at = datetime.utcnow()
                session.add(item)
                batch.failed += 1
                session.add(batch)
                session.commit()
                continue

            if target.pipeline_integrated:
                # #68 scope rule: skip + report, not a failure and not a
                # silent re-run.
                item.status = "already_integrated"
                item.pr_url = target.pipeline_pr_url
                item.completed_at = datetime.utcnow()
                session.add(item)
                batch.already_integrated += 1
                session.add(batch)
                session.commit()
                continue

            item.status = "running"
            session.add(item)
            session.commit()

            try:
                # Only pass steps= when a template applies -- keeps the call
                # shape identical to pre-#35 (open_pipeline_pr(session,
                # target)) for #68's original manual batches, matching what
                # existing tests' fake_open_pipeline_pr(session, target)
                # stand-ins expect.
                if template_steps is not None:
                    result = open_pipeline_pr(session, target, steps=template_steps)
                else:
                    result = open_pipeline_pr(session, target)
                target.pipeline_integrated = True
                target.pipeline_pr_url = result["pr_url"]
                session.add(target)

                item.status = "succeeded"
                item.pr_url = result["pr_url"]
                item.pr_number = result["pr_number"]
                item.completed_at = datetime.utcnow()
                session.add(item)
                batch.succeeded += 1
                session.add(batch)
                session.commit()
            except PipelinePrError as exc:
                session.rollback()
                item = session.get(PipelineIntegrationBatchItem, item.id)
                item.status = "failed"
                item.error = str(exc)
                item.completed_at = datetime.utcnow()
                session.add(item)
                batch.failed += 1
                session.add(batch)
                session.commit()
            except SecretDecryptionError:
                # Distinguished from the generic except below so the batch
                # reports an actionable cause (PLATFORM_ENCRYPTION_KEY
                # mismatch, fixable from Admin > Global Integrations) instead
                # of a raw "unexpected error: ..." traceback string -- this is
                # exactly the failure app.core.crypto.check_encryption_key_health
                # is meant to catch proactively at startup instead of here.
                session.rollback()
                item = session.get(PipelineIntegrationBatchItem, item.id)
                item.status = "failed"
                item.error = (
                    "PLATFORM_ENCRYPTION_KEY mismatch - the GitHub App credentials "
                    "for this target cannot be decrypted with the currently configured "
                    "key. Reconnect the GitHub App in Admin > Global Integrations."
                )
                item.completed_at = datetime.utcnow()
                session.add(item)
                batch.failed += 1
                session.add(batch)
                session.commit()
            except Exception as exc:  # noqa: BLE001 -- last-resort catch so one
                # target's unexpected error (network blip, unhandled GitHub
                # response shape) can't leave the whole batch stuck at
                # "running" forever; every other item still gets processed.
                logger.exception("pipeline integration batch item %s failed unexpectedly", item.id)
                session.rollback()
                item = session.get(PipelineIntegrationBatchItem, item.id)
                item.status = "failed"
                item.error = f"unexpected error: {exc}"
                item.completed_at = datetime.utcnow()
                session.add(item)
                batch.failed += 1
                session.add(batch)
                session.commit()

            if idx < len(item_rows) - 1:
                time.sleep(INTER_ITEM_DELAY_SECONDS)

        batch.status = "completed"
        batch.completed_at = datetime.utcnow()
        session.add(batch)
        session.commit()
        return {"batch_id": batch.id, "succeeded": batch.succeeded, "failed": batch.failed, "already_integrated": batch.already_integrated}
