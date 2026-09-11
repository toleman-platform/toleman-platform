from sqlmodel import Session

from app.core.db import engine
from app.core.pr_guardrail_executor import execute_pr_guardrail_scan
from app.models.models import Target
from app.tasks.celery_app import celery_app


@celery_app.task(
    name="app.tasks.pr_guardrail_tasks.run_pr_guardrail_scan_task",
    bind=True,
    autoretry_for=(ConnectionError,),
    retry_backoff=True,
    max_retries=2,
)
def run_pr_guardrail_scan_task(self, target_id: int, pr_number: int, pr_scan_id: int | None = None):
    """Real-time counterpart to the on-demand POST /api/pr-guardrail/scan
    route, dispatched from the GitHub webhook handler so the webhook response
    itself stays fast (GitHub expects a response within ~10s).

    pr_scan_id (#401): the webhook handler creates the PRGuardrailScan row
    itself, synchronously, before dispatching this task -- so the dashboard
    has something to show as "running" immediately rather than only once
    this task gets around to running. Passed through so
    execute_pr_guardrail_scan reuses that row instead of creating a second
    one. None for any caller that doesn't pre-create a row (there are none
    left, but the default keeps this task callable the old way)."""
    with Session(engine) as session:
        target = session.get(Target, target_id)
        if not target:
            return {"error": "target not found"}
        return execute_pr_guardrail_scan(target, pr_number, session, pr_scan_id=pr_scan_id)
