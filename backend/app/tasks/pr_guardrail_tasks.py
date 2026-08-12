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
def run_pr_guardrail_scan_task(self, target_id: int, pr_number: int):
    """Real-time counterpart to the on-demand POST /api/pr-guardrail/scan
    route, dispatched from the GitHub webhook handler so the webhook response
    itself stays fast (GitHub expects a response within ~10s)."""
    with Session(engine) as session:
        target = session.get(Target, target_id)
        if not target:
            return {"error": "target not found"}
        return execute_pr_guardrail_scan(target, pr_number, session)
