"""Lazy stale-job detection (#153).

Scan/DiscoveryRun/SbomRun/PipelineIntegrationBatch all share the same
create-row(status="running")-then-dispatch-via-.delay() pattern (see
ARCHITECTURE.md's "Async long-running work"). If the dispatched task never
actually reaches a worker -- a worker listening on the wrong queue, a worker
process that died mid-task -- the row is left "running" forever with no
error and no indication anything is wrong beyond an indefinite frontend
spinner. This was caught live: a misconfigured local worker left 27 real
jobs stuck this way.

There's no Celery beat/cron in this project to sweep for this proactively,
so instead this checks lazily on read: any GET endpoint that serves a
single tracking row calls `mark_stale_if_needed` before building its
response, so the first poll after the timeout window flips the row to
"failed" rather than leaving it stuck.
"""
from datetime import datetime, timedelta

from sqlmodel import Session

from app.core.config import settings


def mark_stale_if_needed(session: Session, row, message: str | None = None) -> bool:
    """If `row.status == "running"` and it's been running longer than
    `settings.stale_job_timeout_seconds`, marks it failed and returns True.
    Otherwise returns False and leaves `row` untouched.

    Works across Scan/DiscoveryRun/SbomRun/PipelineIntegrationBatch despite
    their differing schemas: all four have `status`/`started_at`, and
    `completed_at`/`error` are set via getattr/hasattr so this doesn't break
    on PipelineIntegrationBatch, which has no `error` column.
    """
    if row.status != "running":
        return False

    age = datetime.utcnow() - row.started_at
    if age < timedelta(seconds=settings.stale_job_timeout_seconds):
        return False

    row.status = "failed"
    if hasattr(row, "completed_at"):
        row.completed_at = datetime.utcnow()
    if hasattr(row, "error"):
        row.error = message or (
            f"Timed out: no update received within "
            f"{settings.stale_job_timeout_seconds // 60} minutes"
        )
    session.add(row)
    session.commit()
    session.refresh(row)
    return True
