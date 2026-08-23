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
from datetime import UTC, datetime, timedelta

from sqlmodel import Session

from app.core.config import settings


def mark_stale_if_needed(session: Session, row, message: str | None = None, failed_status: str = "failed") -> bool:
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

    # PRGuardrailScan (CTX-02's caller) records `created_at` rather than
    # `started_at`, and its terminal-failure state is "error", not "failed" --
    # its status vocabulary is PRGuardrailStatus, shared with the GitHub
    # commit status it maps onto. Both are read via getattr for the same
    # reason `completed_at`/`error` already are: this helper is deliberately
    # schema-tolerant so one sweep covers every long-running row type.
    started_at = getattr(row, "started_at", None) or row.created_at
    age = datetime.now(UTC).replace(tzinfo=None) - started_at
    if age < timedelta(seconds=settings.stale_job_timeout_seconds):
        return False

    row.status = failed_status
    if hasattr(row, "completed_at"):
        row.completed_at = datetime.now(UTC).replace(tzinfo=None)
    if hasattr(row, "error"):
        row.error = message or (
            f"Timed out: no update received within "
            f"{settings.stale_job_timeout_seconds // 60} minutes"
        )
    session.add(row)
    session.commit()
    session.refresh(row)
    return True
