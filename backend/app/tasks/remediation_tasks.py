"""Celery entry points for Fix Plan PR automation (#247 follow-up).

Two independent things dispatch through here, both wrapping
app.core.remediation_autofix so "raise it by hand" and "raise it
automatically" are the same underlying code path:

  * run_raise_all_batch -- the bulk "Raise all" action a user triggers from
    the Fix Plan tab, processing one RemediationPrBatch's items.
  * sweep_auto_raise_prs_task -- the periodic beat entry that raises PRs
    for every opted-in target's unaddressed packages with no user
    interaction at all (Target.auto_raise_fix_prs).
"""
import logging
import time

from sqlmodel import Session, select

from app.core.autofix import AutofixError
from app.core.db import engine
from app.core.remediation import group_remediations
from app.core.remediation_autofix import AlreadyRaisedError, raise_package_fix_pr, sweep_auto_raise_prs
from app.core.time import utcnow
from app.models.models import RemediationPrBatch, RemediationPrBatchItem, Target, User
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

# Same reasoning as app.tasks.pipeline_tasks.INTER_ITEM_DELAY_SECONDS: each
# item is a real GitHub API call sequence (branch create + one-or-more file
# commits + PR open), and firing a long batch back to back with no pause
# risks tripping GitHub's secondary rate limits.
INTER_ITEM_DELAY_SECONDS = 1.5


@celery_app.task(name="app.tasks.remediation_tasks.run_raise_all_batch", bind=True)
def run_raise_all_batch(self, batch_id: int):
    """(#247 follow-up) Bulk "Raise all": opens one PR per package via
    raise_package_fix_pr, sequentially (see INTER_ITEM_DELAY_SECONDS
    above), recording a real per-item outcome (succeeded/failed) so one bad
    package's GitHub error doesn't crash the rest of the batch or leave it
    stuck at "running" -- same shape as
    app.tasks.pipeline_tasks.run_pipeline_integration_batch.
    """
    with Session(engine) as session:
        batch = session.get(RemediationPrBatch, batch_id)
        if not batch:
            return {"error": "batch not found"}
        target = session.get(Target, batch.target_id)
        if not target:
            batch.status = "completed"
            batch.completed_at = utcnow()
            session.add(batch)
            session.commit()
            return {"error": "target not found"}

        raiser = session.get(User, batch.created_by_user_id)
        raised_by = f"user:{raiser.email}" if raiser else f"user:{batch.created_by_user_id}"

        # Recomputed at dispatch time, not carried over from whatever the
        # request that created the batch saw: a plan can shift between
        # "raise all" being clicked and this task actually running (another
        # raise landed, a rescan changed findings), and acting on a stale
        # snapshot could duplicate a PR or 404 a package that moved on.
        plans_by_package = {p["package"]: p for p in group_remediations(session, target.id)}

        item_rows = session.exec(
            select(RemediationPrBatchItem).where(RemediationPrBatchItem.batch_id == batch_id)
        ).all()

        for idx, item in enumerate(item_rows):
            plan = plans_by_package.get(item.package)
            if plan is None:
                item.status = "failed"
                item.error = "package no longer has an open fix plan entry"
                item.completed_at = utcnow()
                session.add(item)
                batch.failed += 1
                session.add(batch)
                session.commit()
                continue

            # Captured before the commit below: session.commit() expires
            # every attribute on `item` (SQLAlchemy's default
            # expire_on_commit), and if the exception handlers below need
            # to re-fetch this row after a FAILED, rolled-back commit
            # (raise_package_fix_pr's own final commit), reading `item.id`
            # at that point would re-trigger a lazy DB access on an object
            # whose session may still be settling from the rollback. Read
            # it once now, while it's cheap and safe.
            item_id = item.id
            item.status = "running"
            session.add(item)
            session.commit()

            try:
                result = raise_package_fix_pr(session, target, plan, raised_by=raised_by)
                item.status = "succeeded"
                item.pr_url = result["pr_url"]
                item.pr_number = result["pr_number"]
                item.completed_at = utcnow()
                session.add(item)
                batch.succeeded += 1
                session.add(batch)
                session.commit()
            except AlreadyRaisedError as exc:
                # Idempotent, not a failure: this package already has a PR
                # open from an earlier raise (a re-run of the batch, or one
                # raised by hand in the meantime) -- record it as the
                # outcome rather than opening a duplicate. No rollback
                # needed: AlreadyRaisedError is raised before
                # raise_package_fix_pr does any writes.
                item = session.get(RemediationPrBatchItem, item_id)
                item.status = "succeeded"
                item.pr_url = exc.pr_url
                item.pr_number = exc.pr_number
                item.completed_at = utcnow()
                session.add(item)
                batch.succeeded += 1
                session.add(batch)
                session.commit()
            except AutofixError as exc:
                session.rollback()
                item = session.get(RemediationPrBatchItem, item_id)
                item.status = "failed"
                item.error = str(exc)
                item.completed_at = utcnow()
                session.add(item)
                batch.failed += 1
                session.add(batch)
                session.commit()
            except Exception as exc:  # noqa: BLE001, last-resort catch so one
                # package's unexpected error can't leave the whole batch
                # stuck at "running" forever; see run_pipeline_integration_batch's
                # identical catch-all for the same reasoning.
                logger.exception("raise-all batch item %s failed unexpectedly", item_id)
                session.rollback()
                item = session.get(RemediationPrBatchItem, item_id)
                item.status = "failed"
                item.error = f"unexpected error: {exc}"
                item.completed_at = utcnow()
                session.add(item)
                batch.failed += 1
                session.add(batch)
                session.commit()

            if idx < len(item_rows) - 1:
                time.sleep(INTER_ITEM_DELAY_SECONDS)

        batch.status = "completed"
        batch.completed_at = utcnow()
        session.add(batch)
        session.commit()
        return {"batch_id": batch.id, "succeeded": batch.succeeded, "failed": batch.failed}


@celery_app.task(name="app.tasks.remediation_tasks.sweep_auto_raise_prs_task")
def sweep_auto_raise_prs_task() -> dict:
    """Beat entry (celery_app.conf.beat_schedule): raise PRs for every
    opted-in target's unaddressed Fix Plan packages. See
    app.core.remediation_autofix.sweep_auto_raise_prs for the full logic;
    this is just the Celery-facing wrapper, same shape as
    app.tasks.schedule_tasks.dispatch_due_scan_schedules_task."""
    with Session(engine) as session:
        return sweep_auto_raise_prs(session)
