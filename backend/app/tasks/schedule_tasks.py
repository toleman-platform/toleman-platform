"""The beat dispatcher for configurable scheduled scans (issue #306).

One frequent tick replaces the two hardcoded per-scan-type intervals that
used to be the whole scheduling story. Instead of Beat holding the cadence,
Beat only asks "is anything due?" every few minutes and the answer comes
from ``ScanSchedule`` rows (see app.core.scan_schedules for how those
resolve). That inversion is what makes cadence configurable per workspace
and per target at all, and it moves the run clock from Beat's in-memory
schedule state into the database, where a restart cannot lose it.

What this module does NOT do is add a second way to run scans. Both scan
types go out through the exact dispatch helper their interactive path
already uses (``queue_full_scan`` / ``queue_api_scan``), onto the same
"scans" queue the one worker consumes, at whatever concurrency that worker
is already configured for. Issue #229 is about bulk dispatch outrunning the
worker and reporting false all-clears; a scheduled fan-out is the same
shape, so it deliberately reuses the same (bounded) pipe rather than
standing up a parallel one.
"""
import logging

from sqlmodel import Session

from app.core.db import engine
from app.core.scan_schedules import (
    advance_next_run_at,
    due_schedules,
    ensure_workspace_default_rows,
    targets_covered_by,
)
from app.core.time import utcnow
from app.models.models import ScanScheduleType, Target
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


def _dispatch_for_target(session: Session, scan_type: ScanScheduleType, target: Target) -> int:
    """Run one schedule against one target; returns how many scans were
    actually dispatched (0 is a real answer, not a failure).

    Imported lazily so this module does not pull the whole scanner/ingestion
    import graph in at Beat-registration time, and so neither task module
    ends up importing the other at module scope.
    """
    if scan_type == ScanScheduleType.FULL_SCAN:
        from app.tasks.scan_tasks import queue_full_scan

        return len(queue_full_scan(session, target))

    if scan_type == ScanScheduleType.API_SCAN:
        from app.tasks.api_scan_tasks import queue_api_scan

        return 1 if queue_api_scan(session, target) is not None else 0

    # A scan_type this dispatcher does not know how to run. Logged rather
    # than raised: a row written by a newer version of the app must not take
    # down the tick for every other schedule.
    logger.warning("scan schedule has unknown scan_type %r; nothing dispatched", scan_type)
    return 0


def dispatch_due_scan_schedules(session: Session) -> dict:
    """Fire every due schedule once. The whole of the beat task's work,
    factored out of the task so it can be exercised against a real session
    without Celery.

    Ordering inside the loop is the part that matters. Each row is *claimed*
    (its `next_run_at` pushed forward and `last_run_at` stamped, committed)
    BEFORE its targets are dispatched, not after. Claiming first can lose a
    cycle if the process dies in the gap; stamping afterwards would instead
    re-dispatch everything a half-finished pass already dispatched. With
    `task_acks_late = True` and `task_reject_on_worker_lost = True` (see
    celery_app.py) this task really is redelivered when a worker dies, so
    that is not a theoretical ordering: the choice is between one missed
    cycle and a duplicated platform-wide fan-out, and the duplicate is the
    one that hurts (#229).

    Per-row commits, rather than one commit at the end, for the same reason:
    a crash partway through a pass must not un-claim the rows that already
    fired.
    """
    now = utcnow()
    # Idempotent; gives every workspace somewhere to record run history.
    # Doing it here rather than at workspace-creation time means existing
    # installs get their rows on the next tick after an upgrade, with no
    # backfill migration.
    created = ensure_workspace_default_rows(session, now=now)
    if created:
        logger.info("materialised %d workspace-default scan schedule(s)", len(created))

    summary = {"schedules_fired": 0, "scans_dispatched": 0, "targets_considered": 0}
    for row in due_schedules(session, now):
        try:
            targets = targets_covered_by(session, row)
            # Claim before dispatching; see the docstring.
            row.last_run_at = now
            advance_next_run_at(session, row, now=now)
            session.add(row)
            session.commit()

            dispatched = 0
            for target in targets:
                try:
                    dispatched += _dispatch_for_target(session, row.scan_type, target)
                except Exception:
                    # One target's dispatch failure must not stop the rest,
                    # the same property run_scheduled_full_scans' own loop
                    # already had.
                    logger.exception(
                        "scheduled %s dispatch failed for target %s (schedule %s)",
                        row.scan_type,
                        target.id,
                        row.id,
                    )

            row.last_dispatched_count = dispatched
            session.add(row)
            session.commit()

            summary["schedules_fired"] += 1
            summary["scans_dispatched"] += dispatched
            summary["targets_considered"] += len(targets)
        except Exception:
            logger.exception("scan schedule %s failed to dispatch", row.id)
            session.rollback()
    return summary


@celery_app.task(name="app.tasks.schedule_tasks.dispatch_due_scan_schedules_task")
def dispatch_due_scan_schedules_task() -> dict:
    """Beat entry (celery_app.conf.beat_schedule, every few minutes): find
    the due ``ScanSchedule`` rows and dispatch them.

    The tick interval is intentionally much shorter than any schedule's
    cadence. It is not "how often scans run"; it is the resolution at which
    a 6-hour or 24-hour schedule can come due, and the reason a cadence
    change made in the UI takes effect within minutes instead of at the end
    of the current interval.
    """
    with Session(engine) as session:
        return dispatch_due_scan_schedules(session)
