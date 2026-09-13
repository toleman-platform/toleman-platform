"""Configurable scheduled scans (issue #306): resolution, due-selection and
validation for ``ScanSchedule`` rows.

Before this, "scheduled scanning" was two literal ``timedelta(hours=24)``
entries in ``celery_app.conf.beat_schedule``. That meant one cadence for
the entire platform, no way to turn it off for a target that should not be
touched, no way to scan a production repo more often than a scratch one,
and no UI; and the DAST half of the ask (#72's active API scanning) was not
scheduled at all, only ever run on demand. This module holds the
"which schedules are due, and what do they actually mean" half of the fix;
``app.tasks.schedule_tasks`` holds the dispatching half. The split is
deliberate and matches the layering used elsewhere (``app.core.enforcement``
resolves, callers act): nothing in ``app.core`` imports ``app.tasks``.

Inheritance follows the NULL-means-inherit convention already used by
``enforcement_mode`` (#62, see ``app.core.enforcement``) and ``SlaRule``'s
NULL ``group_id`` workspace default (#70), with one refinement: the two
value columns inherit *independently*, at field level. So

    shipped default  ->  workspace-default row  ->  target row

is walked once per field, and a target row saying only ``enabled=False``
still inherits the workspace's interval rather than silently resetting it
to the shipped 24h. A single scalar per level (enforcement_mode's shape)
would have forced an operator pausing one target to also restate its
cadence, which is exactly the kind of accidental config drift the
"None = inherit" convention exists to prevent.
"""
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal, Optional

from sqlmodel import Session, or_, select

from app.core.time import utcnow
from app.models.models import ScanSchedule, ScanScheduleType, Target, Workspace

logger = logging.getLogger(__name__)

# Where an effective value came from, for the "every 24h (workspace
# default)" legibility the UI needs; same idea as
# app.core.enforcement.resolve_enforcement_mode_with_source's label.
ScheduleSource = Literal["target", "workspace", "default"]


@dataclass(frozen=True)
class ShippedDefault:
    enabled: bool
    interval_hours: int


# The floor every install gets with nothing configured. Changing these
# changes behaviour for every unconfigured workspace on the next deploy, so
# they are stated once, here, rather than being spread across the dispatcher
# and the API.
#
# FULL_SCAN reproduces exactly what the old hardcoded beat entry did: on,
# every 24 hours, every target. An install that configures nothing sees no
# change from this issue.
#
# API_SCAN ships OFF, which is likewise no change: active API scanning has
# never been scheduled, only triggered by hand. Defaulting it on would start
# firing nuclei at live hosts on the first worker restart after an upgrade,
# for every target that happens to have an api_base_url set; that is a
# network-visible side effect on somebody else's staging environment and it
# has to be a decision, not an upgrade artefact. (The per-target safety
# boundary in app.core.api_scan_targets still applies on top of this; this
# default is about not surprising anyone, not about trust.)
SHIPPED_DEFAULTS: dict[ScanScheduleType, ShippedDefault] = {
    ScanScheduleType.FULL_SCAN: ShippedDefault(enabled=True, interval_hours=24),
    ScanScheduleType.API_SCAN: ShippedDefault(enabled=False, interval_hours=24),
}

# An hour is the floor because the dispatcher tick (see
# app.tasks.celery_app's beat_schedule) is minutes, not seconds: anything
# finer would silently round up to the tick and read as a broken setting.
# The ceiling is a year; past that "scheduled" stops meaning anything and a
# fat-fingered 100000 would look indistinguishable from "off" while still
# claiming to be enabled.
MIN_INTERVAL_HOURS = 1
MAX_INTERVAL_HOURS = 24 * 365


class ScanScheduleError(ValueError):
    """Invalid schedule configuration (bad interval, unknown scan type,
    target that does not belong to the named workspace). A caller/config
    error, surfaced as a 4xx by the API layer, never retried."""


@dataclass(frozen=True)
class ResolvedScanSchedule:
    """The effective schedule for one (target, scan type) pair, plus enough
    provenance for the UI to explain itself and enough run history to be
    honest about what has and has not happened yet."""
    scan_type: ScanScheduleType
    enabled: bool
    interval_hours: int
    enabled_source: ScheduleSource
    interval_source: ScheduleSource
    # The row that actually governs this target (its own, else the
    # workspace default). None when neither exists yet, i.e. the target is
    # running purely on SHIPPED_DEFAULTS and the dispatcher has not
    # materialised a workspace-default row yet.
    schedule_id: Optional[int]
    # None means "has never fired". Not "nothing to show": a fresh install
    # genuinely spends its first interval in this state, and rendering it as
    # blank is how a scheduler that is quietly not running looks exactly
    # like one that simply has not come round yet.
    last_run_at: Optional[datetime]
    last_dispatched_count: Optional[int]
    # None when the governing row does not exist yet, or when the schedule
    # is disabled (a paused schedule has no next run; see
    # advance_next_run_at for why the stored column is not trusted here).
    next_run_at: Optional[datetime]


def validate_interval_hours(interval_hours: Optional[int]) -> Optional[int]:
    """None passes through untouched: it means "inherit", not "zero"."""
    if interval_hours is None:
        return None
    if interval_hours < MIN_INTERVAL_HOURS or interval_hours > MAX_INTERVAL_HOURS:
        raise ScanScheduleError(
            f"interval_hours must be between {MIN_INTERVAL_HOURS} and {MAX_INTERVAL_HOURS} "
            f"(got {interval_hours}); use enabled=false to stop a schedule rather than a huge interval"
        )
    return interval_hours


def workspace_default_row(
    session: Session, workspace_id: int, scan_type: ScanScheduleType
) -> Optional[ScanSchedule]:
    return session.exec(
        select(ScanSchedule).where(
            ScanSchedule.workspace_id == workspace_id,
            ScanSchedule.target_id.is_(None),
            ScanSchedule.scan_type == scan_type,
        )
    ).first()


def target_row(session: Session, target_id: int, scan_type: ScanScheduleType) -> Optional[ScanSchedule]:
    return session.exec(
        select(ScanSchedule).where(
            ScanSchedule.target_id == target_id,
            ScanSchedule.scan_type == scan_type,
        )
    ).first()


def _overlay(
    base_enabled: bool,
    base_interval: int,
    base_enabled_source: ScheduleSource,
    base_interval_source: ScheduleSource,
    row: Optional[ScanSchedule],
    source: ScheduleSource,
) -> tuple[bool, int, ScheduleSource, ScheduleSource]:
    """Apply one level's non-NULL fields over the level beneath it.

    Field-level rather than row-level, which is the whole point: a row that
    sets only `enabled` must not drag the interval back to the base.
    """
    if row is None:
        return base_enabled, base_interval, base_enabled_source, base_interval_source
    enabled, enabled_source = base_enabled, base_enabled_source
    interval, interval_source = base_interval, base_interval_source
    if row.enabled is not None:
        enabled, enabled_source = row.enabled, source
    if row.interval_hours is not None:
        interval, interval_source = row.interval_hours, source
    return enabled, interval, enabled_source, interval_source


def resolve_scan_schedule(
    session: Session, target: Target, scan_type: ScanScheduleType
) -> ResolvedScanSchedule:
    """Effective schedule for one target: shipped default -> workspace
    default row -> this target's own row, field by field."""
    shipped = SHIPPED_DEFAULTS[scan_type]
    ws_row = workspace_default_row(session, target.workspace_id, scan_type)
    own_row = target_row(session, target.id, scan_type) if target.id is not None else None

    enabled, interval, enabled_source, interval_source = _overlay(
        shipped.enabled, shipped.interval_hours, "default", "default", ws_row, "workspace"
    )
    enabled, interval, enabled_source, interval_source = _overlay(
        enabled, interval, enabled_source, interval_source, own_row, "target"
    )

    # The governing row is the most specific one that exists, because that
    # is the row the dispatcher actually stamps its run history onto. A
    # target with its own row stops being covered by the workspace default
    # entirely (see targets_covered_by), so its history lives on its own row
    # even for fields it inherits.
    governing = own_row or ws_row
    return ResolvedScanSchedule(
        scan_type=scan_type,
        enabled=enabled,
        interval_hours=interval,
        enabled_source=enabled_source,
        interval_source=interval_source,
        schedule_id=governing.id if governing else None,
        last_run_at=governing.last_run_at if governing else None,
        last_dispatched_count=governing.last_dispatched_count if governing else None,
        # A disabled schedule has no next run. Reporting the stale stored
        # value would put a confident future timestamp next to the word
        # "Paused"; the two together are a lie whichever one the reader
        # believes.
        next_run_at=(governing.next_run_at if governing and enabled else None),
    )


def effective_for_row(session: Session, row: ScanSchedule) -> tuple[bool, int]:
    """(enabled, interval_hours) for a schedule row itself, resolved through
    whatever it inherits from.

    This is the dispatcher's view, and it is per-row rather than per-target
    on purpose: every target a given row covers resolves identically,
    because a target with its own row is excluded from the workspace
    default's coverage set. So one resolution per row is not an
    approximation of N per-target resolutions, it is the same answer.
    """
    shipped = SHIPPED_DEFAULTS[row.scan_type]
    if row.target_id is None:
        enabled, interval, _, _ = _overlay(
            shipped.enabled, shipped.interval_hours, "default", "default", row, "workspace"
        )
        return enabled, interval
    ws_row = workspace_default_row(session, row.workspace_id, row.scan_type)
    enabled, interval, es, is_ = _overlay(
        shipped.enabled, shipped.interval_hours, "default", "default", ws_row, "workspace"
    )
    enabled, interval, _, _ = _overlay(enabled, interval, es, is_, row, "target")
    return enabled, interval


def advance_next_run_at(session: Session, row: ScanSchedule, now: Optional[datetime] = None) -> datetime:
    """Set (and return) the row's next due time, one effective interval from
    `now`.

    From `now`, not from the previous `next_run_at`. If a worker is down for
    thirty hours, a schedule that ticks hourly must come back and fire
    *once*, not replay thirty missed runs into the scan queue the moment it
    reconnects. That catch-up storm is precisely the bulk-dispatch shape
    #229 identifies as producing false all-clears, and it would arrive at
    the worst possible moment, right after an outage.
    """
    now = now or utcnow()
    _, interval_hours = effective_for_row(session, row)
    row.next_run_at = now + timedelta(hours=interval_hours)
    row.updated_at = now
    return row.next_run_at


def due_schedules(session: Session, now: Optional[datetime] = None) -> list[ScanSchedule]:
    """Every schedule row that is both due and effectively enabled, oldest
    id first.

    Due is `next_run_at <= now`, inclusive: a schedule whose due time is
    exactly this instant has arrived, and an exclusive comparison would make
    the boundary depend on clock resolution. A NULL `next_run_at` counts as
    due; every write path sets it, so NULL only happens if something wrote a
    row without going through this module, and "run it on the next tick" is
    the safe reading of a row whose clock was never set.

    Disabled rows are filtered out here rather than skipped later in the
    dispatch loop, so a paused schedule is never stamped as having run. It
    keeps a `next_run_at` in the past while paused, which is harmless (the
    API recomputes it on re-enable, and resolve_scan_schedule reports None
    for a disabled schedule rather than surfacing the stale value).
    """
    now = now or utcnow()
    rows = session.exec(
        select(ScanSchedule)
        .where(or_(ScanSchedule.next_run_at.is_(None), ScanSchedule.next_run_at <= now))
        .order_by(ScanSchedule.id)
    ).all()
    return [row for row in rows if effective_for_row(session, row)[0]]


def targets_covered_by(session: Session, row: ScanSchedule) -> list[Target]:
    """The targets one schedule row is responsible for.

    A target-scoped row covers exactly its target. A workspace-default row
    covers every target in that workspace *except* those with a row of their
    own for the same scan type; otherwise a target that had been given a
    faster cadence would also keep getting the workspace's, and would be
    scanned twice.
    """
    if row.target_id is not None:
        target = session.get(Target, row.target_id)
        if target is None:
            # The target was deleted out from under its schedule. Silent
            # no-op rather than an error: the same shape as
            # queue_full_scan_for_target_task's missing-target case.
            return []
        if target.workspace_id != row.workspace_id:
            logger.warning(
                "scan schedule %s names target %s from a different workspace; skipping",
                row.id,
                row.target_id,
            )
            return []
        return [target]

    overridden = set(
        session.exec(
            select(ScanSchedule.target_id).where(
                ScanSchedule.workspace_id == row.workspace_id,
                ScanSchedule.scan_type == row.scan_type,
                ScanSchedule.target_id.is_not(None),
            )
        ).all()
    )
    return [
        t
        for t in session.exec(select(Target).where(Target.workspace_id == row.workspace_id)).all()
        if t.id not in overridden
    ]


def ensure_workspace_default_rows(session: Session, now: Optional[datetime] = None) -> list[ScanSchedule]:
    """Materialise the missing workspace-default rows, one per (workspace,
    scan type), and return the ones that were created.

    The resolution above does not need these rows to exist; SHIPPED_DEFAULTS
    already answers for a workspace with nothing configured. They exist so
    the dispatcher has somewhere to record `last_run_at`/`next_run_at`, and
    so the UI has real run history to show instead of a permanent
    "unknown". Idempotent, and safe to call on every tick.

    `next_run_at` is seeded one full interval out, never "now". This is the
    behaviour the old hardcoded beat entry had and it is deliberately
    preserved: Celery Beat records a fresh interval schedule's creation time
    as its last run and only fires a full interval later (see the comment
    block above `_queue_missing_baseline_scans` in app/tasks/celery_app.py).
    Seeding these due-immediately would turn every worker restart into a
    platform-wide full-scan fan-out, on top of the baseline catch-up that
    already runs on `worker_ready` and is deliberately scoped to targets
    with no baseline at all. `last_run_at` stays NULL: nothing has run yet,
    and saying otherwise on the first page load would be a fabricated
    timestamp.
    """
    now = now or utcnow()
    created: list[ScanSchedule] = []
    for workspace in session.exec(select(Workspace)).all():
        for scan_type in ScanScheduleType:
            if workspace_default_row(session, workspace.id, scan_type) is not None:
                continue
            shipped = SHIPPED_DEFAULTS[scan_type]
            row = ScanSchedule(
                workspace_id=workspace.id,
                target_id=None,
                scan_type=scan_type,
                # Left NULL, not copied from SHIPPED_DEFAULTS: a
                # materialised row is a place to record runs, not an
                # operator's decision. Copying the values in would freeze
                # today's defaults into every existing install and make a
                # future change to SHIPPED_DEFAULTS apply to nobody.
                interval_hours=None,
                enabled=None,
                last_run_at=None,
                next_run_at=now + timedelta(hours=shipped.interval_hours),
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            created.append(row)
    return created
