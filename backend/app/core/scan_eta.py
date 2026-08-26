"""Duration estimates for in-flight scans (#212).

A scan's ETA is derived from that repo's own history with that tool -- the
median wall-clock duration of its recent completed runs -- and from nothing
else.

The alternative, a fixed "about 30 seconds" or a global average across every
repo, was rejected deliberately. Scan duration is dominated by repo size and
tool, and the spread between a small Go service and a large monorepo is
larger than any single number could usefully cover. An estimate that is
routinely wrong is worse than no estimate: a user who trusts "about 30
seconds", watches it run for four minutes, and is told nothing in between
stops believing the rest of the surface too. So when there is not enough
history to justify a number, callers get None and show elapsed time instead
-- "running for 45s" is always true and needs no model behind it.

Only *completed* runs are sampled. A failed run's duration says how long the
platform took to give up (often a clone timeout), not how long the work
takes, and averaging those in would drag every estimate toward the timeout.
"""
from datetime import UTC, datetime
from app.core.time import utcnow
from statistics import median
from typing import Optional

from sqlmodel import Session, select

from app.models.models import Scan

# Below this many completed runs, the sample is too small to be worth
# presenting as an estimate. Three is the point where a median starts
# resisting a single outlier -- with two samples the median is just their
# average, so one anomalously slow run skews it by half its error.
MIN_SAMPLES = 3

# Only recent history counts. A repo that has doubled in size since its
# first scan should not be estimated from runs that predate the growth.
MAX_SAMPLES = 10


def _duration_seconds(scan: Scan) -> Optional[float]:
    if scan.completed_at is None or scan.started_at is None:
        return None
    seconds = (scan.completed_at - scan.started_at).total_seconds()
    # Guard against clock adjustments and any row written out of order.
    # A non-positive duration is not a fast scan, it is bad data.
    if seconds <= 0:
        return None
    return seconds


def estimate_duration_seconds(session: Session, target_id: int, tool: str) -> Optional[int]:
    """Median duration of this target's recent completed runs of `tool`.

    Returns None when there is not enough history to justify a number, which
    callers must render as "no estimate" rather than substituting a default.
    """
    rows = session.exec(
        select(Scan)
        .where(Scan.target_id == target_id, Scan.tool == tool, Scan.status == "completed")
        .order_by(Scan.started_at.desc())
        .limit(MAX_SAMPLES)
    ).all()

    durations = [d for d in (_duration_seconds(s) for s in rows) if d is not None]
    if len(durations) < MIN_SAMPLES:
        return None
    return int(median(durations))


def elapsed_seconds(scan: Scan, now: Optional[datetime] = None) -> int:
    """How long this scan has been running (or ran, once settled).

    Always available, unlike the estimate -- this is what the UI falls back
    to when there is no history to estimate from.
    """
    end = scan.completed_at or (now or utcnow())
    return max(0, int((end - scan.started_at).total_seconds()))


def progress_for(session: Session, scan: Scan) -> dict:
    """The timing block shared by every endpoint that reports a scan's state.

    `eta_seconds` is null whenever it cannot be grounded in history, and is
    only meaningful while the scan is still running -- a settled scan has an
    actual duration, so an estimate for it would be noise.
    """
    running = scan.status == "running"
    return {
        "elapsed_seconds": elapsed_seconds(scan),
        "eta_seconds": estimate_duration_seconds(session, scan.target_id, scan.tool) if running else None,
    }
