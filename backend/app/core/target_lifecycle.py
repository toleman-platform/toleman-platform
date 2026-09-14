"""Target lifecycle (#273): deactivate (stop scanning, keep everything) and
delete (soft, audit-preserving).

Two facts live on `Target` as nullable timestamps -- `deactivated_at` and
`deleted_at`, see their comments in app/models/models.py -- and roughly two
dozen places in this codebase have to agree on what they mean. That's the
reason this module exists rather than each call site writing
``target.deleted_at is None`` by hand: the failure mode of a lifecycle flag
is not a crash, it's one forgotten dispatch path quietly scanning a repo
the operator believes is switched off, or one forgotten aggregate quietly
counting a deleted target's findings into a score. Both are silent, and
both are exactly the class of bug this platform keeps refusing to ship.

The three predicates, and which one each caller wants:

* ``live`` (``deleted_at IS NULL``) -- does this target still exist?
  Every list, read, aggregate, score and report. A soft-deleted target is
  gone as far as the product is concerned.
* ``scannable`` (``deleted_at IS NULL AND deactivated_at IS NULL``) -- may
  we start work against this repo right now? Every scan dispatch path.
* neither -- the historical trails (app/api/audit.py's feed, scan history)
  deliberately resolve deleted targets too, because an audit entry that
  renders as "scan on 47" once someone deletes target 47 has lost the one
  thing it existed to record.

Why soft delete rather than a cascade. `Finding`, `Scan`, `PRGuardrailScan`
and friends all foreign-key to `target_id`, so "delete a target" is really
a question about that history. This is a security tool, and "someone
deleted the record of a finding" is itself a fact that has to remain
answerable -- a cascade makes the question permanently unanswerable and
leaves no trace that it was ever asked. So the default Delete keeps every
row and hides the target instead. A true hard delete remains available as a
deliberate follow-up product call; it is not what an unqualified Delete
button should do.
"""
from sqlmodel import select

from app.core.time import utcnow
from app.models.models import Target


class TargetNotScannable(Exception):
    """A scan was requested against a target that is deactivated or deleted.

    Carries the caller-facing reason text so every dispatch path reports the
    same thing; routes translate it to their own error convention (some of
    these endpoints raise HTTPException, some return a 200 ``{"error": ...}``
    body -- see scan_refusal_reason's callers).
    """


def is_deleted(target: Target) -> bool:
    return target.deleted_at is not None


def is_active(target: Target) -> bool:
    """Active = not deactivated. Independent of deletion: a deleted target's
    deactivated_at is whatever it was, and callers should test `is_deleted`
    first. Serialized onto every target payload so the frontend renders the
    state from one server-owned answer rather than re-deriving it."""
    return target.deactivated_at is None


def scan_refusal_reason(target: Target) -> str | None:
    """None when work may be dispatched against this target; otherwise the
    reason to report, already worded for a human.

    Deletion is reported as "not found" rather than "deleted": a soft-deleted
    target is indistinguishable from a never-existed one at every product
    surface, and saying "this was deleted" here would be the only place that
    leaks otherwise. The audit log is where that question gets answered, and
    it is admin-gated.
    """
    if is_deleted(target):
        return "target not found"
    if not is_active(target):
        return (
            f"{target.name} is deactivated; scanning is off for this target. "
            "Reactivate it to resume scans."
        )
    return None


def require_scannable(target: Target) -> None:
    """Raise `TargetNotScannable` unless work may be dispatched. For the
    worker-side paths (app/tasks/*), where there is no HTTP response to
    shape and the caller just needs to stop."""
    reason = scan_refusal_reason(target)
    if reason is not None:
        raise TargetNotScannable(reason)


def live_targets(query):
    """Narrow a `select(Target)`-shaped query to targets that still exist.

    Use on every list/aggregate/report query over targets. Not applied
    inside a generic session.get() wrapper on purpose: `session.get` is also
    how the audit and scan-history paths resolve a name for a historical
    row, and those must keep resolving deleted targets.
    """
    return query.where(Target.deleted_at.is_(None))


def scannable_targets(query):
    """Narrow a `select(Target)`-shaped query to targets work may be
    dispatched against -- live *and* not deactivated. Use on the fan-out
    dispatch paths (the beat-scheduled full scan, the baseline catch-up,
    mass pipeline rollout) that pick targets themselves rather than being
    handed one."""
    return query.where(Target.deleted_at.is_(None), Target.deactivated_at.is_(None))


def deleted_target_ids():
    """Subquery of soft-deleted target ids, for filtering tables that
    foreign-key to Target without joining it.

    A subquery rather than a join because the queries that need this
    (findings list, dashboard aggregates) already join Target conditionally
    -- app/api/findings.py joins it only for non-admin callers and tracks
    that with a `target_joined` flag, and joining twice raises. A NOT IN
    over this set composes with any of those shapes and can't duplicate
    rows. Safe as NOT IN specifically because Target.id is a primary key,
    so the subquery can never contain NULL.
    """
    return select(Target.id).where(Target.deleted_at.is_not(None))


def exclude_deleted_targets(query, target_id_column):
    """Narrow a query over any target_id-bearing table (Finding, Scan, ...)
    to rows whose target still exists. See `deleted_target_ids` for why this
    is a subquery and not a join."""
    return query.where(target_id_column.not_in(deleted_target_ids()))


def deactivate(target: Target) -> bool:
    """Idempotent: returns True if this call is what changed the state, so
    callers only write an audit row for a real transition (same shape as
    admin.update_role's `if old_role != user.role` guard). Does not commit;
    the caller owns the transaction it's part of."""
    if target.deactivated_at is not None:
        return False
    target.deactivated_at = utcnow()
    return True


def reactivate(target: Target) -> bool:
    """Inverse of `deactivate`, same idempotent-returns-changed contract."""
    if target.deactivated_at is None:
        return False
    target.deactivated_at = None
    return True


def soft_delete(target: Target) -> bool:
    """Mark the target deleted without destroying anything.

    Deliberately does NOT touch `deactivated_at`. The two are separate
    facts, and flattening them would lose information a restore would need:
    a target that was deactivated in March and deleted in June should come
    back deactivated, not silently scanning again.
    """
    if target.deleted_at is not None:
        return False
    target.deleted_at = utcnow()
    return True
