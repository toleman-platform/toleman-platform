"""Collapse findings into the decisions someone actually has to make.

The findings list shows one row per detection. On this repo's own scan that
is 150 rows, 148 of which are licence findings: `@img/sharp-libvips-*` ships
a separate npm package per platform binary, so one licence decision arrives
as roughly a dozen identical rows, and the single Secrets finding — the only
item on the page shaped like an incident — sits on page six behind them.

This module answers the question the flat list cannot: **what are the
distinct decisions in this result set, and how much does each one close?**

The group key is ``(tool, rule_id)``. That is deliberate, and the reason it
works is that `rule_id` is already the identity of "the same issue" for every
parser in ``app.scanners.parsers``:

* ``license:LGPL-3.0-or-later`` for a Trivy licence result, so every package
  under one licence collapses into the one policy call that covers them;
* the CVE id for a Trivy vulnerability;
* the ``check_id`` for a Checkov/Trivy misconfiguration;
* the Semgrep rule for a SAST finding.

Nothing here parses a human-readable title to recover a package name. A group
built by pattern-matching prose would silently regroup the day someone edits a
title template, and a wrong grouping sends a reader to fix something unrelated.

Two categories are deliberately exempt (``UNGROUPED_CATEGORIES``): a leaked
credential is an incident with its own clock, not an instance of a class, and
collapsing two secrets under one gitleaks rule would hide one of them behind
the other's triage decision. Malicious packages are exempt for the same
reason — each one is its own supply-chain event.

Aggregates follow the same honesty rule ``app.core.remediation`` states for
remediations: never round up. ``severity`` is the *highest* among members
rather than a representative's, ``oldest_first_seen`` is the member that has
been open longest, and the SLA/fixability signals are computed from the single
member most at risk (see ``representative_finding``) rather than asserted for
the group as a whole.
"""
from sqlalchemy import case
from sqlmodel import Session, func

from app.models.models import Finding, SEVERITY_WEIGHT, Severity

# Categories where one finding is one incident and grouping would hide
# things. See the module docstring.
UNGROUPED_CATEGORIES = {"Secrets", "Malicious Package"}

# Sort keys accepted by the grouped endpoint. `exploitability` is the
# default and matches the flat list's existing ordering (priority score
# descending), so switching to the grouped view does not silently reorder
# the same data by a different rule.
SORT_KEYS = ("exploitability", "severity", "blast_radius", "age", "recent")
DEFAULT_SORT = "exploitability"


def severity_weight_case():
    """SQL CASE mapping Severity to its numeric weight.

    ``Severity`` is stored as its string value, so ``max(severity)`` orders
    alphabetically — "Critical" < "High" < "Informational" < "Low" < "Medium",
    which is wrong in a way that is easy to miss because it looks sorted. This
    reuses ``SEVERITY_WEIGHT`` so the ordering cannot drift from the weights
    the priority score itself is built on.
    """
    return case(
        *[(Finding.severity == severity, weight) for severity, weight in SEVERITY_WEIGHT.items()],
        else_=0,
    )


def severity_for_weight(weight: int) -> str:
    """Map a weight from ``severity_weight_case`` back to a severity name."""
    for severity, candidate in SEVERITY_WEIGHT.items():
        if candidate == weight:
            return getattr(severity, "value", severity)
    return getattr(Severity.INFORMATIONAL, "value", "Informational")


def is_groupable(category: str) -> bool:
    return category not in UNGROUPED_CATEGORIES


def representative_finding(session: Session, member_query) -> Finding | None:
    """The member whose signals stand for the group: worst severity, then oldest.

    The group's SLA countdown and fixability are read off this one finding
    rather than aggregated across all members. That is the conservative
    choice: a group's SLA is the deadline of the member closest to breaching,
    so the row cannot understate urgency, and it stays a claim about a real
    finding someone can open rather than a synthesised one that matches none
    of them.

    `member_query` must be the caller's already-filtered findings query
    narrowed to this group, not a fresh select over the table. The filtered
    query is what carries workspace scoping, so a representative chosen
    outside it could be a finding the caller may not see -- and its title,
    path and SLA are rendered on the row.
    """
    return session.exec(
        member_query.order_by(severity_weight_case().desc(), Finding.first_seen.asc()).limit(1)
    ).first()


def group_aggregate_columns():
    """The aggregate expressions a grouped query selects, in a fixed order.

    Labelled, because the endpoint reads them back by name off the result
    row; an unlabelled aggregate comes back as `max_1` and the mapping breaks
    silently. Kept in one function so the two grouped queries in the API
    cannot select different aggregates.
    """
    return (
        Finding.tool,
        Finding.rule_id,
        func.count(Finding.id).label("finding_count"),
        func.max(severity_weight_case()).label("severity_weight"),
        func.max(Finding.priority_score).label("max_priority_score"),
        func.min(Finding.first_seen).label("oldest_first_seen"),
        # Both ends of first_seen: `oldest` is what the row's age column shows,
        # `newest` is what `sort=recent` orders by, so "Newest first" means the
        # same thing in the grouped and flat views (the flat list sorts on
        # first_seen, not last_seen -- a group re-detected by today's scan is
        # not newly found).
        func.max(Finding.first_seen).label("newest_first_seen"),
        func.max(Finding.last_seen).label("newest_last_seen"),
        func.count(func.distinct(Finding.target_id)).label("target_count"),
        func.count(func.distinct(Finding.file_path)).label("file_count"),
        func.max(func.coalesce(Finding.epss_score, 0.0)).label("max_epss"),
        # Counted rather than max()'d: SQLite stores booleans as 0/1 so
        # max(kev_listed) happens to work there, and Postgres rejects
        # max(boolean) outright. A count is correct on both, and "3 of these
        # are KEV-listed" is more useful on the row than "at least one is".
        func.sum(case((Finding.kev_listed.is_(True), 1), else_=0)).label("kev_count"),
    )
