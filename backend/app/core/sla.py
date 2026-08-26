"""SLA (days-to-fix) resolution and violation computation (issue #70).

How many days a Finding has to be fixed depends on its severity AND which
repo Group(s) (#61) its Target belongs to, e.g. Critical in a "production"
group might be 7 days, Medium in a "dev" group might be 30. This is
naturally a matrix (group-or-workspace-default x severity) -> days_to_fix,
not a single inherited scalar like #62's enforcement_mode, so SlaRule rows
are looked up rather than walked up an inheritance chain of scalar columns.
The RESOLUTION order still follows #62's most-specific-wins philosophy:

    a group the target belongs to has a rule for this severity
        -> use it (most restrictive wins if multiple groups disagree)
        -> (if none) the workspace's null-group_id default rule for this
           severity
        -> (if none) no SLA applies, return None, never fabricate a number

There is deliberately no per-target SLA override in this first version
(unlike enforcement_mode's target -> group -> workspace chain), targets
inherit SLA purely through their group(s), see SlaRule's docstring in
app/models/models.py.

Violation is computed at read time (query-time calculation), not by a
background job; kept simple for this first version, matching the issue's
explicit scope. A finding is only "in violation" while it's still open
(state not in one of the terminal/accepted states) and only when a real
SLA rule actually applies to it.
"""
from datetime import timedelta
from app.core.time import utcnow
from typing import Literal

from sqlmodel import Session, select

from app.models.models import Finding, FindingState, SlaRule, Target, TargetGroup

SlaSource = Literal["group", "workspace_default"]

# Findings in one of these states are no longer "open" for SLA purposes;
# they've been triaged to a resolution, so a countdown/violation no longer
# means anything for them. REOPENED is deliberately NOT here: a reopened
# finding is unresolved again and should count.
CLOSED_STATES = frozenset(
    {
        FindingState.MITIGATED,
        FindingState.ACCEPTED_RISK,
        FindingState.FALSE_POSITIVE,
        FindingState.WONT_FIX,
    }
)


def _group_ids_for_target(session: Session, target_id: int) -> list[int]:
    return session.exec(
        select(TargetGroup.group_id).where(TargetGroup.target_id == target_id)
    ).all()


def resolve_sla_days_with_source(session: Session, finding: Finding) -> tuple[int | None, SlaSource | None]:
    """Resolve the effective SLA (days_to_fix) for one finding, plus which
    level it came from ("group" or "workspace_default"), or (None, None) if
    no rule applies anywhere. Most-restrictive-wins (fewest days) when a
    target belongs to multiple groups that both carry a rule for this
    severity; same fail-closed philosophy as #62's conflicting-groups
    resolution, just "fewest days" instead of "most blocking mode"."""
    target = session.get(Target, finding.target_id)
    if not target:
        return None, None

    group_ids = _group_ids_for_target(session, target.id)
    if group_ids:
        rules = session.exec(
            select(SlaRule).where(
                SlaRule.workspace_id == target.workspace_id,
                SlaRule.group_id.in_(group_ids),
                SlaRule.severity == finding.severity,
            )
        ).all()
        if rules:
            return min(r.days_to_fix for r in rules), "group"

    default_rule = session.exec(
        select(SlaRule).where(
            SlaRule.workspace_id == target.workspace_id,
            SlaRule.group_id.is_(None),
            SlaRule.severity == finding.severity,
        )
    ).first()
    if default_rule:
        return default_rule.days_to_fix, "workspace_default"

    return None, None


def resolve_sla_days(session: Session, finding: Finding) -> int | None:
    days, _source = resolve_sla_days_with_source(session, finding)
    return days


def compute_sla_status(session: Session, finding: Finding) -> tuple[int | None, bool]:
    """Returns (sla_days, sla_violated) for one finding, computed on read
    (issue #70 scope: query-time calculation, not a background job).

    sla_days is None when no SlaRule applies; in that case sla_violated is
    always False (no fabricated countdown/violation without a real rule).
    A finding that's been triaged to a closed state (Mitigated/Accepted
    Risk/False Positive/Won't Fix) is never "in violation" even past its
    SLA window, it's no longer an open risk waiting on a fix.
    """
    sla_days = resolve_sla_days(session, finding)
    if sla_days is None:
        return None, False
    if finding.state in CLOSED_STATES:
        return sla_days, False
    days_open = utcnow() - finding.first_seen
    return sla_days, days_open > timedelta(days=sla_days)
