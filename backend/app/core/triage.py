"""Shared single-finding state-transition + audit-log logic (moved out of
app/api/findings.py so app/api/pr_guardrail.py's ignore-approval flow can
apply the exact same transition to a matching main-table Finding, instead of
a Finding only ever changing state through the findings.py routes -- same
"one execution path, not two copies" philosophy as
app.core.pr_guardrail_executor.
"""
import logging

from sqlmodel import Session

from app.core.fp_learning import learn_suppression_rule
from app.models.models import Finding, FindingState, FindingStateLog

logger = logging.getLogger(__name__)


def apply_triage(
    finding: Finding,
    to_state: FindingState,
    reason: str,
    actor: str,
    session: Session,
    batch_id: str | None = None,
) -> Finding:
    """batch_id (issue #123) tags every FindingStateLog row written by the
    same bulk-triage call so the Audit Log can collapse them into one
    grouped feed item at read time instead of flooding the feed with N
    near-identical rows. None for a single-finding triage."""
    log = FindingStateLog(
        finding_id=finding.id, from_state=finding.state, to_state=to_state, reason=reason, actor=actor, batch_id=batch_id
    )
    finding.state = to_state
    session.add(finding)
    session.add(log)
    if to_state == FindingState.FALSE_POSITIVE:
        # Issue #76: teach the false-positive learning engine right at the
        # moment a human marks this as noise, so the same shape of finding
        # (same rule_id+tool+file basename) is auto-suppressed on future
        # ingestion; including in a different repo within this workspace.
        # Best-effort: a learning failure must never block the triage action
        # itself, same "never break the primary action" philosophy as the
        # Jira/notification hooks in app.core.ingestion.
        try:
            learn_suppression_rule(session, finding, actor=actor)
        except Exception:
            logger.exception("learn_suppression_rule failed for finding %s", finding.id)
    return finding
