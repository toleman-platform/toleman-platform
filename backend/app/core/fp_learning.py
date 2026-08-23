"""False-positive learning engine (issue #76).

Two halves, mirroring #74's Jira auto-create / #73's notifications shape:

  1. learn_suppression_rule() -- called from app.api.findings whenever a
     Finding is triaged to FindingState.FALSE_POSITIVE. Extracts a signature
     (rule_id, tool, file_path basename) from the finding and upserts a
     FalsePositiveRule for its workspace (deduped so re-triaging the same
     shape of finding twice doesn't stack duplicate rules).

  2. find_matching_rule() / apply_auto_suppression() -- called from
     app.core.ingestion.ingest_findings for every newly-created Finding,
     right alongside the existing dedup/Jira/notification hooks. If an
     active rule matches, the finding is created as usual (so it still shows
     up in history/audit) but is immediately marked FALSE_POSITIVE instead
     of Open, so it never nags a developer as a fresh finding.

See FalsePositiveRule's docstring in app.models.models for why the
signature is (rule_id, tool, file_path basename) and not a snippet hash.
"""
import logging
import os
from datetime import UTC, datetime

from sqlmodel import Session, select

from app.models.models import FalsePositiveRule, Finding, FindingState, FindingStateLog, Target

logger = logging.getLogger(__name__)

# Prefix stamped onto Finding.state_reason when a finding is auto-suppressed
# at ingestion time -- lets the "auto-suppressed this month" dashboard figure
# (app.core.widgets.resolve_fp_auto_suppressions) query Finding directly by
# state + a LIKE on this prefix instead of needing a second event-log table.
AUTO_SUPPRESS_REASON_PREFIX = "auto-suppressed via learned false-positive rule"


def _file_path_pattern(file_path: str) -> str | None:
    """Basename of a file path, normalized -- see FalsePositiveRule's
    docstring for why the pattern is a basename, not a full path. Returns
    None (matches "any file") if the path is empty/unusable."""
    if not file_path:
        return None
    base = os.path.basename(file_path.strip().replace("\\", "/"))
    return base.lower() or None


def extract_signature(finding: Finding) -> dict:
    return {
        "rule_id": finding.rule_id,
        "tool": finding.tool,
        "file_path_pattern": _file_path_pattern(finding.file_path),
    }


def learn_suppression_rule(session: Session, finding: Finding, actor: str = "system") -> FalsePositiveRule | None:
    """Extracts a suppression signature from `finding` (just triaged to
    FALSE_POSITIVE) and upserts a FalsePositiveRule scoped to its target's
    workspace. Returns None (no-op) if the finding's Target can't be
    resolved -- shouldn't happen in practice, but ingestion/triage must
    never hard-fail on this best-effort learning step.

    Upsert, not insert-always: an identical active rule (same workspace +
    rule_id + tool + file_path_pattern) already existing means this exact
    false-positive shape was already learned -- bump its audit fields
    (source_finding_id/created_by/created_at) to point at the latest
    occurrence rather than stacking a duplicate row a security engineer
    would then have to de-duplicate by hand in the management UI.
    """
    target = session.get(Target, finding.target_id)
    if not target:
        logger.warning("learn_suppression_rule: target %s not found for finding %s", finding.target_id, finding.id)
        return None

    signature = extract_signature(finding)
    existing = session.exec(
        select(FalsePositiveRule).where(
            FalsePositiveRule.workspace_id == target.workspace_id,
            FalsePositiveRule.rule_id == signature["rule_id"],
            FalsePositiveRule.tool == signature["tool"],
            FalsePositiveRule.file_path_pattern == signature["file_path_pattern"]
            if signature["file_path_pattern"] is not None
            else FalsePositiveRule.file_path_pattern.is_(None),
        )
    ).first()

    if existing:
        existing.active = True
        existing.source_finding_id = finding.id
        existing.created_by = actor
        existing.created_at = datetime.now(UTC).replace(tzinfo=None)
        session.add(existing)
        return existing

    rule = FalsePositiveRule(
        workspace_id=target.workspace_id,
        rule_id=signature["rule_id"],
        tool=signature["tool"],
        file_path_pattern=signature["file_path_pattern"],
        source_finding_id=finding.id,
        created_by=actor,
    )
    session.add(rule)
    return rule


def find_matching_rule(session: Session, workspace_id: int, rule_id: str, tool: str, file_path: str) -> FalsePositiveRule | None:
    """Looks up an active FalsePositiveRule matching this new finding's
    signature, preferring the most specific match: an exact file_path_pattern
    match wins over a workspace-wide "any file" (file_path_pattern is NULL)
    rule for the same rule_id/tool, so a narrowly-scoped rule someone
    deliberately kept precise isn't shadowed by a broader one that happens to
    also match."""
    pattern = _file_path_pattern(file_path)
    candidates = session.exec(
        select(FalsePositiveRule).where(
            FalsePositiveRule.workspace_id == workspace_id,
            FalsePositiveRule.rule_id == rule_id,
            FalsePositiveRule.tool == tool,
            FalsePositiveRule.active == True,  # noqa: E712
        )
    ).all()
    if not candidates:
        return None

    exact = [r for r in candidates if r.file_path_pattern is not None and r.file_path_pattern == pattern]
    if exact:
        return exact[0]
    wildcard = [r for r in candidates if r.file_path_pattern is None]
    return wildcard[0] if wildcard else None


def apply_auto_suppression(session: Session, rule: FalsePositiveRule, finding: Finding) -> None:
    """Marks a newly-created Finding FALSE_POSITIVE at ingestion time because
    it matched `rule`, logging the transition the same way any other triage
    is logged (FindingStateLog) so it's fully visible/undoable via the
    normal finding history + triage UI -- an auto-suppress engine a user
    can't inspect or revert would be a real product bug, not just a gap."""
    reason = f"{AUTO_SUPPRESS_REASON_PREFIX} #{rule.id}"
    log = FindingStateLog(
        finding_id=finding.id,
        from_state=finding.state,
        to_state=FindingState.FALSE_POSITIVE,
        reason=reason,
        actor="system",
    )
    finding.state = FindingState.FALSE_POSITIVE
    finding.state_reason = reason
    session.add(finding)
    session.add(log)

    rule.match_count += 1
    rule.last_matched_at = datetime.now(UTC).replace(tzinfo=None)
    session.add(rule)
