"""Composite security health score (issue #63): a single 0-100 number (plus
a letter grade and a per-component breakdown) for org/group/target scope, so
a CISO/CTO gets a fast read on posture without digging through the Findings
table.

Every input is queried live from real data; no fabricated/mocked inputs
("no mock data" applies to what ships, not just to how it's verified):

  - findings_score  (weight FINDINGS_WEIGHT): open (Open/Reopened),
    default-branch findings. Each finding's contribution is SEVERITY_WEIGHT
    x its own target's `criticality_weight` (1-5, same factors
    core/scoring.py's per-finding priority score multiplies, so "a Critical
    in a Prod target hurts the org score more than the same Critical in a
    Dev target" holds for the composite score too, not just sort order) x a
    per-category risk multiplier (CATEGORY_RISK_WEIGHT below -- a License
    finding is a legal/compliance signal, not an exploitability one, so a
    scanner grading it "Critical" for licensing reasons shouldn't move this
    score the way an actually-exploitable Critical does). Normalized by the
    *sum* of in-scope targets' criticality_weight, not a plain target count,
    so an org that has never set criticality (every target defaults to 1)
    sees identical numbers to before this weighting existed. See
    `_findings_score`/`_finding_risk_weight` for the exact curve/constant.
  - sla_score       (weight SLA_WEIGHT): reuses
    app.core.sla.compute_sla_status per open/reopened default-branch finding
    (#70's real resolution + violation logic, not recomputed); % of
    SLA-tracked findings NOT in violation. If zero in-scope findings have an
    applicable SLA rule, this is treated as 100 (neutral "no evidence of SLA
    problems"), matching GET /api/dashboard/sla-compliance's own "no
    fabricated number" philosophy; an org that hasn't configured SLA rules
    yet shouldn't be scored as failing SLA.
  - coverage_score  (weight COVERAGE_WEIGHT): % of in-scope targets with at
    least one Scan row (any tool/branch/status) started within the last
    COVERAGE_WINDOW_DAYS days; "has this repo been scanned recently at
    all."
  - fp_rate_score   (weight FP_WEIGHT): 100 * (1 - false_positive_rate),
    where false_positive_rate = (in-scope findings currently in
    FALSE_POSITIVE state) / (all in-scope findings ever seen, any
    branch/state). All-time, no window: `Finding.state` is a current
    snapshot column, not an event log, so "ever marked FP" is best
    approximated by current state (a finding briefly marked FP then
    reclassified no longer counts; this can undercount historical FP
    noise slightly, but it never fabricates a number no real row supports).
    Zero findings ever seen -> 100 (no evidence of FP noise). Deliberately
    NOT restricted to the default branch; this is meant to reflect
    scanner/rule noisiness broadly, not branch-scoped posture.
  - trend_score     (weight TREND_WEIGHT): compares the open-finding
    weighted-severity total *right now* against the same total
    reconstructed as of TREND_WINDOW_DAYS ago, using the real
    FindingStateLog audit trail to determine whether each finding was open
    at that past timestamp; real week-over-week, not a guess. Uses the same
    per-finding weight (severity x target criticality x category risk) as
    findings_score, so a worsening trend and a dropping findings_score
    can't tell contradictory stories about the same findings. Stable or
    improving -> 100; worsening -> penalized proportionally to the percent
    increase, capped at 0.

Combined via the *_WEIGHT constants (sum to 100) into a 0-100 composite,
then a letter grade via GRADE_THRESHOLDS (documented below).
"""
from datetime import datetime, timedelta

from fastapi import HTTPException
from sqlmodel import Session, select

from app.core.sla import CLOSED_STATES, compute_sla_status
from app.core.time import utcnow
from app.core.tool_registry import NON_VULNERABILITY_CATEGORIES, tool_category
from app.models.models import (
    Finding,
    FindingState,
    FindingStateLog,
    OPEN_FINDING_STATES as OPEN_STATES,
    Scan,
    SEVERITY_WEIGHT,
    Target,
    TargetGroup,
)

# ---------------------------------------------------------------------------
# Tunable constants, documented here, not buried in the formula.
# ---------------------------------------------------------------------------

# How many "average weighted-severity points per in-scope target" it takes
# to walk the findings component all the way down to 0. E.g. an average of
# one Critical (weight 5) + one High (weight 4) open finding per target
# (9 points) leaves ~55/100; an average of 4 Criticals (20 points) bottoms
# out at 0. Chosen so a handful of untriaged Criticals per repo visibly
# tanks the score without a single Low finding anywhere zeroing it out.
SEVERITY_POINTS_TO_ZERO = 20.0

# Per-category multiplier on a finding's contribution to findings_score/
# trend_score: severity already says how bad a finding is *within* its
# category, this says how much a category's worst case should move a
# security *posture* score at all. Deliberately narrow -- only License is
# called out, at zero weight, because it's a legal/compliance signal (a
# scanner can grade a copyleft license "Critical" for licensing reasons
# that have nothing to do with exploitability) rather than a security risk
# in the same sense as an exploitable code vuln, a leaked secret, or a
# vulnerable dependency -- it should never move this score, not just move
# it less. Every other category (including ones added to the registry
# later) defaults to DEFAULT_CATEGORY_RISK_WEIGHT via `.get`, so severity
# alone keeps doing the differentiating work there, unchanged from before
# this multiplier existed.
CATEGORY_RISK_WEIGHT = {
    "License": 0.0,
}
DEFAULT_CATEGORY_RISK_WEIGHT = 1.0

# "Scanned recently" window for coverage.
COVERAGE_WINDOW_DAYS = 30

# Week-over-week trend comparison window.
TREND_WINDOW_DAYS = 7

FINDINGS_WEIGHT = 35
SLA_WEIGHT = 25
COVERAGE_WEIGHT = 15
FP_WEIGHT = 10
TREND_WEIGHT = 15
assert FINDINGS_WEIGHT + SLA_WEIGHT + COVERAGE_WEIGHT + FP_WEIGHT + TREND_WEIGHT == 100

# Letter grade thresholds, highest first; first threshold the composite
# score meets or exceeds wins.
GRADE_THRESHOLDS: list[tuple[int, str]] = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]


def _grade(score: float) -> str:
    for threshold, letter in GRADE_THRESHOLDS:
        if score >= threshold:
            return letter
    return "F"


def _default_branch_findings(session: Session, target_ids: list[int], targets_by_id: dict[int, Target]) -> list[Finding]:
    if not target_ids:
        return []
    rows = session.exec(select(Finding).where(Finding.target_id.in_(target_ids))).all()
    return [f for f in rows if targets_by_id.get(f.target_id) and f.branch == targets_by_id[f.target_id].default_branch]


def _finding_risk_weight(finding: Finding, target: Target | None) -> float:
    """A single finding's contribution to findings_score/trend_score:
    SEVERITY_WEIGHT x the owning target's criticality_weight (1-5, clamped
    same as core/scoring.py's compute_priority_score) x CATEGORY_RISK_WEIGHT
    for its vulnerability-type category. `target` is only ever None for a
    finding whose target didn't resolve into targets_by_id, which shouldn't
    happen for anything _default_branch_findings already returned; falls
    back to criticality 1 (neutral) rather than raising, since a missing
    target is exactly the kind of data inconsistency this score should
    degrade gracefully on, not crash on."""
    criticality = max(1, min(5, target.criticality_weight)) if target else 1
    category_weight = CATEGORY_RISK_WEIGHT.get(tool_category(finding.tool), DEFAULT_CATEGORY_RISK_WEIGHT)
    return SEVERITY_WEIGHT[finding.severity] * criticality * category_weight


def _total_criticality(targets_by_id: dict[int, Target]) -> float:
    """Sum of in-scope targets' criticality_weight (clamped 1-5), the
    denominator findings_score/trend_score normalize by instead of a plain
    target count. Every target defaults to criticality_weight=1, so for an
    org that has never customized it this equals target_count exactly --
    identical numbers to before per-target criticality weighting existed."""
    return sum(max(1, min(5, t.criticality_weight)) for t in targets_by_id.values())


def _findings_score(open_default_branch: list[Finding], targets_by_id: dict[int, Target], total_criticality: float) -> dict:
    weighted_sum = sum(_finding_risk_weight(f, targets_by_id.get(f.target_id)) for f in open_default_branch)
    avg_per_target = weighted_sum / max(1, total_criticality)
    score = max(0.0, 100.0 - (avg_per_target / SEVERITY_POINTS_TO_ZERO) * 100.0)
    return {
        "score": round(score, 1),
        "weight": FINDINGS_WEIGHT,
        "open_findings": len(open_default_branch),
        "weighted_severity_sum": round(weighted_sum, 2),
        "avg_weighted_severity_per_target": round(avg_per_target, 2),
    }


def _sla_score(session: Session, open_default_branch: list[Finding]) -> dict:
    with_sla = 0
    in_violation = 0
    # SlaRule is keyed purely on severity (app.core.sla), with no category
    # awareness -- a workspace's "High: fix within 30 days" rule would
    # otherwise apply just as literally to a License finding a scanner
    # happens to grade High (e.g. a copyleft license) as to an actually
    # exploitable one. A license is not something anyone "fixes" on a
    # days-to-fix clock, so it's excluded here the same way it's zeroed out
    # of findings_score/trend_score via CATEGORY_RISK_WEIGHT.
    for f in open_default_branch:
        if tool_category(f.tool) in NON_VULNERABILITY_CATEGORIES:
            continue
        sla_days, violated = compute_sla_status(session, f)
        if sla_days is None:
            continue
        with_sla += 1
        if violated:
            in_violation += 1

    if with_sla == 0:
        score = 100.0
    else:
        score = 100.0 * (with_sla - in_violation) / with_sla

    return {
        "score": round(score, 1),
        "weight": SLA_WEIGHT,
        "with_sla": with_sla,
        "in_violation": in_violation,
        "compliant": with_sla - in_violation,
        "note": "no SLA-tracked findings in scope, treated as neutral 100" if with_sla == 0 else None,
    }


def _coverage_score(session: Session, target_ids: list[int]) -> dict:
    if not target_ids:
        return {"score": 0.0, "weight": COVERAGE_WEIGHT, "scanned_targets": 0, "total_targets": 0, "window_days": COVERAGE_WINDOW_DAYS}

    cutoff = utcnow() - timedelta(days=COVERAGE_WINDOW_DAYS)
    scanned_target_ids = set(
        session.exec(
            select(Scan.target_id).where(Scan.target_id.in_(target_ids), Scan.started_at >= cutoff).distinct()
        ).all()
    )
    scanned = len(scanned_target_ids)
    total = len(target_ids)
    score = 100.0 * scanned / total
    return {
        "score": round(score, 1),
        "weight": COVERAGE_WEIGHT,
        "scanned_targets": scanned,
        "total_targets": total,
        "window_days": COVERAGE_WINDOW_DAYS,
    }


def _fp_rate_score(session: Session, target_ids: list[int]) -> dict:
    if not target_ids:
        return {"score": 100.0, "weight": FP_WEIGHT, "false_positives": 0, "total_findings": 0, "fp_rate": 0.0}

    total = session.exec(select(Finding).where(Finding.target_id.in_(target_ids))).all()
    total_count = len(total)
    fp_count = sum(1 for f in total if f.state == FindingState.FALSE_POSITIVE)
    fp_rate = (fp_count / total_count) if total_count else 0.0
    score = 100.0 if total_count == 0 else 100.0 * (1 - fp_rate)
    return {
        "score": round(score, 1),
        "weight": FP_WEIGHT,
        "false_positives": fp_count,
        "total_findings": total_count,
        "fp_rate": round(fp_rate, 4),
    }


def _state_at(as_of: datetime, first_seen: datetime, logs: list[FindingStateLog]) -> str | None:
    """Reconstructs a finding's state as of `as_of` from its real
    FindingStateLog audit trail. Returns None if the finding didn't exist
    yet (first_seen is after as_of). Every finding starts life as OPEN
    (Finding.state default), so with no applicable log entries the state at
    any point after first_seen is OPEN."""
    if first_seen > as_of:
        return None
    applicable = [log for log in logs if log.created_at <= as_of]
    if not applicable:
        return FindingState.OPEN
    applicable.sort(key=lambda log: log.created_at)
    return applicable[-1].to_state


def _weighted_open_sum_at(
    as_of: datetime,
    findings: list[Finding],
    logs_by_finding: dict[int, list[FindingStateLog]],
    targets_by_id: dict[int, Target],
) -> float:
    total = 0.0
    for f in findings:
        state = _state_at(as_of, f.first_seen, logs_by_finding.get(f.id, []))
        if state is None:
            continue
        if state not in CLOSED_STATES:
            # Anything not a recognized closed/terminal state (i.e. Open or
            # Reopened) counts as open, mirroring app.core.sla.CLOSED_STATES.
            # Same per-finding weight as findings_score (severity x target
            # criticality x category risk), using the target's *current*
            # criticality_weight -- that field isn't itself versioned over
            # time, only the finding's state is being reconstructed here.
            total += _finding_risk_weight(f, targets_by_id.get(f.target_id))
    return total


def _trend_score(session: Session, target_ids: list[int], targets_by_id: dict[int, Target]) -> dict:
    if not target_ids:
        return {"score": 100.0, "weight": TREND_WEIGHT, "direction": "stable", "current_weighted_sum": 0.0, "prior_weighted_sum": 0.0, "window_days": TREND_WINDOW_DAYS}

    # All findings that could plausibly have been open within the trend
    # window (created before now, i.e. all of them; first_seen is always
    # <= now) restricted to the default branch, same posture convention as
    # the findings component.
    findings = _default_branch_findings(session, target_ids, targets_by_id)
    finding_ids = [f.id for f in findings]
    logs_by_finding: dict[int, list[FindingStateLog]] = {}
    if finding_ids:
        logs = session.exec(select(FindingStateLog).where(FindingStateLog.finding_id.in_(finding_ids))).all()
        for log in logs:
            logs_by_finding.setdefault(log.finding_id, []).append(log)

    now = utcnow()
    prior_as_of = now - timedelta(days=TREND_WINDOW_DAYS)

    current_sum = _weighted_open_sum_at(now, findings, logs_by_finding, targets_by_id)
    prior_sum = _weighted_open_sum_at(prior_as_of, findings, logs_by_finding, targets_by_id)

    if current_sum <= prior_sum:
        score = 100.0
        direction = "stable" if current_sum == prior_sum else "improving"
    else:
        pct_increase = (current_sum - prior_sum) / max(prior_sum, 1.0)
        score = max(0.0, 100.0 - pct_increase * 100.0)
        direction = "worsening"

    return {
        "score": round(score, 1),
        "weight": TREND_WEIGHT,
        "direction": direction,
        "current_weighted_sum": round(current_sum, 1),
        "prior_weighted_sum": round(prior_sum, 1),
        "window_days": TREND_WINDOW_DAYS,
    }


def compute_security_score(session: Session, target_ids: list[int]) -> dict:
    """Computes the composite score for a resolved, already-authorized list
    of target ids (org-wide/group/single-target scoping + workspace access
    checks happen at the API layer, same separation as the rest of
    app.core). `target_ids` may be empty (e.g. a group with no targets, or a
    caller with no accessible workspaces); every component degrades to a
    real, documented neutral/zero value rather than raising or fabricating
    a number."""
    targets_by_id: dict[int, Target] = {}
    if target_ids:
        targets_by_id = {t.id: t for t in session.exec(select(Target).where(Target.id.in_(target_ids))).all()}
        target_ids = list(targets_by_id.keys())  # drop any ids that didn't resolve

    open_default_branch = [f for f in _default_branch_findings(session, target_ids, targets_by_id) if f.state in OPEN_STATES]

    components = {
        "findings": _findings_score(open_default_branch, targets_by_id, _total_criticality(targets_by_id)),
        "sla": _sla_score(session, open_default_branch),
        "coverage": _coverage_score(session, target_ids),
        "fp_rate": _fp_rate_score(session, target_ids),
        "trend": _trend_score(session, target_ids, targets_by_id),
    }

    if not target_ids:
        composite = 0.0
    else:
        composite = sum(c["score"] * c["weight"] for c in components.values()) / 100.0

    weakest = min(components.items(), key=lambda kv: kv[1]["score"])[0] if target_ids else None

    return {
        "score": round(composite, 1),
        "grade": _grade(composite) if target_ids else None,
        "target_count": len(target_ids),
        "weakest_component": weakest,
        "components": components,
    }


def resolve_target_ids_for_scope(
    session: Session,
    ws_ids: list[int] | None,
    target_id: int | None,
    group_id: int | None,
) -> list[int]:
    """Resolves the org/group/target scoping shared by
    GET /api/dashboard/security-score and the `security_score` dashboard
    widget resolver (app.core.widgets), same mutually-exclusive
    target_id/group_id filter convention as #61's findings.py group_id
    filtering, layered on top of the caller's accessible_workspace_ids
    (issue #57). Raises HTTPException(404) for a target_id the caller can't
    access; an inaccessible/empty group_id resolves to an empty list rather
    than 404 (mirrors findings.py's group_id handling, which doesn't
    validate group ownership either; the workspace filter alone already
    excludes it)."""
    if target_id is not None and group_id is not None:
        raise HTTPException(400, "target_id and group_id are mutually exclusive")

    if ws_ids is not None and not ws_ids:
        return []

    if target_id is not None:
        target = session.get(Target, target_id)
        if not target or (ws_ids is not None and target.workspace_id not in ws_ids):
            raise HTTPException(404, "Target not found")
        return [target_id]

    if group_id is not None:
        query = select(Target.id).join(TargetGroup, TargetGroup.target_id == Target.id).where(
            TargetGroup.group_id == group_id
        )
        if ws_ids is not None:
            query = query.where(Target.workspace_id.in_(ws_ids))
        return list(session.exec(query).all())

    query = select(Target.id)
    if ws_ids is not None:
        query = query.where(Target.workspace_id.in_(ws_ids))
    return list(session.exec(query).all())
