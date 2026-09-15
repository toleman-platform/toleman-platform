"""Workspace scoring configuration and per-finding signal gathering (#201).

`app.core.scoring` is pure arithmetic: hand it signals, get a breakdown.
This module is the part that knows where the signals live --- the
ScoringWeight rows, the Target's #251 metadata, the cached CveEnrichment
row --- and turns a Finding into the arguments that engine takes.

Nothing here ever hits the network. Enrichment is read out of the local
CveEnrichment cache only, exactly as `app.core.fixability.fixability_for_
finding` already does: a scoring call must not be able to stall on NVD being
slow, and a CVE nobody has enriched yet is simply an unestablished signal,
which contributes nothing. That is the failsafe working as designed, not a
gap --- the score rises to account for the CVSS vector once enrichment has
actually run, and never drops because it has not.
"""

from sqlmodel import Session, select

from app.core.cvss import CvssDecomposition, parse_cvss_vector
from app.core.fixability import UNKNOWN, fixability_for_enrichment
from app.core.scoring import (
    BASELINE_WEIGHTS,
    SIGNAL_CONTRIBUTION,
    SIGNAL_DESCRIPTIONS,
    SIGNAL_LABELS,
    SIGNAL_MAX_POINTS,
    ScoreBreakdown,
    compute_score_breakdown,
    resolve_weights,
)
from app.models.models import (
    CveEnrichment,
    Finding,
    ScoringSignal,
    ScoringWeight,
    Target,
)


def workspace_scoring_weights(session: Session, workspace_id: int | None) -> dict[ScoringSignal, float]:
    """Effective weights for one workspace: the shipped baseline, with any
    ScoringWeight rows layered on top.

    A workspace with no rows gets `BASELINE_WEIGHTS` --- which is what makes
    "an install that configures nothing scores exactly as it does today"
    true. `workspace_id=None` (a caller with no workspace context) gets the
    baseline for the same reason: guessing another workspace's configuration
    would be worse than scoring on the documented default.
    """
    if workspace_id is None:
        return dict(BASELINE_WEIGHTS)
    rows = session.exec(select(ScoringWeight).where(ScoringWeight.workspace_id == workspace_id)).all()
    # Merged (and clamped) here rather than handed to the engine as bare
    # overrides, so this returns the *effective* configuration: the Admin
    # surface and the score breakdown both need the number that will
    # actually be applied, not a sparse diff they would each have to
    # reconstruct the baseline from.
    return resolve_weights({row.signal: row.weight for row in rows})


# Presentation order for the Admin surface: how bad the tool says it is, how
# exploitable it actually is, whether anyone is exploiting it, where it runs,
# whether what it runs in even ships, how much the thing it runs on matters,
# and whether it can be fixed -- the order a person reasons about a finding
# in, not the enum's declaration order.
SIGNAL_ORDER = (
    ScoringSignal.SEVERITY,
    ScoringSignal.CVSS_EXPLOITABILITY,
    ScoringSignal.EPSS,
    ScoringSignal.KEV,
    ScoringSignal.INTERNET_EXPOSURE,
    # Sits next to internet exposure because it answers the same question
    # one layer in: exposure is whether the host is reachable, scope is
    # whether the vulnerable code is even deployed on it.
    ScoringSignal.DEPENDENCY_SCOPE,
    ScoringSignal.BUSINESS_CRITICALITY,
    ScoringSignal.FIXABILITY,
)

# A hand-maintained order is a list someone will forget to extend. Failing at
# import time is the cheap version of that mistake; the expensive version is a
# signal that scores findings but never appears in the UI that configures it.
assert set(SIGNAL_ORDER) == set(ScoringSignal), "SIGNAL_ORDER must cover every ScoringSignal"


def signal_catalog() -> list[dict]:
    """The fixed set of signal slots, for the Admin configuration surface."""
    return [
        {
            "signal": signal.value,
            "label": SIGNAL_LABELS[signal],
            "description": SIGNAL_DESCRIPTIONS[signal],
            "baseline_weight": BASELINE_WEIGHTS[signal],
            "max_points": SIGNAL_MAX_POINTS[signal],
            "contribution": SIGNAL_CONTRIBUTION[signal],
        }
        for signal in SIGNAL_ORDER
    ]


def cvss_for_enrichment(row: CveEnrichment | None) -> CvssDecomposition:
    """Decomposition for an already-loaded enrichment row.

    Prefers the persisted columns and falls back to re-parsing the stored
    vector string, so a row written before #201 (or by a code path that did
    not backfill) still scores correctly instead of silently reading as
    unknown. `app.core.cve_enrichment.get_cve_enrichment` backfills the
    columns on read, so the fallback only runs for rows nothing has touched
    since.
    """
    if row is None:
        return parse_cvss_vector(None)
    stored = CvssDecomposition(
        version=row.cvss_version,
        attack_vector=row.cvss_attack_vector,
        attack_complexity=row.cvss_attack_complexity,
        privileges_required=row.cvss_privileges_required,
        user_interaction=row.cvss_user_interaction,
    )
    if not stored.is_unknown:
        return stored
    return parse_cvss_vector(row.cvss_vector)


def breakdown_for_signals(
    *,
    finding: Finding,
    target: Target | None,
    enrichment: CveEnrichment | None,
    weights: dict[ScoringSignal, float],
) -> ScoreBreakdown:
    """Score one finding from already-loaded rows.

    Takes the rows rather than fetching them so an ingestion run over a few
    hundred findings resolves weights once and enrichment in one batched
    query, instead of two lookups per finding.
    """
    return compute_score_breakdown(
        finding.severity,
        target.criticality_weight if target else 1,
        epss_score=finding.epss_score,
        kev_listed=finding.kev_listed,
        cvss=cvss_for_enrichment(enrichment),
        cve_id=finding.cve_id,
        target_label=target.label if target else None,
        target_environment=target.environment if target else None,
        target_owner=target.owner if target else None,
        fixability=fixability_for_enrichment(enrichment) if finding.cve_id else UNKNOWN,
        # Read off the persisted column (#500), not recomputed: the
        # scanner output that produced it is long gone by the time a
        # re-score runs.
        dependency_scope=getattr(finding, "dependency_scope", "unknown"),
        weights=weights,
    )


def score_breakdown_for_finding(session: Session, finding: Finding) -> ScoreBreakdown:
    """Score one finding, resolving everything it needs from the database.

    The single-finding path (the finding detail view). Recomputes live from
    current data rather than reading the stored `priority_score`, so the
    explanation is an explanation of the signals as they stand now --- which
    is also why the API returns both numbers and says so when they differ.
    """
    target = session.get(Target, finding.target_id)
    enrichment = None
    if finding.cve_id:
        enrichment = session.exec(
            select(CveEnrichment).where(CveEnrichment.cve_id == finding.cve_id)
        ).first()
    weights = workspace_scoring_weights(session, target.workspace_id if target else None)
    return breakdown_for_signals(
        finding=finding, target=target, enrichment=enrichment, weights=weights
    )


def enrichment_map(session: Session, cve_ids: list[str]) -> dict[str, CveEnrichment]:
    """Cached enrichment rows for a batch of CVE IDs, in one query."""
    if not cve_ids:
        return {}
    rows = session.exec(select(CveEnrichment).where(CveEnrichment.cve_id.in_(cve_ids))).all()
    return {row.cve_id: row for row in rows}
