"""Risk scoring configuration (#201): workspace-scoped weights for the
fixed signal slots the prioritisation engine scores on.

Gated at SECURITY_ENGINEER (or global admin), the same trust level as
sla_rules.py and policies.py rather than groups.py's DEVELOPER. Turning the
severity weight down re-ranks every finding in the workspace on the next
scan and moves what PR Guardrail blocks; that is a security-policy decision,
not repo organisation.

The listing always returns the full catalogue with effective values merged
in, not just the stored overrides. A sparse response would make the client
reimplement `BASELINE_WEIGHTS`, and two copies of a default is how the
"unconfigured install scores exactly as before" guarantee quietly stops
being true.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.auth import accessible_workspace_ids, current_user, enforce_workspace_role
from app.api.deps import get_session
from app.core.scoring import MAX_SCORE
from app.core.scoring_config import signal_catalog
from app.core.time import utcnow
from app.models.models import ScoringSignal, ScoringWeight, User, WorkspaceRole

router = APIRouter(prefix="/api/scoring-weights", tags=["scoring-weights"])

# An upper bound on a weight, so a typo ("10" for "1.0") cannot produce a
# configuration where one signal drowns out every other. There is no lower
# bound below 0: 0 means "off", and negatives are rejected outright rather
# than clamped, because a caller asking for a negative weight is asking for a
# signal that *subtracts*, and saying no to that explicitly is better than
# silently doing something else. See ScoringWeight's docstring for why the
# engine can never subtract.
MAX_WEIGHT = 5.0


class ScoringWeightOut(BaseModel):
    """One signal slot's effective configuration.

    `rule_id` is None and `is_default` True when nothing is stored for this
    workspace and the shipped baseline is in force. The client needs both:
    "0.0 because that is the baseline" and "0.0 because someone switched
    this off" look identical otherwise, and only the second one has a
    Reset action.
    """

    signal: str
    label: str
    description: str
    weight: float
    baseline_weight: float
    max_points: int | None
    is_default: bool
    rule_id: int | None
    workspace_id: int


class ScoringWeightsResponse(BaseModel):
    workspace_id: int
    max_score: int
    signals: list[ScoringWeightOut]


class SetScoringWeightRequest(BaseModel):
    workspace_id: int
    signal: ScoringSignal
    weight: float


def _validate_weight(weight: float) -> float:
    if weight != weight or weight in (float("inf"), float("-inf")):  # NaN / inf
        raise HTTPException(status_code=422, detail="weight must be a finite number")
    if weight < 0:
        raise HTTPException(
            status_code=422,
            detail="weight must be >= 0; a negative weight would make a signal subtract from a priority",
        )
    if weight > MAX_WEIGHT:
        raise HTTPException(status_code=422, detail=f"weight must be <= {MAX_WEIGHT}")
    return float(weight)


def _effective(session: Session, workspace_id: int) -> ScoringWeightsResponse:
    stored = {
        row.signal: row
        for row in session.exec(
            select(ScoringWeight).where(ScoringWeight.workspace_id == workspace_id)
        ).all()
    }
    signals = []
    for entry in signal_catalog():
        signal = ScoringSignal(entry["signal"])
        row = stored.get(signal)
        signals.append(
            ScoringWeightOut(
                signal=entry["signal"],
                label=entry["label"],
                description=entry["description"],
                weight=row.weight if row else entry["baseline_weight"],
                baseline_weight=entry["baseline_weight"],
                max_points=entry["max_points"],
                is_default=row is None,
                rule_id=row.id if row else None,
                workspace_id=workspace_id,
            )
        )
    return ScoringWeightsResponse(workspace_id=workspace_id, max_score=MAX_SCORE, signals=signals)


@router.get("")
def list_scoring_weights(
    workspace_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
) -> ScoringWeightsResponse:
    """Effective scoring configuration for one workspace.

    `workspace_id` is required rather than optional-with-a-fan-out (unlike
    GET /api/sla-rules): this is a per-workspace calibration someone edits
    one workspace at a time, and a flattened cross-workspace list of
    identical baseline rows would be noise.
    """
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and workspace_id not in ws_ids:
        # 404 rather than 403, matching the wording used across this codebase
        # for a resource in a workspace the caller cannot see.
        raise HTTPException(status_code=404, detail="workspace not found")
    return _effective(session, workspace_id)


@router.put("")
def set_scoring_weight(
    payload: SetScoringWeightRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
) -> ScoringWeightsResponse:
    """Upsert one signal's weight. Idempotent, so the UI can PUT on every
    edit without tracking whether a row already exists."""
    weight = _validate_weight(payload.weight)
    # workspace_id lives in the JSON body, so this is checked explicitly
    # rather than via a Depends-based require_workspace_role; same reason
    # POST /api/sla-rules does.
    enforce_workspace_role(session, user, WorkspaceRole.SECURITY_ENGINEER, workspace_id=payload.workspace_id)

    existing = session.exec(
        select(ScoringWeight).where(
            ScoringWeight.workspace_id == payload.workspace_id,
            ScoringWeight.signal == payload.signal,
        )
    ).first()
    if existing:
        existing.weight = weight
        existing.updated_at = utcnow()
        session.add(existing)
    else:
        session.add(
            ScoringWeight(workspace_id=payload.workspace_id, signal=payload.signal, weight=weight)
        )
    session.commit()
    return _effective(session, payload.workspace_id)


@router.delete("/{rule_id}")
def delete_scoring_weight(
    rule_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
) -> ScoringWeightsResponse:
    """Drop an override, reverting that signal to the shipped baseline.

    Hard delete, unlike PolicyRule's soft delete: a weight is a dial, not an
    audit-relevant suppression, and a reverted dial leaves no claim behind
    that anyone needs to reconstruct later.
    """
    rule = session.get(ScoringWeight, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="scoring weight not found")
    enforce_workspace_role(session, user, WorkspaceRole.SECURITY_ENGINEER, workspace_id=rule.workspace_id)
    workspace_id = rule.workspace_id
    session.delete(rule)
    session.commit()
    return _effective(session, workspace_id)
