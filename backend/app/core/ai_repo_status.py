"""Persisting AI-repo detection onto a Target (issue #185).

Split out of ai_repo_detection.py so that module stays pure and trivially
testable (no Session, no models); same separation as app.core.security_score
computing over a resolved id list while the API layer owns scoping.
"""
from sqlmodel import Session, select

from app.core.ai_repo_detection import AiRepoDetection, detect_ai_repo
from app.models.models import SbomComponent, Target

# Cap on how much of the signal list is persisted. Signals are a human
# explanation, not an inventory; the full package list already lives in
# SbomComponent, and an unbounded string here would be a slow column to read
# on every target list.
MAX_SIGNAL_CHARS = 500


def components_for_target(session: Session, target: Target) -> list[tuple[str, str]]:
    """(name, package_type) for a target's persisted SBOM inventory on its
    default branch; the input detect_ai_repo() takes. A DB read, not a
    re-parse of the repo's manifests."""
    rows = session.exec(
        select(SbomComponent.name, SbomComponent.package_type).where(
            SbomComponent.target_id == target.id,
            SbomComponent.branch == target.default_branch,
        )
    ).all()
    return [(name, package_type) for name, package_type in rows]


def effective_is_ai_repo(target: Target) -> bool:
    """The value callers should gate on. A human override wins over
    detection in both directions; None means follow detection."""
    if target.is_ai_repo_override is not None:
        return target.is_ai_repo_override
    return target.is_ai_repo


def refresh_ai_repo_status(
    session: Session,
    target: Target,
    repo_path: str | None = None,
) -> AiRepoDetection:
    """Recompute detection for `target` and persist it. Returns the result.

    Deliberately does NOT touch is_ai_repo_override; detection keeps
    updating underneath a human decision rather than clobbering it, so the
    UI can still show "auto-detection says X, you have forced Y".

    Best-effort by contract: callers run this inside a scan, and a detection
    failure must never fail the scan (see the call site in
    app.tasks.scan_tasks). It commits its own change so a later failure in
    the caller doesn't roll the flag back.
    """
    result = detect_ai_repo(repo_path=repo_path, components=components_for_target(session, target))

    signals = "; ".join(result.signals)[:MAX_SIGNAL_CHARS]
    if target.is_ai_repo == result.detected and target.is_ai_repo_signals == signals:
        return result  # no change, skip the write

    target.is_ai_repo = result.detected
    target.is_ai_repo_signals = signals
    session.add(target)
    session.commit()
    session.refresh(target)
    return result
