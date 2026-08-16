"""First-run onboarding questionnaire API (issue #203).

Captures what kind of estate this deployment protects, so scanner defaults
match the operator's stack. See app.core.onboarding_profile for the rule that
governs the whole feature: answers may only narrow what runs, and never
silently.
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.auth import current_user
from app.api.deps import get_session
from app.core.onboarding_profile import (
    CLOUD_CHOICES,
    LANGUAGE_CHOICES,
    PR_ENFORCEMENT_CHOICES,
    parse_csv,
    recommend_tools,
    recommendation_summary,
)
from app.core.tool_registry import default_usage_for
from app.models.models import (
    OnboardingProfile,
    Organization,
    User,
    UserRole,
    Workspace,
    WorkspaceToolConfig,
)

router = APIRouter(prefix="/api/onboarding", tags=["onboarding"])

VALID_PR_PREFERENCES = {slug for slug, _ in PR_ENFORCEMENT_CHOICES}
VALID_LANGUAGES = {slug for slug, _ in LANGUAGE_CHOICES}
VALID_CLOUDS = {slug for slug, _ in CLOUD_CHOICES}


class ProfileRequest(BaseModel):
    languages: list[str] = []
    cloud_providers: list[str] = []
    uses_iac: bool | None = None
    builds_ai_features: bool | None = None
    ships_containers: bool | None = None
    pr_enforcement_preference: str | None = None
    uses_slack: bool | None = None
    uses_jira: bool | None = None
    # True when the operator clicked past the wizard. Recorded rather than
    # inferred from empty answers, because "skipped" and "answered nothing"
    # are different facts and only the first should stop the wizard
    # reappearing.
    skipped: bool = False


def _require_admin(user: User) -> None:
    if user.role != UserRole.ADMIN:
        raise HTTPException(403, "onboarding setup is admin-only")


def _first_organization(session: Session) -> Organization | None:
    return session.exec(select(Organization).order_by(Organization.id)).first()


def _serialize(profile: OnboardingProfile | None) -> dict:
    if profile is None:
        return {
            "exists": False,
            "completed": False,
            "skipped": False,
            "languages": [],
            "cloud_providers": [],
            "uses_iac": None,
            "builds_ai_features": None,
            "ships_containers": None,
            "pr_enforcement_preference": None,
            "uses_slack": None,
            "uses_jira": None,
        }
    return {
        "exists": True,
        "completed": profile.completed_at is not None,
        "skipped": profile.skipped,
        "languages": parse_csv(profile.languages),
        "cloud_providers": parse_csv(profile.cloud_providers),
        "uses_iac": profile.uses_iac,
        "builds_ai_features": profile.builds_ai_features,
        "ships_containers": profile.ships_containers,
        "pr_enforcement_preference": profile.pr_enforcement_preference,
        "uses_slack": profile.uses_slack,
        "uses_jira": profile.uses_jira,
    }


@router.get("/choices")
def onboarding_choices(user: User = Depends(current_user)):
    """The answer vocabularies, served from the backend so the wizard's
    options and the slugs the recommender matches on cannot drift apart."""
    return {
        "languages": [{"value": v, "label": l} for v, l in LANGUAGE_CHOICES],
        "cloud_providers": [{"value": v, "label": l} for v, l in CLOUD_CHOICES],
        "pr_enforcement": [{"value": v, "label": l} for v, l in PR_ENFORCEMENT_CHOICES],
    }


@router.get("/profile")
def get_profile(session: Session = Depends(get_session), user: User = Depends(current_user)):
    """Current answers plus whether the wizard should still be shown.

    `should_prompt` is deliberately computed here rather than in the client:
    it is the single condition that decides whether a fresh deployment
    interrupts the admin, and duplicating it in the frontend is how it ends
    up drifting.
    """
    org = _first_organization(session)
    profile = None
    if org:
        profile = session.exec(
            select(OnboardingProfile).where(OnboardingProfile.organization_id == org.id)
        ).first()

    data = _serialize(profile)
    data["should_prompt"] = (
        user.role == UserRole.ADMIN and org is not None and not data["completed"] and not data["skipped"]
    )
    return data


@router.get("/recommendations")
def get_recommendations(session: Session = Depends(get_session), user: User = Depends(current_user)):
    """What the current answers imply for tooling, without applying it.

    Separate from the save so the wizard can show the consequences before the
    operator commits -- turning scanners off should never be a surprise.
    """
    org = _first_organization(session)
    profile = (
        session.exec(select(OnboardingProfile).where(OnboardingProfile.organization_id == org.id)).first()
        if org
        else None
    )
    recs = recommend_tools(
        languages=parse_csv(profile.languages) if profile else [],
        uses_iac=profile.uses_iac if profile else None,
        builds_ai_features=profile.builds_ai_features if profile else None,
        ships_containers=profile.ships_containers if profile else None,
    )
    return {
        "recommendations": [{"tool": r.tool, "enabled": r.enabled, "reason": r.reason} for r in recs],
        "summary": recommendation_summary(recs),
    }


@router.post("/profile")
def save_profile(
    payload: ProfileRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Save answers and apply the resulting tool defaults.

    Applying writes through WorkspaceToolConfig (#75) rather than inventing a
    parallel switch, so Admin -> Tool Marketplace stays the one place that
    says what runs, and every choice made here remains editable there.
    """
    _require_admin(user)

    for lang in payload.languages:
        if lang not in VALID_LANGUAGES:
            raise HTTPException(400, f"unknown language: {lang}")
    for cloud in payload.cloud_providers:
        if cloud not in VALID_CLOUDS:
            raise HTTPException(400, f"unknown cloud provider: {cloud}")
    if payload.pr_enforcement_preference is not None and payload.pr_enforcement_preference not in VALID_PR_PREFERENCES:
        raise HTTPException(400, "pr_enforcement_preference must be 'block' or 'alert'")

    org = _first_organization(session)
    if org is None:
        raise HTTPException(400, "no organization exists yet")

    profile = session.exec(
        select(OnboardingProfile).where(OnboardingProfile.organization_id == org.id)
    ).first()
    if profile is None:
        profile = OnboardingProfile(organization_id=org.id)

    profile.languages = ",".join(payload.languages)
    profile.cloud_providers = ",".join(payload.cloud_providers)
    profile.uses_iac = payload.uses_iac
    profile.builds_ai_features = payload.builds_ai_features
    profile.ships_containers = payload.ships_containers
    profile.pr_enforcement_preference = payload.pr_enforcement_preference
    profile.uses_slack = payload.uses_slack
    profile.uses_jira = payload.uses_jira
    profile.skipped = payload.skipped
    profile.updated_at = datetime.utcnow()
    if not payload.skipped:
        profile.completed_at = datetime.utcnow()
    session.add(profile)
    session.commit()
    session.refresh(profile)

    applied: list[dict] = []
    if not payload.skipped:
        applied = _apply_recommendations(session, profile)

    return {**_serialize(profile), "applied": applied}


def _apply_recommendations(session: Session, profile: OnboardingProfile) -> list[dict]:
    """Write the recommended enablement into WorkspaceToolConfig for every
    workspace.

    Only tools recommended *off* are written. A recommended-on tool is left
    without a row, which already means "use the built-in default" -- writing
    it explicitly would freeze today's default into every workspace and mean
    a future change to `default_usage_for` silently stopped applying.
    """
    recs = recommend_tools(
        languages=parse_csv(profile.languages),
        uses_iac=profile.uses_iac,
        builds_ai_features=profile.builds_ai_features,
        ships_containers=profile.ships_containers,
    )
    disabled = [r for r in recs if not r.enabled]
    if not disabled:
        return []

    workspaces = session.exec(select(Workspace)).all()
    applied: list[dict] = []

    for workspace in workspaces:
        for rec in disabled:
            row = session.exec(
                select(WorkspaceToolConfig).where(
                    WorkspaceToolConfig.workspace_id == workspace.id,
                    WorkspaceToolConfig.tool == rec.tool,
                )
            ).first()
            if row is None:
                row = WorkspaceToolConfig(workspace_id=workspace.id, tool=rec.tool)
            defaults = default_usage_for(rec.tool)
            for surface in defaults:
                setattr(row, surface, False)
            session.add(row)
        applied.append({"workspace_id": workspace.id, "workspace": workspace.name})

    session.commit()
    return [{"tool": r.tool, "reason": r.reason} for r in disabled]
