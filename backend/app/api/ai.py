
# httpx stays imported here (even though the calls themselves now live in
# app.core.ai_provider) because tests monkeypatch "app.api.ai.httpx.post";
# httpx is a single shared module object, so patching .post via this
# attribute path still affects ai_provider's own httpx.post call too.
import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from app.api.auth import accessible_workspace_ids, current_user
from app.api.config import get_platform_config
from app.api.deps import get_session
from app.core.ai_provider import (
    call_anthropic,
    call_openai_compatible,
    openai_compatible_configured,
    resolve_anthropic_key,
    resolve_provider,
)
from app.core.config import settings
from app.core.time import utcnow
from app.models.models import AiAnalysisRun, Finding, PlatformConfig, Target, User

router = APIRouter(prefix="/api/ai", tags=["ai"])

# Kept as thin aliases (rather than deleting) since existing tests reference
# these names on this module; the real logic now lives in app.core.ai_provider
# so app.core.autofix can share it without importing an api module.
_resolve_anthropic_key = resolve_anthropic_key
_resolve_provider = resolve_provider
_openai_compatible_configured = openai_compatible_configured


def _build_prompt(finding: Finding) -> str:
    return f"""You are a security engineer. Analyze this vulnerability finding and give a concise, actionable remediation.

Tool: {finding.tool}
Rule: {finding.rule_id}
Severity: {finding.severity}
Title: {finding.title}
File: {finding.file_path}{f':{finding.line_start}' if finding.line_start else ''}
Description: {finding.description}

Respond in under 150 words: what the risk is and the specific code/config fix."""


def _analyze_with_anthropic(session: Session, finding: Finding) -> str:
    return call_anthropic(session, _build_prompt(finding))


def _analyze_with_openai_compatible(config: PlatformConfig, finding: Finding) -> str:
    return call_openai_compatible(config, _build_prompt(finding))


@router.get("/status")
def status(session: Session = Depends(get_session)):
    provider = _resolve_provider(session)
    if provider == "openai_compatible":
        config = get_platform_config(session)
        configured = _openai_compatible_configured(config)
    else:
        configured = bool(_resolve_anthropic_key(session))
    return {"configured": configured, "provider": provider}


def _record_analysis_run(session: Session, user: User, finding_id: int) -> None:
    """Issue #122: upsert the (user, finding) "recently analyzed" marker;
    see AiAnalysisRun's docstring for why this is an upsert, not an insert.
    Best-effort: a failure here must never fail the analysis response
    itself (same "never break the primary action" philosophy as the
    Jira/Slack/notification hooks elsewhere in this codebase)."""
    try:
        existing = session.exec(
            select(AiAnalysisRun).where(AiAnalysisRun.user_id == user.id, AiAnalysisRun.finding_id == finding_id)
        ).first()
        now = utcnow()
        if existing:
            existing.last_analyzed_at = now
            existing.analysis_count += 1
            session.add(existing)
        else:
            session.add(AiAnalysisRun(user_id=user.id, finding_id=finding_id, created_at=now, last_analyzed_at=now))
        session.commit()
    except Exception:
        session.rollback()


@router.post("/analyze/{finding_id}")
def analyze_finding(finding_id: int, session: Session = Depends(get_session), user: User = Depends(current_user)):
    """Real remediation suggestion via the configured AI provider (Admin >
    Global Integrations): Anthropic's Claude API, or any OpenAI-compatible
    chat completions endpoint (Kimi/Moonshot, Ollama, vLLM, LM Studio, ...).
    Returns the same {finding_id, analysis} shape regardless of provider. If
    no provider is configured, returns 400 rather than a fabricated answer."""
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")

    # Issue #57-style workspace scoping: a non-admin caller shouldn't be
    # able to run analysis on (or discover the existence of) a finding
    # outside their accessible workspaces.
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None:
        target = session.get(Target, finding.target_id)
        if not target or target.workspace_id not in ws_ids:
            raise HTTPException(status_code=404, detail="finding not found")

    provider = _resolve_provider(session)
    if provider == "openai_compatible":
        config = get_platform_config(session)
        text = _analyze_with_openai_compatible(config, finding)
    else:
        text = _analyze_with_anthropic(session, finding)

    _record_analysis_run(session, user, finding_id)

    return {"finding_id": finding_id, "analysis": text}


@router.get("/recent")
def recent_analyses(
    limit: int = 8, session: Session = Depends(get_session), user: User = Depends(current_user)
) -> list[dict]:
    """Issue #122: "recent analyses" landing state for the AI Analysis page;
    findings this user has previously run AI analysis on, most-recent
    first. Deliberately per-user (not workspace-wide) since AiAnalysisRun
    tracks who ran the analysis; still re-checked against the caller's
    current accessible workspaces (not just filtered at write time) so a
    since-revoked workspace membership can't leak a finding's
    title/severity through this list."""
    ws_ids = accessible_workspace_ids(session, user)
    limit = max(min(limit, 50), 1)

    rows = session.exec(
        select(AiAnalysisRun)
        .where(AiAnalysisRun.user_id == user.id)
        .order_by(AiAnalysisRun.last_analyzed_at.desc())
        .limit(limit * 2)  # headroom for post-filtering findings that no longer resolve/are in scope
    ).all()

    results: list[dict] = []
    for row in rows:
        if len(results) >= limit:
            break
        finding = session.get(Finding, row.finding_id)
        if not finding:
            continue
        target = session.get(Target, finding.target_id)
        if not target:
            continue
        if ws_ids is not None and target.workspace_id not in ws_ids:
            continue
        results.append(
            {
                "finding_id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "cve_id": finding.cve_id,
                "target_id": target.id,
                "target_name": target.name,
                "state": finding.state,
                "last_analyzed_at": row.last_analyzed_at,
            }
        )
    return results
