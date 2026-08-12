from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session

from app.api.deps import get_session
from app.core.config import settings
from app.models.models import Finding

router = APIRouter(prefix="/api/ai", tags=["ai"])


@router.get("/status")
def status():
    return {"configured": bool(settings.anthropic_api_key)}


@router.post("/analyze/{finding_id}")
def analyze_finding(finding_id: int, session: Session = Depends(get_session)):
    """Real remediation suggestion via the Claude API. Requires ANTHROPIC_API_KEY
    in backend .env — if absent, returns 400 rather than a fabricated answer."""
    if not settings.anthropic_api_key:
        raise HTTPException(status_code=400, detail="ANTHROPIC_API_KEY not configured in backend .env")

    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")

    import anthropic

    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    prompt = f"""You are a security engineer. Analyze this vulnerability finding and give a concise, actionable remediation.

Tool: {finding.tool}
Rule: {finding.rule_id}
Severity: {finding.severity}
Title: {finding.title}
File: {finding.file_path}{f':{finding.line_start}' if finding.line_start else ''}
Description: {finding.description}

Respond in under 150 words: what the risk is and the specific code/config fix."""

    try:
        response = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Anthropic API error: {exc}")

    text = "".join(block.text for block in response.content if hasattr(block, "text"))
    return {"finding_id": finding_id, "analysis": text}
