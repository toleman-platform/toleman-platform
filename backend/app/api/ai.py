import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session

from app.api.config import get_platform_config
from app.api.deps import get_session
from app.core.config import settings
from app.core.crypto import decrypt_secret
from app.models.models import Finding, PlatformConfig

router = APIRouter(prefix="/api/ai", tags=["ai"])

# Real network timeout for self-hosted/local model backends -- local inference
# (especially CPU-only Ollama) can be much slower than a hosted API, so this is
# generous rather than the usual short API timeout.
OPENAI_COMPATIBLE_TIMEOUT_SECONDS = 60.0


def _resolve_anthropic_key(session: Session) -> str:
    config = get_platform_config(session)
    if config and config.anthropic_api_key:
        return config.anthropic_api_key
    return settings.anthropic_api_key


def _resolve_provider(session: Session) -> str:
    config = get_platform_config(session)
    provider = config.ai_provider if config else None
    return provider or "anthropic"


def _openai_compatible_configured(config: PlatformConfig | None) -> bool:
    return bool(config and config.openai_compatible_base_url and config.openai_compatible_model)


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
    api_key = _resolve_anthropic_key(session)
    if not api_key:
        raise HTTPException(status_code=400, detail="Anthropic API key not configured")

    import anthropic

    client = anthropic.Anthropic(api_key=api_key)
    try:
        response = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=400,
            messages=[{"role": "user", "content": _build_prompt(finding)}],
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Anthropic API error: {exc}")

    return "".join(block.text for block in response.content if hasattr(block, "text"))


def _analyze_with_openai_compatible(config: PlatformConfig, finding: Finding) -> str:
    if not _openai_compatible_configured(config):
        raise HTTPException(
            status_code=400,
            detail="OpenAI-compatible endpoint not configured (base URL and model are required)",
        )

    base_url = config.openai_compatible_base_url.rstrip("/")
    url = f"{base_url}/chat/completions"

    headers = {}
    if config.openai_compatible_api_key:
        # Self-hosted backends (Ollama, LM Studio) typically need no key at
        # all, so the header is only sent when one is actually configured.
        headers["Authorization"] = f"Bearer {decrypt_secret(config.openai_compatible_api_key)}"

    body = {
        "model": config.openai_compatible_model,
        "messages": [{"role": "user", "content": _build_prompt(finding)}],
    }

    try:
        response = httpx.post(url, json=body, headers=headers, timeout=OPENAI_COMPATIBLE_TIMEOUT_SECONDS)
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"OpenAI-compatible endpoint error ({exc.response.status_code}): {exc.response.text}",
        )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"OpenAI-compatible endpoint request failed: {exc}")

    try:
        data = response.json()
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, ValueError) as exc:
        raise HTTPException(
            status_code=502,
            detail=f"OpenAI-compatible endpoint returned an unexpected response shape: {exc}",
        )


@router.get("/status")
def status(session: Session = Depends(get_session)):
    provider = _resolve_provider(session)
    if provider == "openai_compatible":
        config = get_platform_config(session)
        configured = _openai_compatible_configured(config)
    else:
        configured = bool(_resolve_anthropic_key(session))
    return {"configured": configured, "provider": provider}


@router.post("/analyze/{finding_id}")
def analyze_finding(finding_id: int, session: Session = Depends(get_session)):
    """Real remediation suggestion via the configured AI provider (Admin >
    Global Integrations): Anthropic's Claude API, or any OpenAI-compatible
    chat completions endpoint (Kimi/Moonshot, Ollama, vLLM, LM Studio, ...).
    Returns the same {finding_id, analysis} shape regardless of provider. If
    no provider is configured, returns 400 rather than a fabricated answer."""
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")

    provider = _resolve_provider(session)
    if provider == "openai_compatible":
        config = get_platform_config(session)
        text = _analyze_with_openai_compatible(config, finding)
    else:
        text = _analyze_with_anthropic(session, finding)

    return {"finding_id": finding_id, "analysis": text}
