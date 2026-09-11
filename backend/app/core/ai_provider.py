"""Shared AI-provider dispatch: Anthropic's API, or any OpenAI-compatible
chat completions endpoint (Kimi/Moonshot, Ollama, vLLM, LM Studio, ...).

Extracted out of app/api/ai.py so app.core.autofix (a core module, no
FastAPI/API-layer dependency) can generate text via the same
Admin > Global Integrations provider config without importing an api module.
app/api/ai.py's /api/ai/analyze/{finding_id} endpoint is a thin wrapper
around generate_text() below, prompt-building and response shape.
"""
import httpx
from fastapi import HTTPException
from sqlmodel import Session

from app.api.config import get_platform_config
from app.core.config import settings
from app.core.crypto import decrypt_secret
from app.models.models import PlatformConfig

# Real network timeout for self-hosted/local model backends; local inference
# (especially CPU-only Ollama) can be much slower than a hosted API, so this is
# generous rather than the usual short API timeout.
OPENAI_COMPATIBLE_TIMEOUT_SECONDS = 60.0


def resolve_anthropic_key(session: Session) -> str:
    config = get_platform_config(session)
    if config and config.anthropic_api_key:
        return config.anthropic_api_key
    return settings.anthropic_api_key


def resolve_provider(session: Session) -> str:
    config = get_platform_config(session)
    provider = config.ai_provider if config else None
    return provider or "anthropic"


def openai_compatible_configured(config: PlatformConfig | None) -> bool:
    return bool(config and config.openai_compatible_base_url and config.openai_compatible_model)


def ai_configured(session: Session) -> bool:
    """Whether *any* AI provider is usable right now, without making a call."""
    provider = resolve_provider(session)
    if provider == "openai_compatible":
        return openai_compatible_configured(get_platform_config(session))
    return bool(resolve_anthropic_key(session))


def call_anthropic(session: Session, prompt: str, max_tokens: int = 400) -> str:
    api_key = resolve_anthropic_key(session)
    if not api_key:
        raise HTTPException(status_code=400, detail="Anthropic API key not configured")

    import anthropic

    client = anthropic.Anthropic(api_key=api_key)
    try:
        response = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Anthropic API error: {exc}")

    return "".join(block.text for block in response.content if hasattr(block, "text"))


def call_openai_compatible(config: PlatformConfig, prompt: str) -> str:
    if not openai_compatible_configured(config):
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
        "messages": [{"role": "user", "content": prompt}],
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


def generate_text(session: Session, prompt: str, max_tokens: int = 400) -> str:
    """Dispatch `prompt` to whichever provider is configured (Admin > Global
    Integrations). Raises HTTPException(400) if none is configured,
    HTTPException(502) on an upstream failure -- never fabricates a result."""
    provider = resolve_provider(session)
    if provider == "openai_compatible":
        return call_openai_compatible(get_platform_config(session), prompt)
    return call_anthropic(session, prompt, max_tokens=max_tokens)
