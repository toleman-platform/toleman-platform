from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.deps import get_session
from app.core.crypto import encrypt_secret
from app.models.models import PlatformConfig

router = APIRouter(prefix="/api/config", tags=["config"])

VALID_AI_PROVIDERS = {"anthropic", "openai_compatible"}


class UpdateConfigRequest(BaseModel):
    # All fields are optional so a save only needs to send what changed (e.g.
    # switching provider without re-entering the other provider's key).
    # None = leave unchanged; "" clears the field.
    ai_provider: str | None = None
    anthropic_api_key: str | None = None
    openai_compatible_base_url: str | None = None
    openai_compatible_api_key: str | None = None
    openai_compatible_model: str | None = None


def get_platform_config(session: Session) -> PlatformConfig | None:
    return session.exec(select(PlatformConfig)).first()


def _serialize(config: PlatformConfig | None) -> dict:
    return {
        # Never echo back the raw keys - report only whether one is set, same
        # pattern used for GitHub App secrets.
        "anthropic_api_key_set": bool(config and config.anthropic_api_key),
        "ai_provider": (config.ai_provider if config else None) or "anthropic",
        "openai_compatible_base_url": (config.openai_compatible_base_url if config else "") or "",
        "openai_compatible_api_key_set": bool(config and config.openai_compatible_api_key),
        "openai_compatible_model": (config.openai_compatible_model if config else "") or "",
    }


@router.get("")
def get_config(session: Session = Depends(get_session)):
    config = get_platform_config(session)
    return _serialize(config)


@router.post("")
def update_config(payload: UpdateConfigRequest, session: Session = Depends(get_session)):
    config = get_platform_config(session)
    if not config:
        config = PlatformConfig()

    if payload.ai_provider is not None:
        if payload.ai_provider not in VALID_AI_PROVIDERS:
            raise HTTPException(status_code=400, detail=f"ai_provider must be one of {sorted(VALID_AI_PROVIDERS)}")
        config.ai_provider = payload.ai_provider
    if payload.anthropic_api_key is not None:
        config.anthropic_api_key = payload.anthropic_api_key
    if payload.openai_compatible_base_url is not None:
        config.openai_compatible_base_url = payload.openai_compatible_base_url.rstrip("/")
    if payload.openai_compatible_api_key is not None:
        config.openai_compatible_api_key = encrypt_secret(payload.openai_compatible_api_key)
    if payload.openai_compatible_model is not None:
        config.openai_compatible_model = payload.openai_compatible_model

    session.add(config)
    session.commit()
    session.refresh(config)
    return _serialize(config)
