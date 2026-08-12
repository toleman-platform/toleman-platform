from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.deps import get_session
from app.models.models import PlatformConfig

router = APIRouter(prefix="/api/config", tags=["config"])


class UpdateConfigRequest(BaseModel):
    anthropic_api_key: str


def get_platform_config(session: Session) -> PlatformConfig | None:
    return session.exec(select(PlatformConfig)).first()


@router.get("")
def get_config(session: Session = Depends(get_session)):
    config = get_platform_config(session)
    return {"anthropic_api_key_set": bool(config and config.anthropic_api_key)}


@router.post("")
def update_config(payload: UpdateConfigRequest, session: Session = Depends(get_session)):
    config = get_platform_config(session)
    if not config:
        config = PlatformConfig()
    config.anthropic_api_key = payload.anthropic_api_key
    session.add(config)
    session.commit()
    return {"anthropic_api_key_set": True}
