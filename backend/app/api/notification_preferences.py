from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.auth import current_user
from app.api.deps import get_session
from app.models.models import NotificationChannel, NotificationEventType, NotificationPreference, User

router = APIRouter(prefix="/api/notification-preferences", tags=["notification-preferences"])


class PreferenceOut(BaseModel):
    channel: NotificationChannel
    event_type: NotificationEventType
    enabled: bool


class SetPreferencesRequest(BaseModel):
    preferences: list[PreferenceOut]


@router.get("", response_model=list[PreferenceOut])
def list_preferences(user: User = Depends(current_user), session: Session = Depends(get_session)):
    rows = session.exec(select(NotificationPreference).where(NotificationPreference.user_id == user.id)).all()
    return [PreferenceOut(channel=r.channel, event_type=r.event_type, enabled=r.enabled) for r in rows]


@router.put("", response_model=list[PreferenceOut])
def set_preferences(
    payload: SetPreferencesRequest,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
):
    """Idempotent upsert per (channel, event_type), relying on
    NotificationPreference's unique constraint. Absence of a row in the
    payload for a given (channel, event_type) leaves any existing row
    untouched; this endpoint only touches pairs the client actually sent,
    it doesn't reset everything else to disabled."""
    existing = {
        (r.channel, r.event_type): r
        for r in session.exec(select(NotificationPreference).where(NotificationPreference.user_id == user.id)).all()
    }
    for pref in payload.preferences:
        key = (pref.channel, pref.event_type)
        row = existing.get(key)
        if row:
            row.enabled = pref.enabled
        else:
            row = NotificationPreference(
                user_id=user.id, channel=pref.channel, event_type=pref.event_type, enabled=pref.enabled
            )
        session.add(row)
    session.commit()

    rows = session.exec(select(NotificationPreference).where(NotificationPreference.user_id == user.id)).all()
    return [PreferenceOut(channel=r.channel, event_type=r.event_type, enabled=r.enabled) for r in rows]
