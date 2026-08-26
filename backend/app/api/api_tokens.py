"""Issue #109: personal access token management for the public API
(`/api/public/v1/*`, see app/api/public_api.py). Session-authenticated
(current_user) -- this is the "manage my own tokens" surface used by the
Settings -> Workspace page, not the public API itself.
"""
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.auth import current_user
from app.api.deps import get_session
from app.core.security import generate_api_token
from app.core.time import utcnow
from app.models.models import ApiToken, ApiTokenScope, User

router = APIRouter(prefix="/api/api-tokens", tags=["api-tokens"])


class CreateApiTokenRequest(BaseModel):
    name: str
    scope: ApiTokenScope = ApiTokenScope.READ


def _token_out(token: ApiToken) -> dict:
    return {
        "id": token.id,
        "name": token.name,
        "token_prefix": token.token_prefix,
        "scope": token.scope,
        "created_at": token.created_at,
        "last_used_at": token.last_used_at,
        "revoked_at": token.revoked_at,
    }


@router.get("")
def list_api_tokens(session: Session = Depends(get_session), user: User = Depends(current_user)):
    """A user's own tokens only -- these are personal credentials, not
    workspace-shared like `Workspace.api_key`, so there's no admin-bypass
    "see everyone's tokens" here even for admins."""
    tokens = session.exec(select(ApiToken).where(ApiToken.user_id == user.id)).all()
    return [_token_out(t) for t in tokens]


@router.post("")
def create_api_token(
    payload: CreateApiTokenRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    if not payload.name.strip():
        raise HTTPException(status_code=400, detail="name is required")

    plaintext, token_hash, token_prefix = generate_api_token()
    token = ApiToken(
        user_id=user.id,
        name=payload.name.strip(),
        token_hash=token_hash,
        token_prefix=token_prefix,
        scope=payload.scope,
    )
    session.add(token)
    session.commit()
    session.refresh(token)

    # The only point in this token's lifetime the plaintext value exists
    # anywhere but the caller's own clipboard -- never returned again, same
    # "shown once at creation" pattern as the GitHub App manifest flow's
    # generated secrets.
    return {**_token_out(token), "token": plaintext}


@router.post("/{token_id}/revoke")
def revoke_api_token(token_id: int, session: Session = Depends(get_session), user: User = Depends(current_user)):
    token = session.get(ApiToken, token_id)
    if not token or token.user_id != user.id:
        raise HTTPException(status_code=404, detail="token not found")
    if token.revoked_at is None:
        token.revoked_at = utcnow()
        session.add(token)
        session.commit()
        session.refresh(token)
    return _token_out(token)
