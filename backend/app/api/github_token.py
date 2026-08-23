"""Per-workspace GitHub token management (issue #227).

Admin-only CRUD for the encrypted, TTL'd per-workspace GitHub PAT that
replaces the old env-only GITHUB_TOKEN pickup. The token is encrypted at rest
(app.core.crypto), never echoed back (this API returns only ``token_set`` /
``created_at`` / ``expires_at``), and lazily purged on read once it expires
(app.core.github_token.resolve_github_token).

Security: no endpoint ever logs the token value, its ciphertext, or the
Authorization header used by the test call -- only workspace_id and HTTP
status context.
"""

import logging
from datetime import UTC, datetime, timedelta

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.auth import current_user, require_admin
from app.api.deps import get_session
from app.core.github_token import (
    delete_github_token,
    purge_expired_tokens,
    resolve_github_token,
    upsert_github_token,
)
from app.models.models import GitHubToken, User, Workspace

router = APIRouter(prefix="/api/github-token", tags=["github-token"])

logger = logging.getLogger(__name__)


class SaveGithubTokenRequest(BaseModel):
    # The plaintext GitHub PAT. Rejected when empty/whitespace-only.
    token: str
    # TTL in hours from now; None = never expires.
    expires_in_hours: int | None = None
    # Optional workspace selector; defaults to the first workspace (the
    # single-workspace admin pattern used elsewhere, e.g. GitHub App setup).
    workspace_id: int | None = None


class TestGithubTokenRequest(BaseModel):
    # Optional override so "Test Connection" can verify a not-yet-saved token
    # typed into the form; falls back to the workspace's stored token.
    token: str | None = None
    workspace_id: int | None = None


def _resolve_workspace_id(session: Session, workspace_id: int | None) -> int:
    if workspace_id is not None:
        # Issue #226 review nit: a caller-supplied id that doesn't exist used
        # to sail through here unchecked -- a GET silently read back
        # "token_set: false" (indistinguishable from "no token saved yet"),
        # and a PUT surfaced as a bare 500 from the GitHubToken FK constraint
        # instead of a real 404.
        if not session.get(Workspace, workspace_id):
            raise HTTPException(status_code=404, detail=f"workspace {workspace_id} not found")
        return workspace_id
    workspace = session.exec(select(Workspace).order_by(Workspace.id)).first()
    if not workspace:
        raise HTTPException(status_code=400, detail="No workspace exists yet")
    return workspace.id


def _serialize(token_set: bool, created_at: datetime | None, expires_at: datetime | None) -> dict:
    return {
        "token_set": token_set,
        "created_at": created_at.isoformat() if created_at else None,
        "expires_at": expires_at.isoformat() if expires_at else None,
    }


@router.get("")
def get_github_token(
    workspace_id: int | None = None,
    session: Session = Depends(get_session),
    _: User = Depends(require_admin),
):
    purge_expired_tokens(session)
    wid = _resolve_workspace_id(session, workspace_id)
    row = session.exec(select(GitHubToken).where(GitHubToken.workspace_id == wid)).first()
    return _serialize(bool(row), row.created_at if row else None, row.expires_at if row else None)


@router.put("")
def save_github_token(
    payload: SaveGithubTokenRequest,
    session: Session = Depends(get_session),
    user: User = Depends(require_admin),
):
    token = payload.token.strip()
    if not token:
        raise HTTPException(status_code=400, detail="token must not be empty")

    expires_at = None
    if payload.expires_in_hours is not None:
        if payload.expires_in_hours < 1:
            raise HTTPException(status_code=400, detail="expires_in_hours must be at least 1")
        expires_at = datetime.now(UTC).replace(tzinfo=None) + timedelta(hours=payload.expires_in_hours)

    wid = _resolve_workspace_id(session, payload.workspace_id)
    row = upsert_github_token(session, wid, token, expires_at, created_by=user.id)
    return _serialize(True, row.created_at, row.expires_at)


@router.delete("")
def remove_github_token(
    workspace_id: int | None = None,
    session: Session = Depends(get_session),
    _: User = Depends(require_admin),
):
    wid = _resolve_workspace_id(session, workspace_id)
    deleted = delete_github_token(session, wid)
    return {"token_set": False, "deleted": deleted}


@router.post("/test")
def test_github_token(
    payload: TestGithubTokenRequest,
    session: Session = Depends(get_session),
    _: User = Depends(require_admin),
):
    """Real authenticated GET https://api.github.com/user with the supplied
    (or stored) token. Never fabricates success and never logs the token."""
    wid = _resolve_workspace_id(session, payload.workspace_id)
    token = (payload.token or "").strip() or resolve_github_token(session, wid)
    if not token:
        raise HTTPException(status_code=400, detail="No GitHub token configured or supplied")

    headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}"}
    try:
        res = httpx.get("https://api.github.com/user", headers=headers, timeout=15)
    except Exception:
        logger.warning("GitHub token test request failed (network) for workspace %s", wid)
        raise HTTPException(status_code=502, detail="Could not reach api.github.com")

    if res.status_code == 200:
        login = res.json().get("login", "unknown")
        return {"success": True, "message": f"Token is valid (authenticated as {login})."}
    if res.status_code in (401, 403):
        raise HTTPException(status_code=502, detail="GitHub token is invalid or lacks access")
    raise HTTPException(status_code=502, detail=f"GitHub returned HTTP {res.status_code}")
