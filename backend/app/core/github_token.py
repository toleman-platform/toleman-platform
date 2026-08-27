"""Per-workspace GitHub token storage and resolution (issue #227).

Replaces the previous env-only ``GITHUB_TOKEN`` pickup (app.core.github.
get_github_token, now removed) with a DB-stored, Fernet-encrypted, TTL'd
per-workspace PAT. A token is:

  * encrypted at rest (app.core.crypto.encrypt_secret); the plaintext is
    never persisted and never logged;
  * never echoed back to the client (the API returns only ``token_set`` /
    ``expires_at`` / ``created_at``);
  * lazily purged: the first read *after* ``expires_at`` hard-deletes the
    row and returns None, so an expired token can never be used. Matches the
    project's no-Celery-beat design (app/core/staleness.py, #153).

``resolve_github_token`` is the single credential-resolution entry point used
by every GitHub call site: it prefers the workspace's stored PAT, then falls
back to a GitHub App installation token for the repo (short-lived, minted on
demand) when the workspace has a matching installation. Security note: none
of these functions ever log the token value, only workspace_id / slug /
status context.
"""

import logging
from datetime import datetime

from sqlmodel import Session, select

from app.core.crypto import decrypt_secret, encrypt_secret
from app.core.github_app import (
    get_installation_token,
    resolve_config_for_installation,
    resolve_installation_for_repo,
)
from app.models.models import GitHubToken

logger = logging.getLogger(__name__)


def _resolve_workspace_token(session: Session, workspace_id: int) -> str | None:
    """Decrypt and return the workspace's stored PAT, lazily purging it if it
    has expired. Returns None when no token is stored, when it expired (and
    was just deleted), or when it can't be decrypted (rotated/missing
    PLATFORM_ENCRYPTION_KEY). Never logs the token value."""
    row = session.exec(
        select(GitHubToken).where(GitHubToken.workspace_id == workspace_id)
    ).first()
    if not row:
        return None

    if row.expires_at is not None and row.expires_at <= datetime.utcnow():
        session.delete(row)
        session.commit()
        # workspace_id only, never the token value.
        logger.info("Purged expired GitHub token for workspace %s", workspace_id)  # nosemgrep: python.lang.security.audit.logging.python-logger-credential-disclosure
        return None

    try:
        return decrypt_secret(row.token_ciphertext)
    except ValueError:
        # workspace_id only, never the ciphertext or a decrypted value.
        logger.error(  # nosemgrep: python.lang.security.audit.logging.python-logger-credential-disclosure
            "Failed to decrypt GitHub token for workspace %s - "
            "PLATFORM_ENCRYPTION_KEY is missing or was rotated",
            workspace_id,
        )
        return None


def _resolve_installation_token(session: Session, workspace_id: int, slug: str) -> str | None:
    """Mint a GitHub App installation token for ``slug`` when the workspace
    has a matching installation. Returns None (with a warning) when no
    installation/config exists or minting fails. Never logs the token."""
    installation = resolve_installation_for_repo(session, workspace_id, slug)
    if not installation:
        return None
    config = resolve_config_for_installation(session, installation)
    if not config:
        logger.warning("No GitHub App config for %s", slug)
        return None
    try:
        return get_installation_token(config, installation.installation_id)
    except Exception as exc:
        # repo slug and exception message only; get_installation_token never
        # raises with the minted token embedded in its exception text.
        logger.warning("Failed to mint installation token for %s: %s", slug, exc)  # nosemgrep: python.lang.security.audit.logging.python-logger-credential-disclosure
        return None


def resolve_github_token(session: Session, workspace_id: int, slug: str | None = None) -> str | None:
    """Resolve the best available GitHub credential for a workspace.

    Precedence: the workspace's stored PAT (explicit user configuration),
    then a GitHub App installation token for ``slug`` when one is given. Pass
    ``slug`` for repo-scoped operations (clone, dependency-graph SBOM); omit
    it for workspace-wide operations. Returns None when neither is available;
    callers should fail soft (clone anonymously, skip the enhancement) or
    surface a clear 502/403 rather than inventing a token.
    """
    token = _resolve_workspace_token(session, workspace_id)
    if token:
        return token
    if slug:
        return _resolve_installation_token(session, workspace_id, slug)
    return None


def upsert_github_token(
    session: Session,
    workspace_id: int,
    plaintext: str,
    expires_at: datetime | None,
    created_by: int | None = None,
) -> GitHubToken:
    """Encrypt and store (or replace) the workspace's GitHub PAT. The plaintext
    is passed straight to encrypt_secret and never logged or returned."""
    ciphertext = encrypt_secret(plaintext)
    row = session.exec(
        select(GitHubToken).where(GitHubToken.workspace_id == workspace_id)
    ).first()
    if row:
        row.token_ciphertext = ciphertext
        row.expires_at = expires_at
        row.created_by = created_by
        row.created_at = datetime.utcnow()
    else:
        row = GitHubToken(
            workspace_id=workspace_id,
            token_ciphertext=ciphertext,
            created_by=created_by,
            expires_at=expires_at,
        )
        session.add(row)
    session.commit()
    session.refresh(row)
    return row


def delete_github_token(session: Session, workspace_id: int) -> bool:
    """Remove the workspace's stored token (if any). Returns True if a row was
    deleted."""
    row = session.exec(
        select(GitHubToken).where(GitHubToken.workspace_id == workspace_id)
    ).first()
    if not row:
        return False
    session.delete(row)
    session.commit()
    return True


def purge_expired_tokens(session: Session) -> int:
    """Delete every expired token row regardless of whether it's been read.
    Invoked opportunistically (e.g. on the status GET); the lazy read-path
    purge in _resolve_workspace_token remains the primary mechanism."""
    now = datetime.utcnow()
    expired = session.exec(
        select(GitHubToken).where(GitHubToken.expires_at.is_not(None), GitHubToken.expires_at <= now)
    ).all()
    for row in expired:
        session.delete(row)
    if expired:
        session.commit()
    return len(expired)
