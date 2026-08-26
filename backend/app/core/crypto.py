"""Symmetric encryption helper for secrets-at-rest (GitHub App private key,
client secret, webhook secret in ``GitHubAppConfig``).

Uses Fernet (AES-128-CBC + HMAC-SHA256, from the `cryptography` package,
already a transitive dependency via PyJWT[crypto]).

``check_encryption_key_health``/``reseed_encryption_key_canary`` below exist
because of a real, twice-recurring incident: any deployment where the
configured PLATFORM_ENCRYPTION_KEY diverges from whatever key originally
encrypted a stored secret (a container recreated against a different
``.env``, a lost/rotated key, a fresh clone on another machine) doesn't fail
at the point of divergence -- it fails silently, later, the first time
*anything* touches an encrypted secret. In practice that has meant a
Mass Rollout batch item dying with a raw ``cryptography.fernet.InvalidToken``
traceback three stack frames deep in a Celery worker log, which is not an
actionable signal for whoever is looking at it. The canary check below
catches the divergence at startup instead, before any feature has a chance
to surface it as a confusing per-item failure.
"""

import logging
from datetime import datetime
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken
from sqlmodel import Session, select

from app.core.config import settings

logger = logging.getLogger(__name__)

# Arbitrary fixed plaintext -- its content doesn't matter, only that the same
# constant is used to seed the canary and to verify it later.
_CANARY_PLAINTEXT = "toleman-encryption-key-canary-v1"

# Pre-rename value of _CANARY_PLAINTEXT. Any database seeded before the
# Rikugan -> Toleman rename holds a canary row encrypting *this* string, so
# verification has to accept it too. Without this, the rename alone -- with
# the encryption key completely unchanged -- would make every existing
# deployment fail its boot-time key-health check and log the CRITICAL
# "PLATFORM_ENCRYPTION_KEY MISMATCH" alert, sending operators to reconnect
# integrations that were never broken. Seeding always uses the current
# constant, so this is only ever read, never written.
_LEGACY_CANARY_PLAINTEXTS = ("rikugan-encryption-key-canary-v1",)


class SecretDecryptionError(ValueError):
    """Raised by ``decrypt_secret`` when the configured encryption key cannot
    decrypt a stored value. A ``ValueError`` subclass (not a new exception
    hierarchy) so every existing ``except ValueError`` call site keeps working
    unchanged; callers that want to react specifically to a key mismatch --
    rather than lump it in with generic validation errors -- can now catch
    this type by name instead of string-matching the message."""


@lru_cache(maxsize=1)
def _get_fernet() -> Fernet:
    key = settings.platform_encryption_key
    if not key:
        # No key configured (dev/OSS default). Generate an ephemeral in-memory
        # key so the app still boots rather than crashing on startup.
        #
        # IMPORTANT: production deployments MUST set PLATFORM_ENCRYPTION_KEY
        # explicitly (a urlsafe-base64, 32-byte Fernet key - generate with
        # `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`).
        # Without it, every process restart mints a new key and permanently
        # invalidates every previously-encrypted row (GitHub App private key,
        # client secret, webhook secret), and a multi-worker deployment would
        # have each worker generate a *different* key, so secrets encrypted by
        # one worker couldn't be decrypted by another.
        key = Fernet.generate_key().decode()
        logger.warning(
            "PLATFORM_ENCRYPTION_KEY is not set - generated an ephemeral encryption "
            "key for this process. Set PLATFORM_ENCRYPTION_KEY in the environment for "
            "any deployment that must survive a restart or run multiple workers, "
            "otherwise previously-encrypted secrets become undecryptable."
        )
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a secret string for storage. Falsy input is passed through
    unchanged (nothing sensitive to protect, e.g. an unset webhook secret)."""
    if not plaintext:
        return plaintext
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a secret previously produced by ``encrypt_secret``. Falsy input
    is passed through unchanged."""
    if not ciphertext:
        return ciphertext
    try:
        return _get_fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise SecretDecryptionError(
            "Failed to decrypt secret - PLATFORM_ENCRYPTION_KEY is missing, wrong, "
            "or was rotated since this value was encrypted."
        ) from exc


def check_encryption_key_health(session: Session) -> bool:
    """Proactive health check, meant to be called once at startup (and
    exposed via GET /api/config for an admin-visible banner) rather than
    waiting to discover a key mismatch as a random feature's decrypt failure.

    Looks up the single ``EncryptionKeyCanary`` row:
    - No row yet (fresh install, nothing has ever been encrypted): seed one
      under the current key and report healthy. There is nothing to have
      diverged from yet.
    - Row exists: try to decrypt it with the *current* key and confirm it
      round-trips to the expected plaintext. Success means the running key
      is the same one every other encrypted secret in this database was
      written under. Failure means it changed since -- every encrypted
      secret (GitHub App credentials, Slack/Jira/SIEM webhooks, the AI
      key) is now undecryptable, since Fernet has no recovery path for a
      lost key.

    Deliberately never auto-repairs a mismatch by reseeding -- that would
    just hide the same failure one layer later. See
    ``reseed_encryption_key_canary`` for the explicit, admin-triggered reset.
    """
    from app.models.models import EncryptionKeyCanary  # local import: avoid a
    # crypto.py <-> models.py import cycle at module load time.

    canary = session.exec(select(EncryptionKeyCanary)).first()
    if canary is None:
        session.add(EncryptionKeyCanary(ciphertext=encrypt_secret(_CANARY_PLAINTEXT)))
        session.commit()
        return True

    try:
        plaintext = decrypt_secret(canary.ciphertext)
    except SecretDecryptionError:
        return False
    return plaintext == _CANARY_PLAINTEXT or plaintext in _LEGACY_CANARY_PLAINTEXTS


def reseed_encryption_key_canary(session: Session) -> None:
    """Re-seed the canary under the *current* key, marking it as the new
    source of truth. Only ever called from the explicit, admin-triggered
    "I've reconnected everything" action (POST /api/config/encryption-key/reseed)
    -- deliberately not automatic, since resetting the canary before every
    affected integration has actually been reconnected would just make the
    health check lie about integrations that are still broken."""
    from app.models.models import EncryptionKeyCanary

    canary = session.exec(select(EncryptionKeyCanary)).first()
    ciphertext = encrypt_secret(_CANARY_PLAINTEXT)
    if canary is None:
        session.add(EncryptionKeyCanary(ciphertext=ciphertext))
    else:
        canary.ciphertext = ciphertext
        canary.updated_at = datetime.utcnow()
        session.add(canary)
    session.commit()
