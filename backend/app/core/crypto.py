"""Symmetric encryption helper for secrets-at-rest (GitHub App private key,
client secret, webhook secret in ``GitHubAppConfig``).

Uses Fernet (AES-128-CBC + HMAC-SHA256, from the `cryptography` package,
already a transitive dependency via PyJWT[crypto]).
"""

import logging
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings

logger = logging.getLogger(__name__)


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
        raise ValueError(
            "Failed to decrypt secret - PLATFORM_ENCRYPTION_KEY is missing, wrong, "
            "or was rotated since this value was encrypted."
        ) from exc
