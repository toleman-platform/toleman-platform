import base64
import hashlib
import hmac
import json
import os
import secrets
import time

from app.core.config import DEFAULT_SESSION_SECRET, settings

SESSION_TTL_SECONDS = 60 * 60 * 24 * 7  # 7 days

API_TOKEN_PREFIX = "toleman_pat_"


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return f"{salt.hex()}${derived.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, _ = stored.split("$")
    except ValueError:
        return False
    salt = bytes.fromhex(salt_hex)
    return hmac.compare_digest(hash_password(password, salt), stored)


def _sign(payload: str) -> str:
    return hmac.new(settings.session_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def create_session_token(user_id: int, token_version: int = 1) -> str:
    payload = json.dumps(
        {"uid": user_id, "tv": token_version, "exp": int(time.time()) + SESSION_TTL_SECONDS}
    )
    payload_b64 = base64.urlsafe_b64encode(payload.encode()).decode()
    signature = _sign(payload_b64)
    return f"{payload_b64}.{signature}"


def decode_session_token(token: str) -> dict | None:
    """Verify signature/expiry and return the full payload (uid, tv, exp), or None if invalid."""
    # Defense in depth: app.main's startup check already refuses to boot a
    # non-local deployment with the default SESSION_SECRET, but if that check
    # is ever bypassed (e.g. hot env var edit after startup), never honor a
    # session signed with the known-default secret outside local dev.
    if settings.environment != "local" and settings.session_secret == DEFAULT_SESSION_SECRET:
        return None
    try:
        payload_b64, signature = token.split(".")
    except ValueError:
        return None
    if not hmac.compare_digest(_sign(payload_b64), signature):
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode()))
    except Exception:
        return None
    if payload.get("exp", 0) < time.time():
        return None
    if payload.get("uid") is None:
        return None
    # Tokens issued before token_version existed are treated as version 1.
    payload.setdefault("tv", 1)
    return payload


def verify_session_token(token: str) -> int | None:
    payload = decode_session_token(token)
    return payload["uid"] if payload else None


def generate_api_token() -> tuple[str, str, str]:
    """Issue #109: mint a new public-API personal access token. Returns
    (plaintext, token_hash, token_prefix) -- the caller persists only
    token_hash/token_prefix and returns plaintext to the client exactly
    once; it can never be re-derived from what's stored.

    sha256 (not pbkdf2_hmac like hash_password) on purpose: this token is
    32 bytes of os.urandom-backed entropy via secrets.token_urlsafe, not a
    human-chosen password, so a slow hash defends against nothing here and
    would make every public-API request pay a 200k-iteration cost for no
    security benefit.
    """
    plaintext = API_TOKEN_PREFIX + secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(plaintext.encode()).hexdigest()
    token_prefix = plaintext[: len(API_TOKEN_PREFIX) + 8]
    return plaintext, token_hash, token_prefix


def hash_api_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode()).hexdigest()
