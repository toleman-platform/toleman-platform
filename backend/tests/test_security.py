import time

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from app.core.security import (
    create_session_token,
    decode_session_token,
    hash_password,
    verify_password,
    verify_session_token,
)


def test_password_hash_roundtrip():
    hashed = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", hashed)


def test_wrong_password_rejected():
    hashed = hash_password("correct horse battery staple")
    assert not verify_password("wrong password", hashed)


def test_hash_is_salted_differently_each_time():
    a = hash_password("same password")
    b = hash_password("same password")
    assert a != b
    assert verify_password("same password", a)
    assert verify_password("same password", b)


def test_malformed_stored_hash_rejected_not_crashed():
    assert not verify_password("anything", "not-a-valid-hash-format")


def test_session_token_roundtrip():
    token = create_session_token(user_id=42)
    assert verify_session_token(token) == 42


def test_session_token_tampered_signature_rejected():
    token = create_session_token(user_id=42)
    payload, sig = token.rsplit(".", 1)
    tampered = f"{payload}.{'0' * len(sig)}"
    assert verify_session_token(tampered) is None


def test_session_token_malformed_rejected():
    assert verify_session_token("garbage") is None
    assert verify_session_token("") is None


def test_token_rejected_outside_local_dev_when_secret_is_still_default(monkeypatch):
    """Defense in depth for issue #55: app.main's startup check already
    refuses to boot a non-local deployment with the default session_secret,
    but if that check were ever bypassed, decode_session_token must still
    never honor a token signed with the known-default secret outside local
    dev."""
    import app.core.security as security_module
    from app.core.config import DEFAULT_SESSION_SECRET, settings

    token = create_session_token(user_id=1)  # signed under the real test secret

    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "session_secret", DEFAULT_SESSION_SECRET)
    try:
        assert security_module.decode_session_token(token) is None
    finally:
        pass  # monkeypatch auto-reverts


def test_expired_session_token_rejected(monkeypatch):
    import app.core.security as security_module

    real_time = time.time
    monkeypatch.setattr(security_module.time, "time", lambda: real_time() - security_module.SESSION_TTL_SECONDS - 10)
    token = create_session_token(user_id=1)
    monkeypatch.setattr(security_module.time, "time", real_time)

    assert verify_session_token(token) is None


def test_create_session_token_defaults_to_token_version_one():
    token = create_session_token(user_id=7)
    payload = decode_session_token(token)
    assert payload["uid"] == 7
    assert payload["tv"] == 1


def test_session_token_embeds_given_token_version():
    token = create_session_token(user_id=7, token_version=3)
    payload = decode_session_token(token)
    assert payload["uid"] == 7
    assert payload["tv"] == 3


def test_token_rejected_after_logout_bumps_token_version():
    """Simulates the revocation flow used by app.api.auth.current_user:
    a token issued before "logout" carries the token_version that was
    current at issuance; after logout bumps the user's DB token_version,
    the embedded version no longer matches and the caller must reject it.
    """
    user_token_version = 1

    # Token issued while logged in (pre-logout).
    token = create_session_token(user_id=99, token_version=user_token_version)
    payload = decode_session_token(token)
    assert payload is not None
    assert payload["tv"] == user_token_version  # still valid: versions match

    # Logout bumps the DB-stored token_version, invalidating all
    # previously-issued tokens for this user.
    user_token_version += 1

    payload = decode_session_token(token)
    assert payload is not None  # signature/expiry still valid...
    assert payload["tv"] != user_token_version  # ...but version mismatches, so a caller must reject it

    # A freshly issued token, created with the new version, still works.
    fresh_token = create_session_token(user_id=99, token_version=user_token_version)
    fresh_payload = decode_session_token(fresh_token)
    assert fresh_payload is not None
    assert fresh_payload["tv"] == user_token_version


@pytest.fixture()
def logout_test_user():
    """End-to-end fixture against the real app + DB for the /logout revocation tests below."""
    from app.core.db import engine, init_db
    from app.models.models import User

    init_db()
    email = "session-hardening-test-user@example.test"
    password = "correct horse battery staple"
    with Session(engine) as session:
        existing = session.exec(select(User).where(User.email == email)).first()
        if existing:
            session.delete(existing)
            session.commit()
        user = User(email=email, name="Test User", password_hash=hash_password(password))
        session.add(user)
        session.commit()
        session.refresh(user)
        user_id = user.id

    yield email, password

    with Session(engine) as session:
        user = session.get(User, user_id)
        if user:
            session.delete(user)
            session.commit()


def test_token_issued_before_logout_is_rejected_after_logout(logout_test_user):
    from app.main import app

    email, password = logout_test_user
    client = TestClient(app)

    login_resp = client.post("/api/auth/login", json={"email": email, "password": password})
    assert login_resp.status_code == 200
    old_cookie = login_resp.cookies.get("rikugan_session")
    assert old_cookie

    # The token works before logout.
    me_resp = client.get("/api/auth/me", cookies={"rikugan_session": old_cookie})
    assert me_resp.status_code == 200

    # Logging out bumps the user's token_version server-side.
    logout_resp = client.post("/api/auth/logout", cookies={"rikugan_session": old_cookie})
    assert logout_resp.status_code == 200

    # The pre-logout token is now rejected, even though its signature and
    # expiry are still valid, because its embedded token_version no longer
    # matches the (bumped) DB value.
    stale_resp = client.get("/api/auth/me", cookies={"rikugan_session": old_cookie})
    assert stale_resp.status_code == 401


def test_fresh_login_after_logout_still_works(logout_test_user):
    from app.main import app

    email, password = logout_test_user
    client = TestClient(app)

    first_login = client.post("/api/auth/login", json={"email": email, "password": password})
    old_cookie = first_login.cookies.get("rikugan_session")
    client.post("/api/auth/logout", cookies={"rikugan_session": old_cookie})

    # A brand new login issues a token stamped with the post-logout version.
    second_login = client.post("/api/auth/login", json={"email": email, "password": password})
    assert second_login.status_code == 200
    new_cookie = second_login.cookies.get("rikugan_session")
    assert new_cookie

    me_resp = client.get("/api/auth/me", cookies={"rikugan_session": new_cookie})
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == email
