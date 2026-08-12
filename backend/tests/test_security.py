import time

from app.core.security import (
    create_session_token,
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


def test_expired_session_token_rejected(monkeypatch):
    import app.core.security as security_module

    real_time = time.time
    monkeypatch.setattr(security_module.time, "time", lambda: real_time() - security_module.SESSION_TTL_SECONDS - 10)
    token = create_session_token(user_id=1)
    monkeypatch.setattr(security_module.time, "time", real_time)

    assert verify_session_token(token) is None
