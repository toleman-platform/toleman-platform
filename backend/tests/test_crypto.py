import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app.core.crypto import (
    SecretDecryptionError,
    check_encryption_key_health,
    decrypt_secret,
    encrypt_secret,
    reseed_encryption_key_canary,
)
from app.models.models import EncryptionKeyCanary  # noqa: F401, registers the table on SQLModel.metadata


@pytest.fixture()
def session():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    with Session(eng) as s:
        yield s


def test_encrypt_decrypt_roundtrip():
    # Not a real key: only the PEM header/footer shape, to exercise the
    # roundtrip on PEM-like content.
    plaintext = "-----BEGIN RSA PRIVATE KEY-----\nabc123\n-----END RSA PRIVATE KEY-----"  # gitleaks:allow
    ciphertext = encrypt_secret(plaintext)
    assert decrypt_secret(ciphertext) == plaintext


def test_ciphertext_is_not_plaintext():
    plaintext = "super-secret-client-secret"
    ciphertext = encrypt_secret(plaintext)
    assert ciphertext != plaintext
    assert plaintext not in ciphertext


def test_encrypting_same_value_twice_yields_different_ciphertext():
    # Fernet includes a random IV/nonce per encryption, so two encryptions of
    # the same plaintext must not be identical (defends against ciphertext
    # pattern-matching across rows).
    plaintext = "webhook-secret-value"
    assert encrypt_secret(plaintext) != encrypt_secret(plaintext)


def test_empty_string_passes_through_unchanged():
    assert encrypt_secret("") == ""
    assert decrypt_secret("") == ""


def test_decrypt_with_wrong_key_raises():
    import app.core.crypto as crypto_module
    from cryptography.fernet import Fernet

    ciphertext = encrypt_secret("some-secret")

    # Simulate a differently-keyed process (e.g. key rotated, or a restart
    # with no PLATFORM_ENCRYPTION_KEY set) by swapping the cached Fernet.
    original_fernet = crypto_module._get_fernet
    crypto_module._get_fernet.cache_clear()
    other_key = Fernet.generate_key()
    crypto_module._get_fernet = lambda: Fernet(other_key)
    try:
        try:
            decrypt_secret(ciphertext)
            assert False, "expected decrypt_secret to raise ValueError"
        except ValueError as exc:
            # SecretDecryptionError is a ValueError subclass; every existing
            # `except ValueError` call site keeps working unchanged, but
            # callers that want to react specifically to a key mismatch can
            # now catch SecretDecryptionError by name.
            assert isinstance(exc, SecretDecryptionError)
    finally:
        crypto_module._get_fernet = original_fernet
        crypto_module._get_fernet.cache_clear()


def _swap_fernet_key(crypto_module):
    from cryptography.fernet import Fernet

    crypto_module._get_fernet.cache_clear()
    other_key = Fernet.generate_key()
    crypto_module._get_fernet = lambda: Fernet(other_key)


def test_check_encryption_key_health_seeds_canary_on_fresh_db(session):
    # No canary row yet: nothing has diverged from, so this must report
    # healthy and leave a canary behind for future checks.
    assert check_encryption_key_health(session) is True
    assert session.exec(select_canary()).first() is not None


def test_check_encryption_key_health_true_when_key_unchanged(session):
    assert check_encryption_key_health(session) is True  # seeds
    assert check_encryption_key_health(session) is True  # re-verifies


def test_check_encryption_key_health_false_after_key_swap(session):
    import app.core.crypto as crypto_module

    assert check_encryption_key_health(session) is True  # seeds under key A

    original_fernet = crypto_module._get_fernet
    _swap_fernet_key(crypto_module)
    try:
        assert check_encryption_key_health(session) is False
    finally:
        crypto_module._get_fernet = original_fernet
        crypto_module._get_fernet.cache_clear()


def test_reseed_encryption_key_canary_restores_health(session):
    import app.core.crypto as crypto_module

    assert check_encryption_key_health(session) is True  # seeds under key A

    original_fernet = crypto_module._get_fernet
    _swap_fernet_key(crypto_module)
    try:
        assert check_encryption_key_health(session) is False
        # Admin has reconnected every affected integration under the new
        # (current) key, reseed marks it as the new source of truth.
        reseed_encryption_key_canary(session)
        assert check_encryption_key_health(session) is True
    finally:
        crypto_module._get_fernet = original_fernet
        crypto_module._get_fernet.cache_clear()


def select_canary():
    from sqlmodel import select

    return select(EncryptionKeyCanary)


def test_pre_rename_canary_still_reports_healthy(session):
    """Rikugan -> Toleman rename: a database seeded before the rename holds a
    canary encrypting the *old* plaintext. The key itself has not changed, so
    the health check must not report a mismatch; otherwise the rename alone
    would fire the CRITICAL "PLATFORM_ENCRYPTION_KEY MISMATCH" alert on every
    existing deployment and send operators to reconnect working integrations.
    """
    import app.core.crypto as crypto_module

    legacy = crypto_module._LEGACY_CANARY_PLAINTEXTS[0]
    assert legacy != crypto_module._CANARY_PLAINTEXT
    session.add(EncryptionKeyCanary(ciphertext=encrypt_secret(legacy)))
    session.commit()

    assert check_encryption_key_health(session) is True


def test_pre_rename_canary_still_detects_a_real_key_swap(session):
    """The legacy-plaintext allowance must not swallow an actual mismatch:
    a pre-rename canary under a *different* key still has to report unhealthy.
    """
    import app.core.crypto as crypto_module

    legacy = crypto_module._LEGACY_CANARY_PLAINTEXTS[0]
    session.add(EncryptionKeyCanary(ciphertext=encrypt_secret(legacy)))
    session.commit()

    original_fernet = crypto_module._get_fernet
    _swap_fernet_key(crypto_module)
    try:
        assert check_encryption_key_health(session) is False
    finally:
        crypto_module._get_fernet = original_fernet
        crypto_module._get_fernet.cache_clear()
