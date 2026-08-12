from app.core.crypto import decrypt_secret, encrypt_secret


def test_encrypt_decrypt_roundtrip():
    plaintext = "-----BEGIN RSA PRIVATE KEY-----\nabc123\n-----END RSA PRIVATE KEY-----"
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
        except ValueError:
            pass
    finally:
        crypto_module._get_fernet = original_fernet
        crypto_module._get_fernet.cache_clear()
