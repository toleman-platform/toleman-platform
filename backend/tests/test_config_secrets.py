"""Issue #55: a non-local deployment must not silently boot with the
default session_secret / admin_password baked into Settings - either would
let sessions be forged or the seeded admin account be guessed.

validate_production_secrets() is the fail-fast startup check (called from
app.main's on_startup handler); these tests call it directly against
constructed Settings instances rather than spinning up the whole app.
"""
import pytest

from app.core.config import (
    DEFAULT_ADMIN_PASSWORD,
    DEFAULT_SESSION_SECRET,
    Settings,
    validate_production_secrets,
)


def test_production_with_default_session_secret_raises():
    s = Settings(
        environment="production",
        session_secret=DEFAULT_SESSION_SECRET,
        admin_password="a-real-strong-password",
    )
    with pytest.raises(RuntimeError, match="SESSION_SECRET"):
        validate_production_secrets(s)


def test_production_with_default_admin_password_raises():
    s = Settings(
        environment="production",
        session_secret="a-real-random-secret-value",
        admin_password=DEFAULT_ADMIN_PASSWORD,
    )
    with pytest.raises(RuntimeError, match="ADMIN_PASSWORD"):
        validate_production_secrets(s)


def test_production_with_both_defaults_raises_and_names_both():
    s = Settings(environment="production")  # defaults for both fields
    with pytest.raises(RuntimeError) as exc_info:
        validate_production_secrets(s)
    assert "SESSION_SECRET" in str(exc_info.value)
    assert "ADMIN_PASSWORD" in str(exc_info.value)


def test_staging_environment_also_enforced():
    """Any non-local environment value is enforced, not just 'production'."""
    s = Settings(environment="staging")
    with pytest.raises(RuntimeError):
        validate_production_secrets(s)


def test_local_environment_default_is_exempt():
    """Today's zero-config local dev workflow must keep working unchanged:
    environment defaults to 'local', so unset secrets don't block startup."""
    s = Settings()
    assert s.environment == "local"
    validate_production_secrets(s)  # must not raise


def test_local_environment_explicit_is_exempt_even_with_defaults():
    s = Settings(environment="local")
    validate_production_secrets(s)  # must not raise


def test_production_with_real_non_default_values_does_not_raise():
    s = Settings(
        environment="production",
        session_secret="a-real-random-secret-value",
        admin_password="a-real-strong-password",
    )
    validate_production_secrets(s)  # must not raise
