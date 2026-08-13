from pydantic_settings import BaseSettings

# Known insecure defaults. Fine for local dev (zero-config workflow); must be
# overridden via env vars in any non-local deployment - see
# validate_production_secrets() below.
DEFAULT_SESSION_SECRET = "dev-local-session-secret-change-me"
DEFAULT_ADMIN_PASSWORD = "changeme123"


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://osp:osp@localhost:5432/osp"
    redis_url: str = "redis://localhost:6379/0"
    github_token: str = ""
    workspace_api_key: str = "dev-local-key"
    scan_workdir: str = "/tmp/osp-scans"
    session_secret: str = DEFAULT_SESSION_SECRET
    # Set True in any production/HTTPS deployment so the session cookie is
    # only ever sent over TLS. Defaults to False so local http:// dev works.
    cookie_secure: bool = False
    admin_email: str = "admin@rikugan.io"
    admin_password: str = DEFAULT_ADMIN_PASSWORD
    admin_name: str = "Admin"
    anthropic_api_key: str = ""
    # Fernet key (urlsafe-base64, 32 bytes) used to encrypt secrets at rest
    # (GitHubAppConfig.private_key_pem/client_secret/webhook_secret). If unset,
    # app/core/crypto.py generates an ephemeral one at first use and logs a
    # warning - fine for local dev, but production MUST set this explicitly or
    # every restart invalidates existing encrypted rows.
    platform_encryption_key: str = ""
    # Deployment environment signal. Defaults to "local" so the existing
    # zero-config dev workflow is unaffected. Any non-local deployment
    # (e.g. "production", "staging") is subject to validate_production_secrets()
    # below. Set via the ENVIRONMENT env var.
    environment: str = "local"

    class Config:
        env_file = ".env"


settings = Settings()


def validate_production_secrets(s: Settings = settings) -> None:
    """Fail fast if a non-local deployment still has default secrets.

    Local dev (environment == "local", the default) is intentionally exempt
    so today's zero-config local workflow keeps working unchanged. Any other
    ENVIRONMENT value (e.g. "production", "staging") must set real
    SESSION_SECRET / ADMIN_PASSWORD values, or startup is aborted - a forged
    session or a guessed seeded-admin login is otherwise possible.
    """
    if s.environment == "local":
        return

    unset = []
    if s.session_secret == DEFAULT_SESSION_SECRET:
        unset.append("SESSION_SECRET")
    if s.admin_password == DEFAULT_ADMIN_PASSWORD:
        unset.append("ADMIN_PASSWORD")

    if unset:
        raise RuntimeError(
            "Refusing to start: ENVIRONMENT is set to "
            f"{s.environment!r} but the following env var(s) are still at "
            f"their insecure default value: {', '.join(unset)}. Set "
            f"{'/'.join(unset)} to a real secret before starting a non-local "
            "deployment (or set ENVIRONMENT=local for local development only)."
        )
