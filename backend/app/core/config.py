from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://osp:osp@localhost:5432/osp"
    redis_url: str = "redis://localhost:6379/0"
    github_token: str = ""
    workspace_api_key: str = "dev-local-key"
    scan_workdir: str = "/tmp/osp-scans"
    session_secret: str = "dev-local-session-secret-change-me"
    admin_email: str = "admin@rikugan.io"
    admin_password: str = "changeme123"
    admin_name: str = "Admin"
    anthropic_api_key: str = ""
    # Fernet key (urlsafe-base64, 32 bytes) used to encrypt secrets at rest
    # (GitHubAppConfig.private_key_pem/client_secret/webhook_secret). If unset,
    # app/core/crypto.py generates an ephemeral one at first use and logs a
    # warning - fine for local dev, but production MUST set this explicitly or
    # every restart invalidates existing encrypted rows.
    platform_encryption_key: str = ""

    class Config:
        env_file = ".env"


settings = Settings()
