from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://osp:osp@localhost:5432/osp"
    redis_url: str = "redis://localhost:6379/0"
    github_token: str = ""
    workspace_api_key: str = "dev-local-key"
    scan_workdir: str = "/tmp/osp-scans"
    session_secret: str = "dev-local-session-secret-change-me"
    # Set True in any production/HTTPS deployment so the session cookie is
    # only ever sent over TLS. Defaults to False so local http:// dev works.
    cookie_secure: bool = False
    admin_email: str = "admin@rikugan.io"
    admin_password: str = "changeme123"
    admin_name: str = "Admin"
    anthropic_api_key: str = ""

    class Config:
        env_file = ".env"


settings = Settings()
