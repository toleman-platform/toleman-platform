from pydantic_settings import BaseSettings

# Known insecure defaults. Fine for local dev (zero-config workflow); must be
# overridden via env vars in any non-local deployment - see
# validate_production_secrets() below.
DEFAULT_SESSION_SECRET = "dev-local-session-secret-change-me"
DEFAULT_ADMIN_PASSWORD = "changeme123"


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://toleman:toleman@localhost:5432/toleman"
    # Keep per-process pools small enough for all backend/worker replicas to fit
    # managed-DB connection limits. Always-on pool_pre_ping handles idle connections
    # silently dropped by databases or proxies.
    db_pool_size: int = 5
    db_max_overflow: int = 10
    # Recycle before most managed DBs' own idle/connection-lifetime cutoff
    # (RDS Proxy defaults to 15 min idle; Cloud SQL Auth Proxy and most
    # cloud LBs sit lower still), so a connection is retired on our terms
    # before the far end closes it out from under an in-flight query.
    db_pool_recycle_seconds: int = 600
    redis_url: str = "redis://localhost:6379/0"
    workspace_api_key: str = "dev-local-key"
    scan_workdir: str = "/tmp/toleman-scans"
    # Managed Trivy DB generations and per-run hardlinked caches. Publish whole
    # generations under a lock; never seed from mutable per-user caches. Keep this and
    # scan_workdir on the same filesystem for hardlinks, on a real volume rather than
    # tmpfs for the large DB.
    tool_cache_dir: str = "/tmp/toleman-tool-cache"
    session_secret: str = DEFAULT_SESSION_SECRET
    # Set True in any production/HTTPS deployment so the session cookie is
    # only ever sent over TLS. Defaults to False so local http:// dev works.
    cookie_secure: bool = False
    # Set when the frontend and this API are deployed on different
    # subdomains of the same parent domain (e.g. app.example.com and
    # api.example.com) so the session cookie is shared between them --
    # without this, a cookie set by the API defaults to that exact host
    # only, and the frontend's own server (which reads the cookie directly
    # for server-rendered pages, not just the browser's fetch calls) never
    # sees it, silently bouncing every "logged in" user back to the login
    # page after a successful login. Leave unset for same-origin/local
    # deployments, where the default host-only scoping is exactly right.
    # Example: ".example.com" (leading dot optional on modern browsers).
    cookie_domain: str = ""
    # toleman.local, not toleman.io, the project doesn't own that domain
    # and shipping it as a public-repo default could mislead someone into
    # thinking it's a real, owned address (#154).
    admin_email: str = "admin@toleman.local"
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

    # Issue #72 (Active API Scanning): nuclei CLI invocation knobs. Defaults
    # are deliberately conservative, exclude tags known to send disruptive
    # traffic (dos/fuzz can crash a target; intrusive templates attempt
    # actual exploitation, not just detection) so a first-run scan against a
    # real deployed API defaults to passive/safe detection templates only.
    # An operator can widen this via env var once they understand the
    # implications for their own infrastructure.
    nuclei_binary: str = "nuclei"
    nuclei_timeout_seconds: int = 300
    nuclei_rate_limit: int = 10
    nuclei_exclude_tags: str = "dos,fuzz,intrusive"

    # (#247 follow-up) Fix Plan npm/yarn/pnpm autofix: how long a single
    # package-manager bump (npm install --package-lock-only / pnpm add
    # --lockfile-only / yarn up|add) may run in app.core.npm_lockfile_autofix
    # before being killed. Same role as nuclei_timeout_seconds above -- and,
    # like that one, exists specifically so a hung subprocess (a slow
    # registry, a stuck classic-yarn resolve) can't occupy a Celery worker
    # slot indefinitely; see that module's docstring for why none of the
    # OTHER scanner subprocesses in runner.py have an equivalent yet.
    npm_install_timeout_seconds: int = 180

    # Issue #153: a Scan/DiscoveryRun/SbomRun/PipelineIntegrationBatch row can
    # be left "running" forever if its Celery task never actually reaches a
    # worker (e.g. a worker listening on the wrong queue) or the worker
    # process dies mid-task, there's no beat/cron in this project to sweep
    # for that, so app/core/staleness.py checks lazily on read instead. 15
    # minutes comfortably exceeds every real tool's own timeout (nuclei's
    # above included) so this only fires for jobs that are actually stuck,
    # not ones that are just slow.
    stale_job_timeout_seconds: int = 900

    # Public deployment URLs: public_base_url is the browser-facing frontend;
    # public_api_url is the backend reachable by GitHub for callbacks/webhooks.
    # Localhost defaults support development; shared deployments must configure both.
    public_base_url: str = "http://localhost:3000"
    public_api_url: str = "http://localhost:8000"
    # Extra browser origins allowed to call this API, comma-separated.
    # public_base_url is always allowed; this is for the cases where it
    # isn't the only one (e.g. a staging alias, or a dev server on a
    # second port). See cors_allow_origins below.
    extra_cors_origins: str = ""

    # Operator-only, comma-separated additions to the git-clone host allowlist. Keep
    # this deployment configuration outside user-controlled API inputs: allowing
    # arbitrary hosts would permit SSRF. Use for internal GitHub Enterprise/GitLab/Gitea
    # hosts.
    extra_clone_hosts: str = ""

    # Build identity appears in /health and the sidebar to identify the serving
    # instance. CI sets it at image-build time; local working trees use dev.
    build_version: str = "dev"
    build_commit: str = ""

    # Python logging level name (DEBUG/INFO/WARNING/ERROR/CRITICAL) for the
    # JSON logging configured by app/core/logging.py's configure_logging().
    log_level: str = "INFO"

    class Config:
        env_file = ".env"

    @property
    def cors_allow_origins(self) -> list[str]:
        """Every browser origin permitted to call this API.

        Always includes public_base_url so the deployment's own frontend
        works with no extra configuration. Deliberately never "*": these
        endpoints are session-cookie authenticated, and FastAPI's
        allow_credentials=True with a wildcard origin is both rejected by
        browsers and a real CSRF surface if it weren't.
        """
        origins = [self.public_base_url.rstrip("/")]
        for extra in self.extra_cors_origins.split(","):
            extra = extra.strip().rstrip("/")
            if extra and extra not in origins:
                origins.append(extra)
        return origins

    @property
    def extra_clone_hosts_set(self) -> set[str]:
        """Operator-configured hosts to add to ALLOWED_CLONE_HOSTS. See
        extra_clone_hosts's own docstring for why this must stay
        operator-set (an env var) rather than anything an API caller can
        influence."""
        return {h.strip() for h in self.extra_clone_hosts.split(",") if h.strip()}


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
    if not s.session_secret.strip() or s.session_secret == DEFAULT_SESSION_SECRET:
        unset.append("SESSION_SECRET")
    if not s.admin_password.strip() or s.admin_password == DEFAULT_ADMIN_PASSWORD:
        unset.append("ADMIN_PASSWORD")

    if unset:
        raise RuntimeError(
            "Refusing to start: ENVIRONMENT is set to "
            f"{s.environment!r} but the following env var(s) are still at "
            f"their insecure default value: {', '.join(unset)}. Set "
            f"{'/'.join(unset)} to a real secret before starting a non-local "
            "deployment (or set ENVIRONMENT=local for local development only)."
        )
