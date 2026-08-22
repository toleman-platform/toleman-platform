from pydantic_settings import BaseSettings

# Known insecure defaults. Fine for local dev (zero-config workflow); must be
# overridden via env vars in any non-local deployment - see
# validate_production_secrets() below.
DEFAULT_SESSION_SECRET = "dev-local-session-secret-change-me"
DEFAULT_ADMIN_PASSWORD = "changeme123"


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://rikugan:rikugan@localhost:5432/rikugan"
    redis_url: str = "redis://localhost:6379/0"
    workspace_api_key: str = "dev-local-key"
    scan_workdir: str = "/tmp/rikugan-scans"
    session_secret: str = DEFAULT_SESSION_SECRET
    # Set True in any production/HTTPS deployment so the session cookie is
    # only ever sent over TLS. Defaults to False so local http:// dev works.
    cookie_secure: bool = False
    # rikugan.local, not rikugan.io -- the project doesn't own that domain
    # and shipping it as a public-repo default could mislead someone into
    # thinking it's a real, owned address (#154).
    admin_email: str = "admin@rikugan.local"
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
    # are deliberately conservative -- exclude tags known to send disruptive
    # traffic (dos/fuzz can crash a target; intrusive templates attempt
    # actual exploitation, not just detection) so a first-run scan against a
    # real deployed API defaults to passive/safe detection templates only.
    # An operator can widen this via env var once they understand the
    # implications for their own infrastructure.
    nuclei_binary: str = "nuclei"
    nuclei_timeout_seconds: int = 300
    nuclei_rate_limit: int = 10
    nuclei_exclude_tags: str = "dos,fuzz,intrusive"

    # Issue #153: a Scan/DiscoveryRun/SbomRun/PipelineIntegrationBatch row can
    # be left "running" forever if its Celery task never actually reaches a
    # worker (e.g. a worker listening on the wrong queue) or the worker
    # process dies mid-task -- there's no beat/cron in this project to sweep
    # for that, so app/core/staleness.py checks lazily on read instead. 15
    # minutes comfortably exceeds every real tool's own timeout (nuclei's
    # above included) so this only fires for jobs that are actually stuck,
    # not ones that are just slow.
    stale_job_timeout_seconds: int = 900

    # Where *other people and other machines* reach this deployment.
    #
    # Finding GH-02: these were five hardcoded "http://localhost:3000" /
    # ":8000" literals spread across main.py, api/github_app.py and
    # core/pr_guardrail_executor.py. Every link Rikugan posted to GitHub --
    # the PR comment's "review in Rikugan", the commit status target_url,
    # the "request ignore" link -- pointed at the developer's own laptop, so
    # no teammate on a shared repository could follow any of them. The same
    # constant pinned CORS to a single origin, which made running on any
    # other port surface as "Invalid email or password" at the login form.
    #
    # public_base_url  -> the frontend, as a browser reaches it.
    # public_api_url   -> this backend, as GitHub's servers reach it
    #                     (the GitHub App manifest's callback/webhook host).
    #
    # Defaults preserve the existing localhost dev experience exactly, so
    # nothing has to be configured to keep working locally.
    public_base_url: str = "http://localhost:3000"
    public_api_url: str = "http://localhost:8000"
    # Extra browser origins allowed to call this API, comma-separated.
    # public_base_url is always allowed; this is for the cases where it
    # isn't the only one (e.g. a staging alias, or a dev server on a
    # second port). See cors_allow_origins below.
    extra_cors_origins: str = ""

    # (BLD-01) Build identity, surfaced by GET /health and in the sidebar.
    #
    # An external evaluator built a fresh stack while a previously-running
    # host-native instance still held :3000/:8000. The browser resolved
    # localhost to the old process, so the "fresh" install showed 1,434
    # findings and 35 targets while the new container database held zero.
    # Nothing in the product flagged the mismatch -- it was only caught by
    # querying Postgres directly. An hour of review can go into an instance
    # that is not the one being reviewed.
    #
    # Set at image build time (see backend/Dockerfile's ARG/ENV pair, fed by
    # CI from the real commit). "dev" is the honest answer for a working tree
    # rather than a fabricated version number.
    build_version: str = "dev"
    build_commit: str = ""

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
