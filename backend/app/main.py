import logging
from urllib.parse import urlparse

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, select

from app.core.config import settings, validate_production_secrets
from app.core.crypto import check_encryption_key_health
from app.core.db import engine, init_db
from app.core.security import hash_password
from app.models.models import User

logger = logging.getLogger(__name__)
from app.api import auth, targets, findings, ingest, scans, dashboard, workspaces, github, ai, audit, admin, admin_workspace_roles, discovery, github_app, config as config_api, tools, pr_guardrail, webhooks, search, policies, sbom, reports, groups, sla_rules, notification_preferences, api_scan, pipeline_templates, fp_rules, api_tokens, public_api
from app.api.auth import current_user, require_admin

app = FastAPI(title="Rikugan - DevSecOps Vulnerability Management Platform")

app.add_middleware(
    CORSMiddleware,
    # GH-02: was a single hardcoded localhost:3000 literal, so any
    # deployment not on that exact origin failed CORS preflight -- and the
    # login form reported that transport failure as "Invalid email or
    # password". Driven by PUBLIC_BASE_URL (+ EXTRA_CORS_ORIGINS) now.
    allow_origins=settings.cors_allow_origins,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)


@app.on_event("startup")
def on_startup():
    validate_production_secrets()
    init_db()
    with Session(engine) as session:
        existing = session.exec(select(User).where(User.email == settings.admin_email)).first()
        if not existing:
            session.add(User(
                email=settings.admin_email,
                name=settings.admin_name,
                password_hash=hash_password(settings.admin_password),
            ))
            session.commit()
        # Detect a PLATFORM_ENCRYPTION_KEY mismatch here, at boot, rather than
        # letting it surface later as a random feature's decrypt failure --
        # see check_encryption_key_health's docstring for why this exists.
        # Deliberately logged, not raised: a hard startup failure here would
        # lock an admin out of the very UI (Admin > Global Integrations) they
        # need to reconnect integrations and clear this warning.
        if not check_encryption_key_health(session):
            logger.critical(
                "PLATFORM_ENCRYPTION_KEY MISMATCH: the configured encryption key "
                "cannot decrypt secrets written by a previous key. Every encrypted "
                "secret in this database (GitHub App credentials, Slack/Jira/SIEM "
                "webhooks, the AI provider key) is currently undecryptable. "
                "Reconnect each affected integration in Admin > Global Integrations, "
                "then use the 'I've reconnected everything' action there to clear "
                "this warning."
            )


login_required = [Depends(current_user)]
admin_required = [Depends(require_admin)]

app.include_router(auth.router)
app.include_router(ingest.router)  # own auth: Workspace API key, not a login session
app.include_router(github_app.public_router)  # GitHub calls these directly, no session cookie available
app.include_router(webhooks.router)  # GitHub webhook deliveries, verified via HMAC signature instead of a session
app.include_router(public_api.router)  # own auth: Bearer API token (see app.api.auth.current_api_token_user), not a login session

app.include_router(workspaces.router, dependencies=login_required)
app.include_router(targets.router, dependencies=login_required)
app.include_router(groups.router, dependencies=login_required)
app.include_router(sla_rules.router, dependencies=login_required)
app.include_router(fp_rules.router, dependencies=login_required)
app.include_router(findings.router, dependencies=login_required)
app.include_router(scans.router, dependencies=login_required)
app.include_router(dashboard.router, dependencies=login_required)
app.include_router(github.router, dependencies=login_required)
app.include_router(ai.router, dependencies=login_required)
app.include_router(audit.router, dependencies=login_required)
app.include_router(discovery.router, dependencies=login_required)
app.include_router(api_scan.router, dependencies=login_required)
app.include_router(github_app.router, dependencies=login_required)
app.include_router(tools.router, dependencies=login_required)
app.include_router(pr_guardrail.router, dependencies=login_required)
app.include_router(search.router, dependencies=login_required)
app.include_router(sbom.router, dependencies=login_required)
app.include_router(reports.router, dependencies=login_required)
app.include_router(notification_preferences.router, dependencies=login_required)
app.include_router(pipeline_templates.router, dependencies=login_required)
app.include_router(api_tokens.router, dependencies=login_required)

app.include_router(admin.router, dependencies=admin_required)
app.include_router(admin_workspace_roles.router, dependencies=admin_required)
app.include_router(config_api.router, dependencies=admin_required)
# Policy rules can silently suppress real findings / widen PR Guardrail's
# blocking threshold platform-wide -- there's no per-workspace membership
# model in this app (single org/admin pattern, same as admin.router and
# config_api.router above), so admin-only is the only safe gate available.
# Previously login_required, which let any authenticated user (including
# role=viewer) create suppression rules for any workspace_id - a real IDOR
# found in review.
app.include_router(policies.router, dependencies=admin_required)


@app.get("/health")
def health():
    """Liveness, plus build identity (BLD-01).

    The identity fields are what let anyone -- an evaluator, a deploy script,
    a support conversation -- confirm *which* instance is answering on this
    address before drawing conclusions from what it shows. Cheap insurance
    against reviewing a stack you are not actually running.
    """
    return {
        "status": "ok",
        "version": settings.build_version,
        "commit": settings.build_commit,
        # Which database this instance is talking to, host/name only -- never
        # the URL, which carries credentials.
        "database": _database_identity(),
    }


def _database_identity() -> str:
    """host:port/dbname from DATABASE_URL, with credentials stripped.

    Deliberately reconstructed field by field rather than regex-scrubbing the
    URL: a scrub that misses leaves a password in an unauthenticated
    endpoint's response body, and this endpoint is reachable without a
    session by design (container healthchecks call it).
    """
    try:
        parsed = urlparse(settings.database_url)
        host = parsed.hostname or "?"
        port = f":{parsed.port}" if parsed.port else ""
        name = (parsed.path or "").lstrip("/") or "?"
        return f"{host}{port}/{name}"
    except Exception:
        return "unknown"
