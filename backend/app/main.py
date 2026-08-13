from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, select

from app.core.config import settings
from app.core.db import engine, init_db
from app.core.security import hash_password
from app.models.models import User
from app.api import auth, targets, findings, ingest, scans, dashboard, workspaces, github, ai, audit, admin, discovery, github_app, config as config_api, tools, pr_guardrail, webhooks, search, policies
from app.api.auth import current_user, require_admin

app = FastAPI(title="OSP - DevSecOps Vulnerability Management Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)


@app.on_event("startup")
def on_startup():
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


login_required = [Depends(current_user)]
admin_required = [Depends(require_admin)]

app.include_router(auth.router)
app.include_router(ingest.router)  # own auth: Workspace API key, not a login session
app.include_router(github_app.public_router)  # GitHub calls these directly, no session cookie available
app.include_router(webhooks.router)  # GitHub webhook deliveries, verified via HMAC signature instead of a session

app.include_router(workspaces.router, dependencies=login_required)
app.include_router(targets.router, dependencies=login_required)
app.include_router(findings.router, dependencies=login_required)
app.include_router(scans.router, dependencies=login_required)
app.include_router(dashboard.router, dependencies=login_required)
app.include_router(github.router, dependencies=login_required)
app.include_router(ai.router, dependencies=login_required)
app.include_router(audit.router, dependencies=login_required)
app.include_router(discovery.router, dependencies=login_required)
app.include_router(github_app.router, dependencies=login_required)
app.include_router(tools.router, dependencies=login_required)
app.include_router(pr_guardrail.router, dependencies=login_required)
app.include_router(search.router, dependencies=login_required)
app.include_router(policies.router, dependencies=login_required)

app.include_router(admin.router, dependencies=admin_required)
app.include_router(config_api.router, dependencies=admin_required)


@app.get("/health")
def health():
    return {"status": "ok"}
