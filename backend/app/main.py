from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, select

from app.core.config import settings
from app.core.db import engine, init_db
from app.core.security import hash_password
from app.models.models import User
from app.api import auth, targets, findings, ingest, scans, dashboard, workspaces

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


app.include_router(auth.router)
app.include_router(workspaces.router)
app.include_router(targets.router)
app.include_router(findings.router)
app.include_router(ingest.router)
app.include_router(scans.router)
app.include_router(dashboard.router)


@app.get("/health")
def health():
    return {"status": "ok"}
