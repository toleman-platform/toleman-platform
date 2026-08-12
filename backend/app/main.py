from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.db import init_db
from app.api import targets, findings, ingest, scans, dashboard, workspaces

app = FastAPI(title="OSP - DevSecOps Vulnerability Management Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    init_db()


app.include_router(workspaces.router)
app.include_router(targets.router)
app.include_router(findings.router)
app.include_router(ingest.router)
app.include_router(scans.router)
app.include_router(dashboard.router)


@app.get("/health")
def health():
    return {"status": "ok"}
