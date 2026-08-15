---
sidebar_position: 2
---

# Architecture Overview

## Stack

- **Backend**: FastAPI + SQLModel + PostgreSQL + Celery/Redis, Python 3.12
- **Frontend**: Next.js 16 (App Router) + TypeScript + Tailwind, dark-theme design system
- **Scanners**: Semgrep (SAST), Trivy (container/SCA), Gitleaks (secrets), gosec (Go), nuclei (active API scanning)
- **Deployment**: `docker-compose.yml` at repo root (postgres, redis, backend, celery-worker, frontend)

## Directory map

```
backend/app/
  api/        one file per resource, FastAPI router
  core/       shared logic: db engine, crypto, scoring, dedup, scanner HTTP clients, Celery app
  models/     models.py — every SQLModel table + enum
  scanners/   runner.py (subprocess dispatch), discovery.py (route extraction), parsers.py (tool output → findings)
  tasks/      Celery tasks — scan/discovery/sbom/pr_guardrail all run async via .delay()
backend/alembic/versions/   one migration file per schema change

frontend/src/app/(dashboard)/   one directory per sidebar page
frontend/src/components/        shared components
frontend/src/lib/api.ts         single API client
```

## Core data model

`Organization` → `Workspace` → `Target` (a scanned repo) → `Finding` / `Scan` / `ApiEndpoint` / `SbomComponent`

- Every `User` has a **global** role (admin/user/viewer/developer/security_engineer) — admins bypass all workspace scoping.
- `WorkspaceMembership` layers a **workspace-scoped** role on top of the global one; non-admin visibility on list endpoints is filtered by this.
- `PRGuardrailScan` → `PRGuardrailFinding` are kept separate from the main `Finding` table so PR-branch noise doesn't pollute default-branch posture.

## Async job pattern

Long-running work (git clone + scanner subprocess, GitHub API calls) never runs synchronously in a request handler. The pattern throughout the platform:

1. Request handler creates a tracking row (`Scan` / `DiscoveryRun` / `SbomRun` / batch tables) with `status="running"`.
2. Dispatches a Celery task via `.delay()`.
3. Returns `202` immediately.
4. Frontend polls a `GET` endpoint (`frontend/src/lib/poll.ts`) until the row settles.

## Database migrations

The backend's startup hook (`app/core/db.py:init_db`) runs `alembic upgrade head` automatically on every start — there's no manual migration step to just run the app.

You only touch Alembic directly when you change `backend/app/models/models.py`:

```bash
cd backend
alembic revision --autogenerate -m "describe the schema change"
```

Always review the generated file under `alembic/versions/` before committing — autogenerate is a starting point (it can miss column renames, seeing them as drop+add).

## Philosophy

Rikugan is deliberately **100% free** — every feature (SSO, RBAC, PR enforcement, etc.) ships without a paid tier. It's also **operational, not just aggregating**: it natively runs scanners, manages tool installs, and enforces block/alert modes in CI/CD, rather than just ingesting other tools' output.
