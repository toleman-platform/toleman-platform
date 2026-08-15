---
sidebar_position: 1
---

# Quickstart

Rikugan is 100% free and open-source — no paid tiers, no feature gating. This page gets you from `git clone` to a running instance.

## Option A: Docker Compose (recommended)

Requires only [Docker](https://docs.docker.com/get-docker/) with Compose v2.

```bash
git clone https://github.com/geekshiv/rikugan.git
cd rikugan
cp .env.example .env   # every var has a working local-dev default
docker compose up --build
```

This starts five containers:

- **postgres** (16) and **redis** (7) — each gated by a real healthcheck
- **backend** — FastAPI on port 8000, with Semgrep/Trivy/Gitleaks/gosec pre-installed
- **celery-worker** — same image as backend, runs async scan/discovery/SBOM/PR Guardrail jobs
- **frontend** — Next.js on port 3000

Once it's up:

| What | Where |
|---|---|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:8000 (`/docs` for OpenAPI UI, `/health` for liveness) |
| Scanner sanity check | `curl http://localhost:8000/api/tools/health` |

Sign in with the seeded admin account: `ADMIN_EMAIL`/`ADMIN_PASSWORD` from `.env` (defaults to `admin@rikugan.io` / `changeme123` — **change this before any non-local use**).

To stop: `docker compose down` (add `-v` to also drop the Postgres volume).

## Option B: Manual setup (macOS, Homebrew)

Prefer running backend/frontend directly for hot reload or debugging.

```bash
brew install postgresql@16 redis semgrep trivy gitleaks gosec python@3.12
brew services start postgresql@16
brew services start redis
```

Create the database:

```bash
psql postgres -c "CREATE USER rikugan WITH PASSWORD 'rikugan' CREATEDB;"
psql postgres -c "CREATE DATABASE rikugan OWNER rikugan;"
```

### Backend

```bash
cd backend
python3.12 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --port 8000
```

Async work (scans/discovery/SBOM/PR Guardrail) requires the Celery worker:

```bash
celery -A app.tasks.celery_app worker -Q scans --loglevel=info
```

The backend's startup hook runs `alembic upgrade head` automatically — no separate migration step needed just to run the app. See [Architecture Overview](./architecture-overview.md) for when you *do* need to touch Alembic directly.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:3000 — redirects to `/login`.

## First steps after signing in

1. Bootstrap or confirm your workspace (Settings → Workspaces).
2. Connect GitHub — see [Connecting GitHub](../github-integration/connecting-github.md).
3. Add a target repo and run your first scan — see [Scanners](../scanning/scanners.md).
