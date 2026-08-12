# OSP — Open-Source DevSecOps Vulnerability Management Platform

MVP slice of the [architecture](../ARCHITECTURE.md): FastAPI + Celery backend, Next.js frontend, native execution of Semgrep/Trivy/Gitleaks/gosec, dedup engine, two-tier priority scoring, triage state machine.

Deferred (see architecture doc §2/§8): Custom Workflow Builder, Mass CI/CD Rollout Engine, full GitHub App OAuth (this MVP uses a PAT/`gh`-credentialed git clone for native scans and a Workspace API Key for CI push ingestion instead).

## Prerequisites (macOS, Homebrew)

```bash
brew install postgresql@16 redis semgrep trivy gitleaks gosec python@3.12
brew services start postgresql@16
brew services start redis
```

Homebrew's bundled `redis.conf` references modules that aren't shipped — if redis fails to start, comment out the `loadmodule` lines under `/usr/local/etc/redis.conf`.

Create the database:

```bash
psql postgres -c "CREATE USER osp WITH PASSWORD 'osp' CREATEDB;"
psql postgres -c "CREATE DATABASE osp OWNER osp;"
```

## Backend

```bash
cd backend
python3.12 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --port 8000
```

Optional — async/scheduled scans via Celery:

```bash
celery -A app.tasks.celery_app worker -Q scans --loglevel=info
```

Bootstrap a workspace (creates an Org + Workspace + API key for CI push auth):

```bash
curl -X POST "http://localhost:8000/api/workspaces/bootstrap?org_name=myorg&workspace_name=default"
```

Register a target and trigger a native scan:

```bash
curl -X POST http://localhost:8000/api/targets -H "Content-Type: application/json" -d '{
  "workspace_id": 1, "name": "myrepo", "repo_url": "https://github.com/org/repo.git",
  "default_branch": "main", "label": "Dev", "criticality_weight": 2
}'
curl -X POST "http://localhost:8000/api/scans/run?target_id=1&tool=semgrep"
```

Private repos are cloned using whatever git credential helper is already configured locally (e.g. `gh auth setup-git`) — set `GITHUB_TOKEN` in `.env` as an alternative.

## Frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:3000. All pages read live data from the backend API — no mock data.

## Architecture decisions made during build (deltas from the design doc)

- **Python driver**: `psycopg[binary]` (v3) instead of `psycopg2-binary` — no prebuilt wheel for `psycopg2` on Python 3.13+/3.14 yet.
- **pydantic pinned to 2.9.x** — `sqlmodel==0.0.22` breaks on pydantic ≥2.10 (`Field 'id' requires a type annotation`), a known upstream incompatibility.
- **Scan execution runs as a direct subprocess** for this MVP (no container isolation yet) — matches the architecture review's noted blocker; must move to ephemeral containers before multi-tenant/mass-rollout use.
