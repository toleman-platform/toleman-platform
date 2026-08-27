# Toleman: Open-Source DevSecOps Vulnerability Management Platform

> **Status: active development.** No tagged release yet; `main` is the only
> line to track. APIs, schema, and config vars can change without notice.
> Expect rough edges; file issues for what you hit.

See the [architecture](ARCHITECTURE.md) for the full design: FastAPI + Celery backend, Next.js frontend, native execution of Semgrep/Trivy/Gitleaks/gosec and more, OSV.dev malicious-package detection on SBOM inventory (surfaced as `osv-malware` Critical findings), dedup engine, two-tier priority scoring, triage state machine.

**Documentation:** [geekshiv.github.io/toleman](https://geekshiv.github.io/toleman) (source: [geekshiv/toleman](https://github.com/geekshiv/toleman)).

## Contents

- [Getting Started](#getting-started)
  - [Quickstart (Docker Compose)](#quickstart-docker-compose)
  - [Manual setup (macOS/Linux/Windows)](#manual-setup-macoslinuxwindows)
- [Development](#development)
  - [Database migrations (Alembic)](#database-migrations-alembic)
  - [Pre-commit hooks](#pre-commit-hooks)
- [Architecture decisions made during build](#architecture-decisions-made-during-build-deltas-from-the-design-doc)
- [License & Security](#license--security)

## Getting Started

### Quickstart (Docker Compose)

The fastest way to try Toleman, no Homebrew, no manually installing Postgres/Redis/scanner CLIs. Requires only [Docker](https://docs.docker.com/get-docker/) with Compose v2 (`docker compose`, bundled with Docker Desktop and recent Docker Engine installs).

```bash
cp .env.example .env   # optional: every var has a working local-dev default
docker compose up --build
```

#### Prefer not to build from source?

Prebuilt images are published to GHCR by [`publish-images.yml`](.github/workflows/publish-images.yml). Use the override file instead of editing `docker-compose.yml`:

```bash
docker compose -f docker-compose.yml -f docker-compose.ghcr.yml pull
docker compose -f docker-compose.yml -f docker-compose.ghcr.yml up
```

Available tags, for both `…-backend` and `…-frontend`:

| Tag | Moves | Use it for |
|---|---|---|
| `edge` | every merge to `main` | trying the current state of the project |
| `latest` | every tagged release | tracking releases without pinning |
| `1.2.3`, `1.2` | fixed at release | pinning to a release |
| `sha-abc1234` | never | reproducing an exact build |

No version has been tagged yet, so only `edge` and `sha-` tags exist today; `latest`/`1.2.3`-style tags will appear once the first release ships. `edge` and `latest` are moving tags; pin to a version or a `sha-` tag for anything you need to reproduce. Every image carries [build provenance](https://docs.github.com/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds) attesting the workflow run and commit it came from:

```bash
gh attestation verify oci://ghcr.io/toleman-platform/toleman-platform-backend:edge \
  --owner toleman-platform
```

Releases build for `linux/amd64` and `linux/arm64`; `edge` is amd64 only, since emulated arm64 builds are too slow to justify on every merge. On Apple Silicon, either use a released tag or build from source with `docker compose up --build`.

This builds and starts five containers:

- `postgres` (16) and `redis` (7), each gated by a real healthcheck (`pg_isready`, `redis-cli ping`)
- `backend`: FastAPI on port 8000, with Semgrep/Trivy/Gitleaks/gosec installed in the image (same versions/install method proven in `.github/workflows/`); waits for Postgres and Redis to report healthy before starting, and exposes its own healthcheck (`curl` against `/health`)
- `celery-worker`: same image as `backend`, running `celery -A app.tasks.celery_app worker -Q scans`; waits for the backend to be healthy first (backend's startup hook runs `alembic upgrade head` against `DATABASE_URL` before serving, so the schema is always current; see `backend/alembic/`)
- `frontend`: Next.js on port 3000, waits for the backend to be healthy

Once it's up:

- Frontend: http://localhost:3000, sign in with the seeded admin account (`ADMIN_EMAIL`/`ADMIN_PASSWORD` in `.env`, defaults to `admin@toleman.local` / `changeme123`)
- Backend: http://localhost:8000 (`/docs` for the OpenAPI UI, `/health` for a liveness check)
- Scanner install sanity check: **Control Plane → Tooling → Tool Marketplace** reports real installed versions for every scanner, checked live inside the containers that run scans.

  `/api/tools/health` backs that page but requires a login session, so a bare `curl` returns `{"detail":"not authenticated"}`. To check it from a shell, run the scanners directly instead:

  ```bash
  docker compose exec backend sh -c 'semgrep --version && trivy --version && gitleaks version && gosec --version'
  ```

Bootstrap a workspace and register a target the same way as the manual setup below, just against `http://localhost:8000`.

See `.env.example` for every variable Compose reads (Postgres credentials, backend secrets, `NEXT_PUBLIC_API_URL`) and what happens if you leave it at its default. `.env` is git-ignored, so it's safe to put real secrets there once you have any (`GITHUB_TOKEN`, `ANTHROPIC_API_KEY`, etc.).

To stop everything: `docker compose down` (add `-v` to also drop the Postgres volume and start fully fresh next time).

### Kubernetes (Helm)

An out-of-the-box Helm chart lives at [`charts/toleman`](charts/toleman), covering the same five services as the Docker Compose stack above (bundled Postgres StatefulSet + PVC, bundled Redis, backend, celery-worker, frontend), plus an optional Ingress.

```bash
helm install toleman charts/toleman \
  --set-string secrets.sessionSecret="$(openssl rand -hex 32)" \
  --set-string secrets.adminPassword="a real password" \
  --set-string secrets.platformEncryptionKey="$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" \
  --set-string postgres.password="$(openssl rand -hex 24)" \
  --set config.publicBaseUrl="https://toleman.example.com" \
  --set config.publicApiUrl="https://api.toleman.example.com"
```

`config.environment` defaults to `production`, so the `secrets.*` values and `postgres.password` above are required — the chart's own render fails without them (see `charts/toleman/templates/secret.yaml`) rather than silently deploying with an empty session-signing key/admin password/encryption key, or a bundled Postgres reachable with its publicly-documented default password. Use `https://` for `public*Url` for anything but throwaway testing: `config.cookieSecure` defaults to `"True"`, and a browser will not send a `Secure` session cookie over plain HTTP, so login fails. Put TLS in front of the deployment (an Ingress with `ingress.tls` configured, or your own load balancer) rather than setting `config.cookieSecure` to `"False"`, which is for non-production HTTP testing only.

See `charts/toleman/values.yaml` for every option, including how to point at a managed Postgres/Redis instead of the bundled ones (`postgres.enabled: false` / `redis.enabled: false` plus `externalDatabaseUrl` / `externalRedisUrl`, a full SQLAlchemy connection string — `app/core/config.py` doesn't distinguish a managed DB from the bundled one) and how to enable the Ingress (`ingress.enabled: true`, plus `ingress.tls` for HTTPS). `helm install`'s NOTES output repeats the port-forward command, prints `http`/`https` in the Ingress URLs it shows based on whether `ingress.tls` is set, and warns if secure cookies are enabled without it.

### Manual setup (macOS/Linux/Windows)

Prefer running the backend/frontend directly on your machine instead of in containers, e.g. for faster iteration with hot reload, or to attach a debugger. Skip this section if you used Docker Compose above.

#### Prerequisites

**macOS (Homebrew)**

```bash
brew install postgresql@16 redis semgrep trivy gitleaks gosec python@3.12
brew services start postgresql@16
brew services start redis
```

Homebrew's bundled `redis.conf` references modules that aren't shipped; if redis fails to start, comment out the `loadmodule` lines under `/usr/local/etc/redis.conf`.

**Linux (Debian/Ubuntu, apt)**

```bash
sudo apt-get update
sudo apt-get install -y postgresql-16 redis-server python3.12 python3.12-venv
sudo systemctl start postgresql redis-server
# Semgrep/gosec aren't in apt; install via their own installers:
python3.12 -m pip install --user semgrep
go install github.com/securego/gosec/v2/cmd/gosec@latest   # requires Go
# Trivy and Gitleaks ship .deb packages; see their release pages for the
# current version, e.g.:
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
curl -sfL https://raw.githubusercontent.com/gitleaks/gitleaks/master/scripts/install.sh | sh -s -- -b /usr/local/bin
```

Package names/repos vary by distro (Fedora/RHEL: `dnf install postgresql16-server redis python3.12`, then `systemctl` the same way); the point is the same five tools as macOS, just via your distro's package manager plus each scanner's own installer where there's no distro package.

**Windows**

The scanner CLIs (Semgrep/Trivy/Gitleaks/gosec) are Linux/macOS-first tools with inconsistent native Windows support. **WSL2 is the recommended path**: install WSL2 with an Ubuntu distro, then follow the Linux instructions above entirely inside it (clone the repo into the WSL filesystem, not a Windows path, for usable I/O performance). Running natively on Windows without WSL2 is unsupported; use Docker Compose above instead if you'd rather not set up WSL2.

Create the database:

```bash
psql postgres -c "CREATE USER toleman WITH PASSWORD 'toleman' CREATEDB;"
psql postgres -c "CREATE DATABASE toleman OWNER toleman;"
```

#### Backend

```bash
cd backend
python3.12 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --port 8000
```

Optional, async/scheduled scans via Celery:

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

Private repos are cloned using whatever git credential helper is already configured locally (e.g. `gh auth setup-git`); set `GITHUB_TOKEN` in `.env` as an alternative.

#### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:3000, redirects to `/login`. Sign in with the seeded admin account (`ADMIN_EMAIL`/`ADMIN_PASSWORD` in backend `.env`, defaults to `admin@toleman.local` / `changeme123`, seeded on first backend startup). Change `ADMIN_PASSWORD` before any non-local use. All pages read live data from the backend API, no mock data.

Auth: pbkdf2-hashed password + hmac-signed session cookie (`app/core/security.py`), no external auth service. Route protection is `src/proxy.ts` (Next.js 16 renamed `middleware.ts` → `proxy.ts`).

## Development

### Database migrations (Alembic)

The backend's startup hook (`app/core/db.py:init_db`, called from `app/main.py`) runs `alembic upgrade head` automatically against `DATABASE_URL` every time it starts; both `uvicorn app.main:app` and the Docker Compose `backend` service. There's no separate manual migration step for the common case of running the app.

You only need to touch Alembic directly when you change `app/models/models.py`:

```bash
cd backend
alembic revision --autogenerate -m "describe the schema change"
```

Review the generated file under `alembic/versions/` before committing; autogenerate is a starting point, not a guarantee (it can miss things like column renames, which it sees as a drop+add). `alembic upgrade head` (or just starting the app) applies it. See `alembic/env.py` for how migrations read `DATABASE_URL` from `app.core.config.settings`, the same source the app itself uses, so they can never disagree about which DB they're pointed at.

### Pre-commit hooks

The repo ships a `.pre-commit-config.yaml` that runs gitleaks v8.21.2 against staged changes before every commit, mirroring the CI self-scan job. Install once per checkout with:

```bash
pip install pre-commit && pre-commit install
```

A gitleaks failure blocks the commit; run `git commit` with `SKIP=gitleaks` only when you have a deliberate reason.

## Architecture decisions made during build (deltas from the design doc)

- **Python driver**: `psycopg[binary]` (v3) instead of `psycopg2-binary`, no prebuilt wheel for `psycopg2` on Python 3.13+/3.14 yet.
- **pydantic pinned to 2.9.x**: `sqlmodel==0.0.22` breaks on pydantic ≥2.10 (`Field 'id' requires a type annotation`), a known upstream incompatibility.
- **Scan execution runs as a direct subprocess** for this MVP (no container isolation yet); matches the architecture review's noted blocker; must move to ephemeral containers before multi-tenant/mass-rollout use.

## License & Security

Apache License 2.0; see [LICENSE](LICENSE). Attribution for the bundled
third-party scanners is in [NOTICE](NOTICE).

To report a security vulnerability, see [SECURITY.md](SECURITY.md), please
don't open a public issue for one.
