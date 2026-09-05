# Toleman

**Open-source DevSecOps vulnerability management.** FastAPI + Celery backend, Next.js frontend, native execution of Semgrep/Trivy/Gitleaks/gosec and more, OSV.dev malicious-package detection, a dedup engine, two-tier priority scoring, and a triage state machine — no paid tiers, no feature gating.

[![CI](https://github.com/toleman-platform/toleman-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/toleman-platform/toleman-platform/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-geekshiv.github.io%2Ftoleman-blue)](https://geekshiv.github.io/toleman)

> **Status: active development.** No tagged release yet; `main` is the only
> line to track. APIs, schema, and config vars can change without notice.
> Expect rough edges; file issues for what you hit.

See the [architecture](ARCHITECTURE.md) for the full design. Full docs, including feature-by-feature guides, live at **[geekshiv.github.io/toleman](https://geekshiv.github.io/toleman)** (source: [geekshiv/toleman](https://github.com/geekshiv/toleman)) — this README covers getting a copy running and developing on it.

---

## Contents

- [Getting Started](#getting-started)
  - [Quickstart (Docker Compose)](#quickstart-docker-compose)
  - [Manual setup (macOS/Linux/Windows)](#manual-setup-macoslinuxwindows)
- [Upgrading](#upgrading)
- [Development](#development)
  - [Database migrations (Alembic)](#database-migrations-alembic)
  - [Backups and zero data loss during upgrades](#backups-and-zero-data-loss-during-upgrades)
  - [Pre-commit hooks](#pre-commit-hooks)
- [Architecture decisions made during build](#architecture-decisions-made-during-build-deltas-from-the-design-doc)
- [Contributing](#contributing)
- [License & Security](#license--security)

---

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

## Upgrading

Which path applies depends on how you're running Toleman, not on what changed upstream: both paths pick up every change, the only difference is who builds the image.

**Running from prebuilt GHCR images** (the `docker-compose.ghcr.yml` override above): pull the new tag and recreate the containers.

```bash
docker compose -f docker-compose.yml -f docker-compose.ghcr.yml pull
docker compose -f docker-compose.yml -f docker-compose.ghcr.yml up -d
```

If you pinned a version or `sha-` tag in your override (recommended for anything but a throwaway environment), bump it there first; `edge` and `latest` re-resolve to the newest image on `pull` without an edit.

**Building from source** (the default `docker compose up --build`): pull the new commit and rebuild.

```bash
git pull
docker compose up --build -d
```

Either way, no separate migration step: `backend`'s startup hook runs `alembic upgrade head` against `DATABASE_URL` before it starts serving (see [Database migrations](#database-migrations-alembic)), and `celery-worker` waits for `backend`'s healthcheck before it starts, so it never runs against a schema older than what it expects. Compose recreates only the services whose image or config actually changed, so `postgres` and `redis` keep running (and keep their data) through an upgrade of `backend`/`celery-worker`/`frontend`.

There's no rollback tooling beyond re-pointing at the previous tag/commit and re-running the same command, and that alone does **not** undo a schema change already applied by a migration that ran forward: `alembic upgrade head` only applies pending upgrades, so an older image can fail its startup migration because it can no longer locate the revision the database is recorded at. An older application image is unsupported until the schema is restored from a backup taken before the upgrade, or the migration is proven backward-compatible; see [Backups and zero data loss during upgrades](#backups-and-zero-data-loss-during-upgrades) for the tested restore procedure. No tagged release has shipped yet, so there's no cross-version upgrade to test against — this section will grow real "upgrading from 1.x to 2.x" notes once one exists.

---

## Development

### Database migrations (Alembic)

The backend's startup hook (`app/core/db.py:init_db`, called from `app/main.py`) runs `alembic upgrade head` automatically against `DATABASE_URL` every time it starts; both `uvicorn app.main:app` and the Docker Compose `backend` service. There's no separate manual migration step for the common case of running the app.

You only need to touch Alembic directly when you change `app/models/models.py`:

```bash
cd backend
alembic revision --autogenerate -m "describe the schema change"
```

Review the generated file under `alembic/versions/` before committing; autogenerate is a starting point, not a guarantee (it can miss things like column renames, which it sees as a drop+add). `alembic upgrade head` (or just starting the app) applies it. See `alembic/env.py` for how migrations read `DATABASE_URL` from `app.core.config.settings`, the same source the app itself uses, so they can never disagree about which DB they're pointed at.

### Backups and zero data loss during upgrades

An Alembic migration is not guaranteed reversible: some in `backend/alembic/versions/` are, by their own name, destructive (e.g. `drop onboarding profile`). Rolling an upgrade back by re-pointing at the previous image tag or commit does **not** undo a schema change already applied to the running database, since migrations run forward automatically on every backend startup (see above). The only real zero-data-loss guarantee is a backup taken immediately before the upgrade runs.

For the Docker Compose deployment:

```bash
./scripts/backup-postgres.sh                 # writes ./backups/toleman-<db>-<timestamp>-<unique>.sql.gz
docker compose pull && docker compose up -d  # or `docker compose up --build -d`
```

If something goes wrong, restore the backup taken just before the upgrade:

```bash
./scripts/restore-postgres.sh backups/toleman-osp-20260101T000000Z-a1B2c3.sql.gz
```

`restore-postgres.sh` validates the backup file, asks for confirmation, then stops `backend`/`celery-worker` before restoring (they hold open connections, and the backend's own startup hook runs `alembic upgrade head` against this same database, either of which can interleave with a restore in progress) and runs the restore itself in a single transaction that aborts on the first error (`psql -v ON_ERROR_STOP=on --single-transaction`), so a bad restore rolls back cleanly instead of leaving a half-applied mix of old and new state. It leaves both services stopped afterward; start them (`docker compose up -d backend celery-worker`) once you're sure the schema the restored data expects matches what's about to run.

For a Kubernetes deployment (`charts/toleman`), the equivalent is `kubectl exec` into the postgres Pod with the same `pg_dump`/`psql` invocations the scripts above use; there's no in-cluster backup CronJob yet (tracked as a follow-up), so back up before every Helm upgrade the same way.

Postgres's data itself already survives a `docker compose down` (no `-v`) or a Pod restart via the named volume/PVC; these scripts are for the case a completed migration needs to be undone, not for routine restarts.

### Pre-commit hooks

The repo ships a `.pre-commit-config.yaml` that runs gitleaks v8.21.2 against staged changes before every commit, mirroring the CI self-scan job. Install once per checkout with:

```bash
pip install pre-commit && pre-commit install
```

A gitleaks failure blocks the commit; run `git commit` with `SKIP=gitleaks` only when you have a deliberate reason.

---

## Architecture decisions made during build (deltas from the design doc)

- **Python driver**: `psycopg[binary]` (v3) instead of `psycopg2-binary`, no prebuilt wheel for `psycopg2` on Python 3.13+/3.14 yet.
- **pydantic pinned to 2.9.x**: `sqlmodel==0.0.22` breaks on pydantic ≥2.10 (`Field 'id' requires a type annotation`), a known upstream incompatibility.
- **Scan execution runs as a direct subprocess** for this MVP (no container isolation yet); matches the architecture review's noted blocker; must move to ephemeral containers before multi-tenant/mass-rollout use.

---

## Contributing

Bug reports, feature requests, and PRs are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow, how to run
the same checks CI runs, and commit/PR conventions, and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community standards.

---

## License & Security

Apache License 2.0; see [LICENSE](LICENSE). Attribution for the bundled
third-party scanners is in [NOTICE](NOTICE).

To report a security vulnerability, see [SECURITY.md](SECURITY.md), please
don't open a public issue for one.
