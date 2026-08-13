# OSP Platform — Architecture Map

A token-cheap reference for working on this repo. Read this instead of re-discovering structure/conventions by grepping the whole tree on every task. Keep it updated when you add a new router, model, established pattern, or top-level page — a stale map costs more tokens than none.

## Stack

Backend: FastAPI + SQLModel + PostgreSQL + Celery/Redis, Python 3.12 (pinned — 3.9 too old, 3.14 breaks `pydantic-core`/`psycopg` wheels).
Frontend: Next.js 16 (App Router) + TypeScript + Tailwind, dark-theme "Rikugan" design system.
Deployment: `docker-compose.yml` at repo root (postgres, redis, backend, celery-worker, frontend) — see `README.md` Quickstart.
Migrations: Alembic (`backend/alembic/`) — `init_db()` in `backend/app/core/db.py` runs `alembic upgrade head` on startup, not `create_all()`. **Any model change needs a real migration** (`alembic revision --autogenerate`, then hand-check it).

## Directory map

```
backend/app/
  api/        one file per resource, FastAPI router — see table below
  core/       shared logic: db engine, crypto, scoring, dedup, scanners' HTTP clients, Celery app
  models/     models.py — single file, every SQLModel table + enum (see Models below)
  scanners/   runner.py (subprocess dispatch), discovery.py (regex route extraction), parsers.py (tool output → Finding dicts)
  tasks/      Celery tasks — scan/discovery/sbom/pr_guardrail all run async via .delay()
backend/alembic/versions/   one file per migration, ordered by down_revision chain
backend/tests/    pytest, TestClient + sqlite in-memory (see Testing below)

frontend/src/app/(dashboard)/   one directory per sidebar page (route-mapped)
frontend/src/components/        shared non-page components (see Frontend components below)
frontend/src/components/ui/     shadcn-style primitives (Button, Card, Badge, Input, Label, Skeleton...)
frontend/src/lib/api.ts         single API client — every backend call + response type lives here
frontend/src/lib/poll.ts        shared polling helper for async job status (scan/discovery/sbom runs)
```

## Backend routers (`backend/app/api/*.py`)

| Router | Mount | Auth | Covers |
|---|---|---|---|
| `auth` | `/api/auth` | — | login/logout/me, session cookie issuance |
| `workspaces` | `/api/workspaces` | login (bootstrap: admin) | org/workspace creation, API key |
| `admin_workspace_roles` | `/api/admin/workspace-roles` | admin | assign `WorkspaceMembership` |
| `targets` | `/api/targets` | login, workspace-scoped reads | repo CRUD |
| `findings` | `/api/findings` | login, workspace-scoped reads | list/triage/history/bulk-triage |
| `scans` | `/api/scans` | login | trigger scan (async via Celery), poll status |
| `discovery` | `/api/discovery` | login | API-route discovery (async), persisted + org-wide aggregate |
| `sbom` | `/api/sbom` | login | SBOM generation (async), per-target + org-wide + export |
| `pr_guardrail` | `/api/pr-guardrail` | login | diff scan, ignore/approval workflow |
| `github` / `github_app` | `/api/github*` | login (some public for GH callbacks) | activity, App manifest flow, multi-install |
| `webhooks` | `/api/webhooks` | HMAC signature, not session | GitHub webhook deliveries |
| `ai` | `/api/ai` | login | remediation analysis — Anthropic or OpenAI-compatible provider |
| `config` | `/api/config` | admin | `PlatformConfig` (AI provider, keys — encrypted) |
| `reports` | `/api/reports` | login | compliance posture export (CSV/PDF) |
| `admin` | `/api/admin` | admin | user CRUD |
| `policies` | `/api/policies` | admin | policy-as-code rules |
| `tools` | `/api/tools` | login | scanner health check |
| `audit` | `/api/audit` | login | audit log |
| `search` | `/api/search` | login | global search |
| `ingest` | `/api/ingest` | Workspace API key (not session) | external CI/CD push |

Registration pattern in `backend/app/main.py`: `login_required`/`admin_required` are `Depends(...)` lists applied per-router via `app.include_router(x.router, dependencies=...)`, not per-route. Look there first when adding a new router.

## Models (`backend/app/models/models.py`)

Single file, ~380 lines, every table + enum. Key relationships:
- `Organization` → `Workspace` → `Target` (a scanned repo) → `Finding`/`Scan`/`ApiEndpoint`/`SbomComponent`
- `User` has a **global** `UserRole` (admin/user/viewer/developer/security_engineer) — admins bypass all workspace scoping
- `WorkspaceMembership` (user_id, workspace_id, `WorkspaceRole`) — **workspace-scoped** role, layered on top of the global role, added in #32. Non-admin visibility on GET/list endpoints is filtered by this (via `accessible_workspace_ids()` in `backend/app/api/auth.py`, added in #57)
- `PRGuardrailScan` → `PRGuardrailFinding` (net-new-only findings from a diff scan, separate from the main `Finding` table so PR-branch noise doesn't pollute default-branch posture)
- `DiscoveryRun`/`SbomRun` — async job tracking rows (status/error/count), added in #59 when scan/discovery/sbom moved off the request thread onto Celery
- `GitHubAppConfig` (potentially multiple, one per App) → `GitHubInstallation` (FK to the App that minted it) — multi-App/multi-install support added in #34, this used to be assumed single-row

## Established patterns (read before reinventing)

- **Workspace-scoped reads**: `accessible_workspace_ids(session, user)` in `backend/app/api/auth.py` — returns `None` for admins (no filter), else the caller's `WorkspaceMembership` workspace ids. Apply to every new GET/list endpoint that returns workspace-owned resources.
- **Secrets at rest**: `encrypt_secret()`/`decrypt_secret()` in `backend/app/core/crypto.py` (Fernet, key from `PLATFORM_ENCRYPTION_KEY`). Used for GitHub App secrets and the OpenAI-compatible provider key. Note: `PlatformConfig.anthropic_api_key` is a pre-existing plaintext exception, left alone — don't copy that, encrypt new secret fields.
- **Async long-running work**: don't run `git clone` + scanner subprocess synchronously in a request handler. Dispatch a Celery task (see `backend/app/tasks/`), create a tracking row (`Scan`/`DiscoveryRun`/`SbomRun`) with `status="running"`, return 202 immediately, poll via a GET endpoint. Frontend uses `frontend/src/lib/poll.ts`.
- **git clone safety**: `clone_repo()` in `backend/app/scanners/runner.py` validates `repo_url` (https + github.com host only), uses `--` before the positional URL arg, and delivers the GitHub token via `http.extraHeader` env vars — never embed a token in a URL or pass one where a `CalledProcessError` could leak it into a response.
- **"All repos" dropdown option**: `TargetPicker`'s `allowAll` prop + `ALL_TARGETS` sentinel (`frontend/src/components/target-picker.tsx`) — one dropdown with a 0-value "All repositories" entry, not a separate tab/toggle. Established for SBOM, reused for reports.
- **Persisted-scan pattern**: `POST` triggers a real (now async) scan and upserts results; `GET` reads persisted state without re-scanning. Net-new items get an `is_new`/`first_seen`/`last_seen` treatment (see `upsert_endpoints()`/`upsert_components()` — extracted to `backend/app/core/discovery_ingestion.py`/`sbom_ingestion.py` to avoid an api↔tasks import cycle).
- **Dedup**: `compute_dedup_hash()` in `backend/app/core/dedup.py` — fingerprints on `(rule_id, file_path, tool, normalized_snippet)`, survives line-shift refactors. `file_path` must be normalized (relative to repo root, not the scan-scoped clone dir) via `normalize_file_path()` in `runner.py` before hashing, or dedup silently breaks.
- **Priority scoring**: `backend/app/core/scoring.py` — `severity_weight × criticality_weight × 40`, boosted by real-time EPSS (`core/epss.py`) and CISA KEV (`core/kev.py`, cached 1hr) lookups.
- **Downloadable exports**: `Content-Disposition: attachment` header pattern, see `sbom.py`'s `/export`/`org/export` and `reports.py` — frontend downloads via `fetch(..., {credentials:"include"})` → blob → `URL.createObjectURL` → synthetic `<a>` click (see `exportSbom`/`exportOrgSbom` in `frontend/src/lib/api.ts`).
- **Admin page tabs**: `frontend/src/app/(dashboard)/admin/page.tsx` — a `TABS` array + one component file per tab in the same directory (`user-management.tsx`, `workspace-roles.tsx`, `global-integrations.tsx`, `tools-health.tsx`, `policies.tsx`, `approval-queue.tsx`). Add a new tab by adding one entry + one file, not by editing the others.

## Frontend components (`frontend/src/components/*.tsx`, non-`ui/`)

`target-picker.tsx` (repo selector, `allowAll` pattern), `findings-list.tsx`/`finding-row.tsx`/`findings-filter-bar.tsx` (the Findings/Vulnerabilities table stack, reused inside SBOM's OSS-vuln tab too), `pr-guardrail-log.tsx`/`pr-scan-action.tsx` (PR diff-scan UI), `connect-github-card.tsx` (GitHub App connect flow, per-App sections since #34), `global-search.tsx`, `sidebar.tsx` (nav — add new pages here).

## Testing (`backend/tests/`)

FastAPI `TestClient` + SQLite in-memory via `StaticPool`, override `get_session`. Login via `create_session_token()` + `client.cookies.set("osp_session", token)` — see `test_workspace_roles.py`/`test_pr_guardrail_ignore.py` for the reference pattern (fixtures: `engine`, `client`, a `_login(client, engine, role=...)` helper). Async/Celery-task tests use `task_always_eager` (see `test_celery_offload.py`) rather than a real running worker.

## Workflow notes for background agents working this repo

- Always `git fetch origin main` and branch from current `origin/main` HEAD before starting — this project has repeatedly hit bugs from stale-base agents.
- No Alembic before #58; if you're reading old context/history that mentions manual `ALTER TABLE`/`ALTER TYPE` against the live dev DB, that's no longer the right approach — write a real migration instead.
- If you do live-verification writes against the shared dev Postgres (creating real tables/rows to prove something works), say exactly what you created in your final report — merges have repeatedly needed to reconcile schema that existed on the DB but wasn't yet stamped in Alembic's `alembic_version`.
- Live-verify with real data wherever feasible (real clone, real scan, real HTTP calls) — "no mock data" is enforced throughout this project, including in how work gets verified, not just what ships.
