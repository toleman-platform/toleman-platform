# Contributing to Toleman

Thanks for taking the time to contribute. Toleman is early (no tagged
release yet, `main` is the only line to track), so expect APIs and schema
to move; that also means there's a lot of room to shape the project.

By participating, you're expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

- **Security vulnerability?** Do not open a public issue. See
  [SECURITY.md](SECURITY.md) for private reporting.
- **Small fix (typo, broken link, obvious bug)?** Skip straight to a PR.
- **Bigger change (new feature, schema change, a new scanner integration,
  anything touching auth or secret storage)?** Open an issue first,
  describing the problem and your proposed approach, before writing code.
  This project is a security product; changes to trust boundaries get
  reviewed more carefully, and an early discussion saves you from a large
  diff that has to be reworked. Check [ROADMAP.md](ROADMAP.md) too — it
  may already record a decision on the approach.

## Development setup

Follow [README.md](README.md#getting-started) — either the Docker Compose
quickstart or the manual per-platform setup. That's the same setup used
locally and in CI, so if it works there it'll pass here.

The codebase has three independently-tested parts:

| Component | Stack | Path |
|---|---|---|
| Backend | FastAPI + Celery, Python 3.12 | `backend/` |
| Frontend | Next.js | `frontend/` |
| MCP server | Python, exposes Toleman to MCP clients | `mcp-server/` |

See [ARCHITECTURE.md](ARCHITECTURE.md) for how they fit together, and each
directory's own README (`frontend/README.md`, `mcp-server/README.md`) for
component-specific detail.

### Running the checks locally

These are exactly the jobs `.github/workflows/ci.yml` runs on every PR;
run them before pushing so CI isn't the first place a failure shows up.

**Backend** (needs Postgres and Redis reachable — `docker compose up postgres redis` works, or use whatever the manual setup gave you):

```bash
cd backend
python -m pytest -v
```

If you changed `backend/app/models/models.py`, generate a migration too:

```bash
alembic revision --autogenerate -m "describe the schema change"
```

Review the generated file under `alembic/versions/` before committing —
autogenerate is a starting point, not a guarantee (it misses things like
column renames, seeing them as a drop+add).

**Frontend**:

```bash
cd frontend
npm test                        # unit/component tests
npm run test:lint-rules         # the custom Server/Client Component ESLint rule
npm run lint -- --max-warnings=0
npm run build                   # also type-checks and generates Next.js route types
```

**MCP server**:

```bash
cd mcp-server
pip install -r requirements-dev.txt
python -m pytest -v
```

### Pre-commit hook

Install the gitleaks pre-commit hook once per checkout:

```bash
pip install pre-commit && pre-commit install
```

It scans staged changes for hardcoded secrets before every commit, using
the same gitleaks release as CI's self-scan job — so a secret caught
locally is caught in CI too, and vice versa. If it flags something in a
test fixture that's a deliberately fake credential, prefer restructuring
the fixture over `SKIP=gitleaks`; a real CI failure downstream is more
disruptive than fixing it now.

## Making the change

- Keep PRs focused. A refactor and a behavior change in the same PR are
  harder to review and to revert independently — split them.
- Match the existing style in the file you're touching rather than
  introducing a new convention; the frontend has a custom ESLint rule
  (`npm run test:lint-rules`) enforcing one such convention (Server
  Components can't import a value out of a `"use client"` module).
- Add or update tests for the behavior you're changing. A PR that changes
  behavior without a test covering it is the most common reason for
  review back-and-forth.
- Update `ARCHITECTURE.md` or the relevant README if the change affects
  how the system is put together, not just its internals.
- Don't commit real credentials, tokens, or API keys anywhere, including
  test fixtures and example configs — use obviously-fake values (the
  pre-commit hook and CI's `self-scan.yml` will otherwise catch it, but
  it's better not to write it in the first place).

## Commit messages and PR titles

This repo uses `type(scope): summary` for commit subjects and PR titles,
e.g. `fix(scanners): diagnose permanent clone failures instead of retrying
them` or `feat(pr-guardrail): scan only a PR's changed files, and say so`.
Common types: `feat`, `fix`, `docs`, `ci`, `chore`. The scope is whatever
area changed (`frontend`, `scanners`, `pr-guardrail`, `security`, etc.) and
can be omitted if nothing fits cleanly. Reference the issue you're closing
or the discussion that prompted the change where relevant.

## Submitting the PR

1. Push your branch and open a PR against `main`.
2. Fill in the PR template — what changed and why, and how you tested it.
3. CI (`ci.yml`) runs automatically. Note: GitHub does not expose repo
   secrets to workflows triggered by a fork PR, so some checks run with
   reduced capability on fork PRs by design — that's expected, not a
   setup problem on your end.
4. Address review feedback with new commits; no need to force-push or
   squash mid-review, that just makes the diff harder to re-review.
5. A maintainer merges once CI is green and review is resolved.

## License

By contributing, you agree that your contributions are licensed under the
Apache License 2.0 (see [LICENSE](LICENSE)), the same license as the rest
of the project.
