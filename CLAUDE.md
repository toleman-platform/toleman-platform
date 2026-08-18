# Rikugan Platform — AI Knowledge Transfer (KT)

Welcome to the Rikugan Platform project. You are an AI engineer assisting in the development of a 100% free, open-source DevSecOps vulnerability management platform. 

This document serves as your onboarding and knowledge transfer. Before starting any implementation, you must understand our strategic goals and read **`ARCHITECTURE.md`** — a token-cheap map of directory structure, backend routers, models, and established conventions (workspace scoping, secrets encryption, async task dispatch, the `TargetPicker` "all repos" pattern, etc.). Read it instead of re-discovering structure by grepping the whole tree on every task.

## 🎯 Project Vision & Strategy
Rikugan aims to be the "Grafana for Security"—a fully free, open-source platform that orchestrates best-of-breed OSS scanners (Semgrep, Trivy, Gitleaks, gosec) with a modern developer-first UI, intelligent deduplication, context-aware prioritization, and PR-level enforcement.

**Core Philosophy:** 
- **100% Free**: No paid tiers, no feature gating, no monetization. Every enterprise feature (SSO, RBAC, etc.) is free.
- **Operational vs Passive**: We don't just aggregate findings; we natively run scans, manage tools, and enforce block/alert modes in CI/CD pipelines.
- **Enterprise Polish**: The UI and experience must feel like a premium enterprise product (e.g., Datadog), not a weekend side project.

## 📚 Required Reading (The Backlog)
The source of truth for what needs to be built, fixed, and prioritized is **`ROADMAP.md`** (Sprints 1–21 and counting, each item linked to a GitHub issue) plus the GitHub Project board. **Whenever you are asked to "work on the next item" or "review the plan", read `ROADMAP.md` and the relevant issue(s) — not the raw historical reports.**

`ROADMAP.md` also carries an **"Explicitly not planned"** section. Treat it as binding: it is where deliberate declines live (e.g. SSO/SAML, #113, closed as *not planned* — declining paid-tier parity is a product-direction decision, not an oversight). If a request conflicts with a line there, raise the conflict before building; don't quietly implement past it.

`code-review-report.md` and `market-research-report.md` (gitignored, not tracked in git) were the original inputs used to generate that backlog. They are historical raw material, not current status — many of their individual findings have since been verified, fixed, or in a few cases found to be **incorrect** (e.g. an early claim that `frontend/src/proxy.ts` should be renamed to `middleware.ts` was backwards — Next.js 16 deprecated `middleware.ts` in favor of `proxy.ts`; don't "fix" that). Don't re-derive priorities from the raw reports — `ROADMAP.md` and the issue tracker already did that triage, including discarding several hallucinated findings.

## 🛠 Tech Stack
- **Backend**: FastAPI (Python), SQLModel, PostgreSQL, Celery, Redis.
- **Frontend**: Next.js (App Router, TypeScript), TailwindCSS, Shadcn UI primitives, Recharts.
- **Scanners integrated** (`TOOL_COMMANDS` in `backend/app/scanners/runner.py` is the authoritative list): Semgrep (SAST), `semgrep-llm` (OWASP LLM Top 10 code patterns), Trivy + `trivy-license` + `trivy-sbom` (container/SCA/licence/SBOM), Gitleaks (secrets), gosec (Go), Checkov and tfsec (IaC), modelscan (unsafe model-file deserialization).
- **Tool Marketplace** carries a wider *catalog* than the wired set above — a tool being listed there does not mean it executes. `garak` is the standing example: catalogued for visibility, deliberately not wired (it needs a live model endpoint, not a repo checkout). Never present a catalogued-but-unwired tool as if it scans.

## ⚙️ AI Engineering Workflow
When you are asked to implement a feature or fix a bug, adhere to the following workflow:

1. **Read `ARCHITECTURE.md` first**, then `ROADMAP.md` and the specific GitHub issue, to understand priority, exact requirements, and existing conventions before writing anything.
2. **Plan First**: Propose an implementation plan. Outline the specific files you will create/modify. Any schema change needs a real Alembic migration (`backend/alembic/`, in place since #58) — not a manual `ALTER TABLE`.
3. **Security First**: Rikugan is a security tool. Ensure no command injection, SQL injection, or IDOR is introduced. New GET/list endpoints over workspace-owned resources must use `accessible_workspace_ids()` (`backend/app/api/auth.py`) for tenant isolation.
4. **UX Consistency**: When working on the frontend, use existing Shadcn components from `frontend/src/components/ui/`. Ensure dark mode styling is maintained and accessibility (ARIA labels) is prioritized.
5. **No Placeholders**: Write complete, functional code. "No mock data" applies to verification too — live-test against real data/real HTTP calls wherever feasible, not just unit tests with mocks.

## 🚀 Current Status

Sprints 1–21 have shipped. Beyond the original core platform, PR Guardrail, findings UX, RBAC/compliance and infra hardening, that now includes: the design-system/light-dark revamp (Sprints 11–15), public surfaces (Sprint 16 — public API with personal access tokens, standalone MCP server, SIEM export), UI polish (17), supply-chain malware + SAST engine (18), AI/LLM repo security coverage (19), scan feedback (20), and deployability/tool lifecycle (21). See `ROADMAP.md` for the per-sprint issue list and the reasoning behind each, and the GitHub Project board for live status.

### Things that surprise people returning to this repo

- **Navigation was restructured** (PR #224). `/admin` is now **"Control Plane"** and holds only Access + Tooling. Scan-policy config moved to a top-level **`/guardrails`** (Repo Groups, SLA Rules, Workflow Templates, FP Rules, Policies). **`/approval-queue`**, **`/workspaces`**, and **`/ai-security`** are their own routes. "AI Analysis" was renamed **"Explain with AI"** so it doesn't collide with AI Security (AI/ML repo scanning). Sidebar groups (`Overview / Discover / Scan / Triage / Report / Operate`) are deliberate — don't rename them casually.
- **The onboarding module was removed entirely** (frontend pages, backend router, `OnboardingProfile` model, plus a real drop migration). A fresh login goes straight to the dashboard. Don't reintroduce a wizard without asking.
- **The dark theme is intentionally neutral charcoal**, not shadcn's stock blue-slate. That palette was the specific thing a user complained made the app look AI-scaffolded. Color belongs to the brand accent and severity states only — don't reintroduce blue-tinted surfaces. Light theme was deliberately left on its original palette.
- **Docs live in a separate repo**: `geekshiv/rikugan-docs`, deployed at `geekshiv.github.io/rikugan-docs`. An in-repo Docusaurus site existed briefly and was removed on purpose (GitHub Pages via Actions needs a public repo on the free plan, and two copies would drift). Don't re-add a docs site here.
- **The MCP server is a standalone process** under `./mcp-server`, with its own CI workflow — not part of the FastAPI app.
- **`PLATFORM_ENCRYPTION_KEY` must be set** in the root `.env` (gitignored). If it is empty, `backend/app/core/crypto.py` mints a fresh key per process start, which permanently orphans every previously-encrypted secret (GitHub App private key, client secret, webhook secret) on each restart. Generate one with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.

*Note: Always confirm with the user before starting a major feature from the roadmap.*
