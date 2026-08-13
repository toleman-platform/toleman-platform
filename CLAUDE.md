# OSP Platform — AI Knowledge Transfer (KT)

Welcome to the OSP Platform project. You are an AI engineer assisting in the development of a 100% free, open-source DevSecOps vulnerability management platform. 

This document serves as your onboarding and knowledge transfer. Before starting any implementation, you must understand our strategic goals and read **`ARCHITECTURE.md`** — a token-cheap map of directory structure, backend routers, models, and established conventions (workspace scoping, secrets encryption, async task dispatch, the `TargetPicker` "all repos" pattern, etc.). Read it instead of re-discovering structure by grepping the whole tree on every task.

## 🎯 Project Vision & Strategy
OSP aims to be the "Grafana for Security"—a fully free, open-source platform that orchestrates best-of-breed OSS scanners (Semgrep, Trivy, Gitleaks, gosec) with a modern developer-first UI, intelligent deduplication, context-aware prioritization, and PR-level enforcement.

**Core Philosophy:** 
- **100% Free**: No paid tiers, no feature gating, no monetization. Every enterprise feature (SSO, RBAC, etc.) is free.
- **Operational vs Passive**: We don't just aggregate findings; we natively run scans, manage tools, and enforce block/alert modes in CI/CD pipelines.
- **Enterprise Polish**: The UI and experience must feel like a premium enterprise product (e.g., Datadog), not a weekend side project.

## 📚 Required Reading (The Backlog)
The source of truth for what needs to be built, fixed, and prioritized is **`ROADMAP.md`** (Sprint 1–10, each item linked to a GitHub issue) plus the GitHub Project board. **Whenever you are asked to "work on the next item" or "review the plan", read `ROADMAP.md` and the relevant issue(s) — not the raw historical reports.**

`code-review-report.md` and `market-research-report.md` (gitignored, not tracked in git) were the original inputs used to generate that backlog. They are historical raw material, not current status — many of their individual findings have since been verified, fixed, or in a few cases found to be **incorrect** (e.g. an early claim that `frontend/src/proxy.ts` should be renamed to `middleware.ts` was backwards — Next.js 16 deprecated `middleware.ts` in favor of `proxy.ts`; don't "fix" that). Don't re-derive priorities from the raw reports — `ROADMAP.md` and the issue tracker already did that triage, including discarding several hallucinated findings.

## 🛠 Tech Stack
- **Backend**: FastAPI (Python), SQLModel, PostgreSQL, Celery, Redis.
- **Frontend**: Next.js (App Router, TypeScript), TailwindCSS, Shadcn UI primitives, Recharts.
- **Scanners integrated**: Semgrep (SAST), Trivy (Container/SCA), Gitleaks (Secrets), gosec (Go).

## ⚙️ AI Engineering Workflow
When you are asked to implement a feature or fix a bug, adhere to the following workflow:

1. **Read `ARCHITECTURE.md` first**, then `ROADMAP.md` and the specific GitHub issue, to understand priority, exact requirements, and existing conventions before writing anything.
2. **Plan First**: Propose an implementation plan. Outline the specific files you will create/modify. Any schema change needs a real Alembic migration (`backend/alembic/`, in place since #58) — not a manual `ALTER TABLE`.
3. **Security First**: OSP is a security tool. Ensure no command injection, SQL injection, or IDOR is introduced. New GET/list endpoints over workspace-owned resources must use `accessible_workspace_ids()` (`backend/app/api/auth.py`) for tenant isolation.
4. **UX Consistency**: When working on the frontend, use existing Shadcn components from `frontend/src/components/ui/`. Ensure dark mode styling is maintained and accessibility (ARIA labels) is prioritized.
5. **No Placeholders**: Write complete, functional code. "No mock data" applies to verification too — live-test against real data/real HTTP calls wherever feasible, not just unit tests with mocks.

## 🚀 Current Status

Sprints 1–6 are complete (core platform, PR Guardrail, findings UX, coverage breadth, RBAC/compliance/GitHub multi-install, security & infra hardening). Sprint 7 (org structure & developer trust: repo groups/tags, PR history all-repo view, PR reference links, no-AI vulnerability descriptions) is in progress — see `ROADMAP.md` for the full sprint plan and issue numbers, and the GitHub Project board for live status.

*Note: Always confirm with the user before starting a major feature from the roadmap.*
