# Roadmap

Synthesized from a 4-lens review (Principal Architect, Lead PM, Security, Design) of the codebase as of 2026-08-12. Goal per product direction: not a literal Snyk clone, but comprehensive OSS DevSecOps management covering most of Snyk's feature surface. 2-week sprints, each independently shippable.

## Sprint 1 — Trust & Safety Foundation (in progress)

The platform is a security tool; it has to hold itself to a high bar before anything else matters.

- **Scan execution isolation & concurrency safety** (`backend/app/scanners/runner.py`) — workdir is keyed only by repo name and gets `rmtree`'d/recloned; concurrent scans of the same target race and corrupt each other's checkout. Move to per-scan random workdir.
- **Secrets encryption at rest** — `GitHubAppConfig.private_key_pem`/`client_secret`/`webhook_secret` are plaintext columns in Postgres. Encrypt with a Fernet key sourced from an env secret.
- **Session hardening** — cookie has no `secure` flag path and no revocation (logout only clears the client cookie; a leaked token stays valid 7 days). Add a `token_version` column bumped on logout/password change.
- **DB indices** — `Finding.target_id`/`state`/`branch`/`priority_score` (sorted on every list call) and `Scan.target_id` are unindexed; findings/dashboard queries degenerate past tens of thousands of rows.
- **Celery retry policy** — `scan_tasks.run_scan` has no `autoretry_for`/backoff; transient clone/network failures become permanent failures.
- **Rate limiting** — auth/scan-trigger/ingest endpoints are unthrottled.

## Sprint 2 — PR Guardrail (the actual product wedge)

Per the architecture doc, this was always meant to be the core differentiator ("severity × context × exploitability, enforced at PR time") but Flow C was never built — PR History currently just lists PRs with `scan_status: "not scanned"`. Per PM review, this is the single highest-leverage feature: it's what makes a developer see the tool without opening a dashboard.

- Diff-only scan: on a PR event (or on-demand trigger), scan the feature branch, diff against default-branch findings, surface only net-new vulnerabilities.
- Post a PR comment (via installed GitHub App) summarizing new findings.
- Set a commit status (pass/fail) to block/allow merge.
- PR Audit & Discovery Log view: AppSec override/accept-risk action, wired to the existing triage state machine.

## Sprint 3 — Findings UX (currently the weakest surface for daily use)

- Filter/search/sort bar on Findings and Vulnerabilities (severity, tool, state, target) — currently an unfiltered `.map()`.
- Bulk triage (select multiple findings → one triage action).
- Severity-first visual hierarchy (color-coded left border/icon, not a same-weight badge).
- Pagination on Findings/Audit Log/GitHub Org Logs/PR History (currently unbounded).
- Skeleton loading states instead of bare "Loading..." text.
- Global search across findings/targets from the sidebar.

## Sprint 4 — Coverage breadth (closing the gap to Snyk's feature surface)

- SBOM + license scanning — Trivy is only invoked in `fs` vuln mode; its native SBOM/license output is unused.
- Policy-as-code — severity/CVSS/license thresholds for PR blocking, org-level suppression rules (today triage is per-finding only).
- Guided onboarding wizard (replace curl-based bootstrap with connect-repo → first-scan → first-finding flow).
- EPSS/KEV exploitability surfaced in the UI (backend already computes it in `scoring.py`, verify it's actually rendered).

## Sprint 5 — Scale & enterprise readiness

- **#32** RBAC with workspace/project-scoped roles (today it's global admin/user/viewer only).
- **#33** Compliance/report export (PDF/CSV posture reports).
- **#34** Full GitHub App OAuth polish (multi-install support — `GitHubAppConfig` is explicitly single-row/single-tenant today).
- ~~Mass CI/CD Rollout Engine + Custom Workflow Builder~~ — **#35 moved to after Sprint 8**: it naturally builds on the single-repo pipeline-integration mechanism (#66), which doesn't exist until Sprint 8. Building the "mass rollout" wrapper before the thing it rolls out would be speculative.

## Sprint 6 — Security & Platform Hardening (#54–60)

Surfaced by a code-review pass against the live codebase (verified against actual source, not assumed — several other claims from the same review turned out to be false and were discarded). This is foundational: must land before Sprint 8's pipeline integration adds more surface area to secure.

- **#54** Git-clone argument injection + GitHub token leakage in `runner.py` (missing `--` separator/host allowlist; token embedded in clone URL leaks via exception messages).
- **#55** Enforce non-default `SESSION_SECRET`/`ADMIN_PASSWORD` — fail-fast or loud warning outside local dev.
- **#56** Gate `POST /api/workspaces/bootstrap` to admin (currently any logged-in user).
- **#57** Workspace-scoped filtering on findings/targets queries (IDOR) — ties into Sprint 5's RBAC work (#32).
- **#58** Adopt Alembic for schema migrations (replace `create_all()` — every schema change so far has required a manual `ALTER TABLE`/`ALTER TYPE` against the live DB).
- **#59** Offload scan/discovery/SBOM execution to Celery (currently synchronous in the request handler; threadpool exhaustion risk under concurrent scans).
- **#60** Docker Compose deployment (backend, frontend, Postgres, Redis, Celery worker) — biggest adoption blocker per both reviews.

## Sprint 7 — Org Structure & Developer Trust (#61, #64, #65, #71)

Low-effort, high-value items plus the repo-grouping foundation Sprint 8/9 build on.

- **#61** Custom repo groups/tags (many-to-many `Group`/`TargetGroup`) — prerequisite for #62 and #70.
- **#64** PR History: "All repos" aggregate view (reuse the `ALL_TARGETS` dropdown pattern already shipped for SBOM).
- **#65** PR Guardrail scan log: link back to the originating GitHub PR.
- **#71** Detailed vulnerability descriptions from CWE/NVD/OWASP/OSV.dev — explicitly no AI required, for developer trust when no AI provider is configured.

## Sprint 8 — Pipeline Integration & Enforcement (#66, #68, #62, #70)

The "operational, not just a dashboard" story — founder's highest-priority manual-review finding.

- **#66** Pipeline integration button (generate CI YAML, open a PR to the target repo, track integration status).
- **#68** Bulk pipeline onboarding — multi-select in Repo Sync, depends on #66.
- **#62** Block mode vs alert mode per repo/group/org with inheritance (workspace → group → target).
- **#70** SLA configuration by severity × group, depends on #61.

## Sprint 9 — Executive & Ops Surfaces (#63, #69, #73, #74)

- **#63** Security score (org/group/repo composite, gauge chart) — the metric a CISO buys into.
- **#69** Configurable dashboard (widget library, per-user layout, CVE timeline).
- **#73** User profile (password/name) + notification preferences (email/Slack on critical/KEV/SLA-breach).
- **#74** Slack & Jira integration in Admin settings, encrypted config + test-connection — delivery channel for #73.

## Sprint 10 — Platform Differentiation (#75, #72, #76, #35)

The largest, highest-effort items — the features that make Rikugan more than a free Snyk clone.

- **#75** Tool marketplace / health page (registry, install-from-UI, per-tool usage assignment, IaC tools).
- **#72** Active API scanning against discovered endpoints (Nuclei/ZAP integration).
- **#76** False positive learning engine (cross-repo suppression rules, auto-suppress on ingestion).
- **#35** Mass CI/CD Rollout Engine + Custom Workflow Builder (moved from Sprint 5 — depends on #66's single-repo pipeline mechanism from Sprint 8).

## Sprint 11 — Design System Foundation (#115)

Blocker for every sprint below — the light/dark token system every other redesign issue builds against. Land and merge alone before dispatching Sprint 12+; every other frontend issue building against the old hardcoded colors first just means redoing it once this lands.

- **#115** Light/dark theme tokens + toggle. Real values (not auto-inverted) from the published design board: https://claude.ai/code/artifact/48eb6411-7e34-4a7d-83f0-024000bdcef4 — see issue comment for a concrete pitfall already found in the design artifact itself (partially-themed components: one CSS property tokenized, a sibling property still hardcoded — invisible until you actually toggle themes).

## Sprint 12 — Shell & Shared Components (depends on #115)

Establishes the components other sprints consume: #117's criticality-chip/tooltip/risk-score pattern (needed by #119, #120, #125) and #116's branding wordmark (needed by #124, #131).

- **#116** Global shell: sidebar IA regroup, responsive/collapse strategy, branding wordmark.
- **#117** Findings page polish: truncation tooltips, labeled risk score, Prod/Internal/Dev criticality chips.
- **#118** Admin: grouped sub-navigation (fixes a real tab-strip scroll-clip bug), destructive-action confirmation dialogs, duplicate-workspace disambiguation.

## Sprint 13 — Consumers of Sprint 12's components (depends on #116 + #117)

- **#119** Dashboard: fix the duplicate-row bug, reuse #117's tooltip fix.
- **#120** Scans page rebuild: search/filter/multi-select, reuses #117's criticality chips, Prod-aware confirmation modal.
- **#125** Targets: separate integration config from inventory list, reuses #117's criticality chips.
- **#124** Login: remove hardcoded admin-email placeholder, apply #116's wordmark.
- **#131** Onboarding: light-touch pass applying #116's wordmark.
- **#130** Settings: grouped section-nav matching #118's pattern.

## Sprint 14 — Reporting & Activity Surfaces (depends on #115 only — can run parallel to Sprint 12/13)

- **#121** Shared "generate a document" pattern across SBOM, API Discovery, PR History, Reports — plus export-format parity and a real PR History error state.
- **#122** AI Analysis: real entry point (finding selector / recent-analyses list) — currently a dead end.
- **#123** Audit Log + GitHub Org Logs: shared filter/pagination pattern, bulk-action grouping (a real data-layer fix, not just visual), QA-disclaimer copy rewrite.

## Sprint 15 — Independent fixes (no dependency on #115 or any other sprint — can run anytime, good parallel filler)

- **#126** Branded 404 page.
- **#127** GitHub PR comment redesign (markdown/GFM, not component-library — severity table, collapsible sections) + a real functional bug fix: `post_pr_comment()` always posts a new comment instead of updating in place, spamming PR threads on every rescan.
- **#128** Fix: expired/revoked session renders a broken authenticated shell instead of redirecting to login.
- **#129** Fix: workspace API key shown in cleartext with no mask/reveal/rotate UX.

## Explicitly not planned

- Feature-parity chase with Snyk's paid/enterprise tiers (SSO/SAML, sales-led compliance packages) — out of scope per product direction; this stays a comprehensive **open-source** DevSecOps management UI, not a SaaS competitor.
