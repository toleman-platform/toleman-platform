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

- RBAC with workspace/project-scoped roles (today it's global admin/user/viewer only).
- Compliance/report export (PDF/CSV posture reports).
- Full GitHub App OAuth polish (multi-install support — `GitHubAppConfig` is explicitly single-row/single-tenant today).
- Mass CI/CD Rollout Engine + Custom Workflow Builder (deferred from the original architecture doc's v2.1, still deferred).

## Explicitly not planned

- Feature-parity chase with Snyk's paid/enterprise tiers (SSO/SAML, sales-led compliance packages) — out of scope per product direction; this stays a comprehensive **open-source** DevSecOps management UI, not a SaaS competitor.
