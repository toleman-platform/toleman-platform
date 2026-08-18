# Knowledge Transfer — Nav/IA Revamp Session (2026-08-17 → 2026-08-18)

This document captures everything discussed, decided, and delivered in the session that produced [PR #224](https://github.com/geekshiv/rikugan-platform/pull/224) (merged to `main` as commit `9095dd9`). It exists so a reader who wasn't in the conversation — human or AI — can pick up exactly where it left off, understand every decision's reasoning, and know what's still outstanding.

## 1. How this session started

The session opened with two requests that were explicitly **declined or dropped**, for the record:

- **"Rebuild using clean architecture principles"** — declined. A full architectural rewrite of a live app was judged too risky relative to the value; the user agreed and chose to continue incrementally, the same discipline as the prior 4 PRs in this repo's history.
- **"Register Rikugan on the GitHub Marketplace"** — investigated and dropped by the user. Findings for the record: Marketplace listing does **not** remove GitHub Actions' requirement for a workflow file in each consuming repo (a common misconception), and PR comments already post under the "Rikugan" GitHub App identity regardless of Marketplace listing status. Nothing was built here; this thread was closed by the user with "let's drop this for now."

The actual work that shipped came from a **UI/UX quality complaint**: "the bluish theme of dark is seen in every vibecoded app" plus "the amount of data and action we have is not accommodated properly." The user asked for the design to be benchmarked against **Wiz and Snyk** specifically, named as the SaaS products to draw inspiration from.

### Tooling set up for this (informational, not part of the shipped diff)

At the user's request, three things were evaluated/installed for future design work:
- **Taste skill** and **Vercel Web Design Guidelines skill** — installed. Taste skill's own documentation scopes it to "landing pages, portfolios, and redesigns — not dashboards, not data tables, not multi-step product UI," which was flagged to the user as a mismatch for Rikugan (a dashboard) before installing anyway.
- **21st.dev "Magic" MCP** — installed via `claude mcp add magic --env TWENTY_FIRST_API_KEY=<key> -- npx -y @21st-dev/magic@latest`. Note for future reference: the correct env var is `TWENTY_FIRST_API_KEY` (or `API_KEY` / `API_KEY_21ST`) — **not** `TWENTYFIRST_API_KEY`, which is what the user first tried and which fails silently with a connection error.
- A "full design system skill" and Playwright CLI were **declined** — Playwright was redundant with the already-available browser automation tooling.

### Competitor research performed

Real, live inspection of `wiz.io` and `snyk.io` (product pages, docs, and the Snyk platform marketing page including two of its embedded demo videos, extracted frame-by-frame via a CORS workaround) informed the design direction. Concrete things pulled from that research and later applied:
- Neutral, non-blue-tinted dark surfaces with color spent only on brand accent + severity states.
- Snyk's target-list pattern: thin-divider rows instead of bordered cards, with status filter tabs above the list.
- Snyk's own docs nav treats "Agent security" as a top-level section — used as direct precedent for giving AI/agent security a first-class nav entry in Rikugan rather than burying it.

A visual mockup artifact was built and iterated on with the user before any real code was touched (published to `claude.ai/code/artifact/...`, not part of this repo). The user reacted to a visible bug in that mockup (the severity gauge's number/badge overlapping the arc) which was fixed in the mockup and later became directly relevant when the *same category* of layout bug was found for real in the shipped Security Score widget — see §5.

## 2. Decisions made before writing code

These were confirmed with the user via explicit questions, not assumed:

- **"Guardrails"** was chosen (over alternatives) as the name for the new top-level nav group holding scan-policy config (Repo Groups, SLA Rules, Workflow Templates, FP Rules, Policies) — it reuses the existing "PR Guardrail" branding already in the product.
- **"Control Plane"** was chosen as the new name for what remains of `/admin` after the split (Access + Tooling only) — a real infra term distinguishing the management layer from the "data plane" that runs scans.
- The `Overview / Discover / Scan / Triage / Report / Operate` sidebar **group labels were explicitly NOT renamed**, despite alternatives having been drafted internally (Posture / Attack Surface / Coverage / Assurance / Account) — those were never shown to the user, so they were left alone rather than silently changed.
- Approval Queue moving out of Admin into its own route, and out from behind `adminOnly`, was flagged to the user as a **deliberate widening of navigability** (not access — the backend already permitted `security_engineer`, it just had no nav link) rather than let it pass as a silent side effect.
- "AI Analysis" (existing LLM-assisted remediation explanation feature) was renamed to **"Explain with AI"** to avoid colliding with the new, unrelated "AI Security" (AI/ML repo scanning) nav item.

## 3. What shipped — Nav/IA restructure

**Before:** `/admin` was a single page with 11 tabs (Users, Workspace Roles, Repo Groups, SLA Rules, Workflow Templates, FP Rules, Global Integrations, Tools Health, Tool Marketplace, Policies, Approval Queue), already grouped into 4 sub-groups from a prior fix (#118) but still visually and cognitively overloaded.

**After** — four real route changes, all merged:

| Route | What it holds | Access |
|---|---|---|
| `/guardrails` (new) | Repo Groups, SLA Rules, Workflow Templates, FP Rules, Policies | `adminOnly` in the sidebar — same visibility the tabs had before, deliberately not widened |
| `/approval-queue` (new) | The PR Guardrail ignore-request review queue, wrapped with its own role check | **Not** `adminOnly` — visible to `admin` and `security_engineer`; other roles hitting the URL directly see an `EmptyState` access-denied message, not the real data |
| `/admin` (trimmed) | User Management, Workspace Roles removed → now just Users + Global Integrations/Tools Health/Tool Marketplace, heading changed to "Control Plane" | `adminOnly`, unchanged |
| `/workspaces` (new) | Absorbed the "Workspace Roles" tab and the per-workspace API key that used to live in Settings behind a confusing target-picker-driven `WorkspaceKeyCard` | `adminOnly` |
| `/ai-security` (new) | See §4 | Visible to all roles (no adminOnly), matches severity/finding pages' existing access model |

Sidebar (`frontend/src/components/sidebar.tsx`) relabeled to match: "Admin" → "Control Plane", "AI Analysis" → "Explain with AI", new "AI Security" item under **Scan**, new "Approval Queue" item under **Triage**, new "Guardrails" top-level group, new "Workspaces" item under Control Plane's group.

Every existing tab/component was **moved, not rewritten** — `Groups`, `SlaRules`, `WorkflowTemplates`, `FpRules`, `Policies`, `ApprovalQueue`, `UserManagement`, `GlobalIntegrations`, `ToolsHealth`, `ToolMarketplace`, `WorkspaceRoles` are the exact same components, just re-hosted under new route files. No functionality was rewritten in this slice — verified by grep that zero existing frontend tests referenced the old routes/labels before touching anything.

### `/ai-security` in detail

Built because AI-repo detection (#185), ModelScan (#186), and the LLM SAST ruleset (#189) had shipped in prior sessions with **zero dedicated frontend surface** — the only way to see any of it was already knowing to filter the Findings page by tool name. The new page shows:
- KPI row: AI/ML repo count, ModelScan open findings, LLM-ruleset open findings (all real data, no new backend endpoints — reuses `api.targets()` filtered on `is_ai_repo_effective` and two `api.findings({tool: ...})` calls, same pattern `sbom/page.tsx` already used for its OSS Vulnerabilities tab).
- Per-repo breakdown linking into `/findings?tool=modelscan&target_id=X` (verified this exact URL shape round-trips correctly through the real Findings page filter bar).
- A pointer into the existing AIBOM tab on `/sbom` rather than duplicating that UI.
- An **honest "not yet available" card for garak** (LLM red-teaming) — garak is registered in the Tool Marketplace catalog for visibility but has no `TOOL_COMMANDS` entry (needs a live model endpoint, not a repo checkout, so it was deliberately never wired into scanning). The page says this plainly instead of omitting garak and silently implying no LLM red-teaming exists, or claiming it works when it doesn't.

## 4. What shipped — Dashboard widgets

Three new **opt-in** widgets (not added to `DEFAULT_WIDGET_ORDER`, so no existing user's dashboard changes unless they explicitly add one via "Add Widget"):

- **Live Scan Activity** — scans currently running, most-recently-started first. Backend resolver duplicates the query `GET /api/scans/active` already uses (`Scan.status == "running"`, workspace-scoped, stale-row sweep via `mark_stale_if_needed`) rather than importing that endpoint, because it returns a differently-shaped (flat, most-recent-first) result than the by-target dict the target-detail page's scan buttons need.
- **AI/ML Risk** — same shape of data as the `/ai-security` page's KPIs, but filtered to `OPEN_STATES` (matching every other dashboard widget's "open" convention) rather than all-states (which `/ai-security` uses, matching the SBOM page's inventory convention — a deliberate, disclosed difference between the two surfaces, not an inconsistency bug).
- **Guardrail Activity** — recent PR Guardrail scan decisions (reusing `LOG_STATUS_COLOR` exported from `pr-guardrail-log.tsx` so status pills look identical everywhere) plus a pending-approvals count that links straight to `/approval-queue`.

All three: real backend resolvers in `backend/app/core/widgets.py`, real regression tests in `backend/tests/test_dashboard_widgets.py` (widget-count assertion updated 8→11), and live-verified in the browser with real seeded data before merge.

## 5. What shipped — Design revamp

### Color tokens (`frontend/src/app/globals.css`)

The dark theme's surfaces (`--background`, `--card`, `--sidebar`, `--border`, `--muted`, `--secondary`) were every one of them a shade of the same blue-slate family — this is shadcn's stock default palette, never actually customized, and is exactly the palette every unstyled AI-scaffolded dashboard ships with. Repainted to a **true neutral charcoal** (`#16181b` background, `#1d2023` card, `#2b2e33` border — no channel bias toward blue) with cyan (`#22c1d9`) and the four semantic colors (critical `#f0555c`, high/warning `#f2924a`, success `#34b774`) as the only color in the room. **Light theme was left untouched** — it was already near-white/near-black, not visibly slate-tinted, and the user's complaint was specifically about dark mode.

### Targets list (`frontend/src/app/(dashboard)/targets/targets-list.tsx`)

- Replaced 35+ individually-bordered `Card` rows with one outer container + `divide-y` hairline dividers (matches Snyk/Wiz's own target-list pattern) — same information, same bulk-select/Mass-Rollout functionality, verified unchanged.
- Added real quick-filter status tabs above the list: **All / Needs attention / Never scanned / Stale (30d+)**, each with a live count, stored in the URL (`?quick=`) so it survives reload/share, computed client-side against the already-fetched target/summary data (no new backend calls).

### Two real bugs found and fixed while doing this (not part of the original ask — surfaced by the user's own screenshots)

1. **Security Score gauge arc/number misalignment.** Root cause: the gauge's outer `<div>` has a **fixed pixel size** set via inline style (matching its child SVG's hardcoded `width`/`height` attributes), but sits inside a flex row without `shrink-0` — flexbox's default `flex-shrink: 1` was silently compressing that div below its stated size whenever the row ran short on space, while the SVG inside kept its hardcoded width and visually overflowed the now-smaller parent. Fixed by adding `shrink-0` to the gauge's own root, and changing the parent row from a brittle `sm:flex-row` (a viewport-width guess that doesn't know how wide *this specific card* actually is) to `flex-wrap` (reacts to the row's real available width).
2. **Whole-dashboard horizontal overflow on any non-desktop width.** Found while testing bug #1's fix at mobile width: `main.scrollWidth` was 1491px against a 375px viewport. Root cause: `dashboard-board.tsx`'s widget grid (`className="grid gap-4 lg:grid-cols-3"`) had **no explicit `grid-cols-1` below the `lg:` breakpoint**, so its implicit single-column track sized itself to the widest child's *max-content* rather than clamping to the viewport — and a grid item that can genuinely shrink at layout time (the Security Score row, post-fix-#1) still contributes its un-shrunk max-content to that track-sizing pass. One widget was silently forcing the entire page ~1100px wider than every phone-width viewport. Fixed with a one-line `grid-cols-1` addition — this is the fix with real blast radius, since it affects the layout track hosting *every* dashboard widget, not just Security Score.

Both fixes were verified with real DOM measurements (`getBoundingClientRect`, `getComputedStyle`) at both 1280px and 375px widths before being called done — not just visual inspection.

### Explicitly investigated and NOT built

The original mockup proposed a redesigned "Finding Detail" page with a per-finding severity gauge. Investigation found **no such page exists** in the real app — findings expand inline within the list (`findings-list.tsx`'s row-expand pattern), not as a separate route. Forcing a mockup element designed for a single-finding context into a list of 1000+ rows would be bad UX (heavy, noisy per-row SVG gauges). This was flagged honestly to the user rather than inventing a fictional route to match the mockup.

## 6. What shipped — bug fixes unrelated to the visual work

- **Scan status not surviving a page refresh.** `frontend/src/app/(dashboard)/targets/[id]/scan-buttons.tsx` now wires in the existing `useActiveScans` hook (which polls `GET /api/scans/active`, the server truth) alongside the locally-tracked scan-in-progress state, so a scan dispatched from anywhere (this page, the Scans page's bulk trigger, another browser tab) shows up correctly after a reload. Also changed "disable every scan button while any one tool runs" to "disable only the specific running tool's button" — concurrent scans of different tools against the same target are safe per `runner.clone_repo`'s own docstring (isolated clone directories).
- **Login form lying about failure reasons.** `frontend/src/app/login/page.tsx`'s `catch` block collapsed every failure — a 429 rate limit, a network error, a 500 — into a hardcoded "Invalid email or password." Fixed to surface the real backend error message (`ApiError.message`, which already carries FastAPI's real `detail` string) for anything that isn't actually a 401, since a wrong password is the only case that message is true for.

## 7. Infrastructure bugs found and fixed (not code — environment)

These were found while manually testing everything above end-to-end in the browser and are **not part of the merged PR diff**, but are critical for anyone running this stack locally:

1. **`PLATFORM_ENCRYPTION_KEY` was never set.** `backend/app/core/crypto.py` mints a brand-new random Fernet key every process start when this env var is empty — a documented, intentional dev fallback, but it means **every container restart permanently orphans every previously-encrypted secret** (GitHub App private key, client secret, webhook secret). This is what caused the mass "Add Pipeline to 32 repos" rollout to fail for every single repo with "Failed to decrypt secret." **Fixed** by creating a root-level `.env` (gitignored — added `.env` to `.gitignore`, it was previously only covering `backend/.env`) with a real, generated key — see that local `.env` file for the actual value in use on this machine; it is deliberately not reproduced here since this document is committed to git and `.env` is not.

   **Anyone deploying this for real, or setting up a fresh checkout, must generate their own key**: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. The GitHub App connection had to be **reconnected once** after this fix (old secrets were unrecoverable) — from this point forward, secrets survive restarts.
2. **A stray native `uvicorn` process** (started directly on the host much earlier in this session, before Docker was brought up, and never killed) was squatting on port 8000 alongside Docker's own backend container. Login requests were nondeterministically landing on whichever process answered first, and the two had diverged databases — one issuing session tokens with a `token_version` the *other* one's database didn't recognize, so sessions were rejected as "revoked" immediately after a successful login. This is what made login look completely broken from the user's side. **Fixed** by killing the stray process; there is no code change for this since it was never a code bug.
3. A related **rate-limit false alarm**: the login endpoint's 5-attempts-per-60-seconds limit (keyed by client IP, backed by Redis with a 60s TTL) was legitimately tripped by the volume of manual/automated login attempts made while diagnosing bug #2 above. It self-cleared; no code or config change was needed, but it's worth knowing the limit exists (`backend/app/api/auth.py`: `LOGIN_RATE_LIMIT = 5`, `LOGIN_RATE_WINDOW_SECONDS = 60`) if it's ever hit again during heavy manual testing.

## 8. What shipped — onboarding module removed entirely

Per explicit user instruction ("let's deprecate onboarding module" → confirmed "Remove entirely" over two lighter alternatives). Removed:

**Frontend:**
- `frontend/src/app/(dashboard)/onboarding/` (the whole directory — `page.tsx`, `setup-questionnaire.tsx`) deleted outright.
- `frontend/src/app/(dashboard)/layout.tsx` — removed `ONBOARDING_EXEMPT_PATHS` and the `if (targets.length === 0) redirect("/onboarding")` block. A fresh login now goes straight to the dashboard regardless of how many targets exist, rather than being forced through a wizard.
- `frontend/src/app/(dashboard)/settings/page.tsx` — removed the "Replay guided onboarding" link.
- `frontend/src/proxy.ts` — removed the `x-pathname` header plumbing that only existed to let the old layout know the current path for its onboarding-exemption check; confirmed nothing else consumed it before removing.
- `frontend/src/lib/api.ts` — removed `OnboardingChoice`/`OnboardingChoices`/`OnboardingProfile`/`OnboardingRecommendations` types and the three `onboarding*` API methods.

**Backend:**
- `backend/app/api/onboarding.py` (the whole router: `/api/onboarding/choices`, `/profile` GET+POST, `/recommendations`) deleted.
- `backend/app/core/onboarding_profile.py` (choice vocab + `recommend_tools()`) deleted.
- `backend/app/models/models.py` — `OnboardingProfile` model class deleted.
- `backend/app/main.py` — router import and `app.include_router(onboarding.router, ...)` removed.
- `backend/tests/test_onboarding_profile.py` deleted (its ~17 tests are why the full suite count dropped from 794 to 777 passing).
- **A real Alembic migration** (`ac9daa1d9a66_drop_onboarding_profile_224.py`) was authored to drop the `onboardingprofile` table — the *original creation migration* (`9f7506526474_add_onboarding_profile_203.py`) was deliberately **not deleted**, since removing historical migrations breaks Alembic's revision chain for anyone not yet upgraded past it. The new migration has a real, tested `downgrade()` that recreates the table if ever needed.

### One disclosed, deliberate gap

The questionnaire's `POST /profile` used to write real rows into `WorkspaceToolConfig` (issue #75) disabling scanners like `gosec`/`checkov`/`tfsec`/`modelscan`/`semgrep-llm` based on answers. **Any such rows already written by a past onboarding run are untouched by this removal** — there is no `source` column distinguishing an onboarding-written row from a manually-set one, so there was no reliable way to selectively clear them. Those scanners stay off (or on) exactly as onboarding last left them, and remain editable in Tool Marketplace like any other tool config. This was investigated and disclosed rather than either guessed at or silently ignored.

## 9. Verification performed before merge

- Backend: `pytest` — **777 passed, 1 skipped** (down from 794 before onboarding-test removal, exactly accounting for the deleted test file).
- Frontend: `vitest run` — **139 passed**, `tsc --noEmit` clean, `eslint` clean, `next build` succeeds with all expected routes present and `/onboarding` correctly absent.
- Live browser verification (not just automated tests) of: role-gating on Guardrails/Approval Queue for `admin`/`security_engineer`/`developer` accounts created specifically for this test and deleted afterward; AI Security page with real seeded AI-flagged repos; all 3 new dashboard widgets rendering real data; targets list quick-filters actually filtering; neutral-charcoal theme at both 1280px and 375px widths with zero horizontal overflow; full login → dashboard flow after fixing the stray-process bug; onboarding-removed login flow going straight to dashboard.
- Both `docker compose build backend frontend` images built clean and were run as the actual verification target for the final state (not just `next dev`).

## 10. PR / merge record

- Branch: `nav-revamp-ia-restructure`, pushed and merged via `gh pr merge --squash --delete-branch`.
- PR: [github.com/geekshiv/rikugan-platform/pull/224](https://github.com/geekshiv/rikugan-platform/pull/224)
- Merged into `main` as commit `9095dd9` (33 files changed, 1536 insertions, 1953 deletions).
- CI was green (11/11 checks) and GitHub reported the merge as `MERGEABLE`/`CLEAN` before merging.

## 11. Explicitly out of scope / not done this session

These were discussed as follow-ups in the original design-revamp plan but **not started**:

- Applying the neutral-charcoal token change had already been done for dark mode; **light mode was never touched** and still uses its original (already-reasonable) palette — no action needed unless a future complaint targets light mode specifically.
- The Finding Detail page redesign proposed in the original mockup was investigated and found not to correspond to any real page (see §5) — no further action unless the user wants a genuinely new single-finding detail route built from scratch (would be new scope, not a redesign of something existing).
- Whether "Workspace Roles" should have merged into the new `/workspaces` page was proposed and incorporated into design mockups earlier in this session's history, and the actual `/workspaces` page (present in this PR) does absorb it — this is done, not outstanding.
- No further design-system work (typography, spacing scale, motion) was requested or attempted beyond the color-token and layout fixes described above.

## 12. Key file map for future reference

| Concern | File |
|---|---|
| Nav structure | `frontend/src/components/sidebar.tsx` |
| Guardrails page | `frontend/src/app/(dashboard)/guardrails/page.tsx` |
| Approval Queue page | `frontend/src/app/(dashboard)/approval-queue/page.tsx` |
| Control Plane (trimmed admin) | `frontend/src/app/(dashboard)/admin/page.tsx` |
| Workspaces page | `frontend/src/app/(dashboard)/workspaces/page.tsx` |
| AI Security page | `frontend/src/app/(dashboard)/ai-security/page.tsx` |
| Dashboard widget resolvers (backend) | `backend/app/core/widgets.py` |
| Dashboard widget renderers (frontend) | `frontend/src/components/dashboard/widgets.tsx` |
| Dashboard grid (the `grid-cols-1` fix) | `frontend/src/components/dashboard/dashboard-board.tsx` |
| Security Score gauge (the `shrink-0` fix) | `frontend/src/components/charts/security-score-gauge.tsx` |
| Color tokens | `frontend/src/app/globals.css` |
| Targets list (quick filters + row style) | `frontend/src/app/(dashboard)/targets/targets-list.tsx` |
| Scan button persistence fix | `frontend/src/app/(dashboard)/targets/[id]/scan-buttons.tsx` |
| Login error-message fix | `frontend/src/app/login/page.tsx` |
| Encryption key config | `.env` (gitignored, root of repo) + `backend/app/core/crypto.py` |
| Onboarding-drop migration | `backend/alembic/versions/ac9daa1d9a66_drop_onboarding_profile_224.py` |
