<!-- BEGIN:nextjs-agent-rules -->

# This is NOT the Next.js you know

This version has breaking changes, APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` (resolved from this file's directory; in monorepos the `next` package may not be visible from the repo root) before writing any code. Heed deprecation notices.

This block is written and re-added by `next dev`, verify at `node_modules/next/dist/server/lib/generate-agent-files.js`. Removing it from a diff only re-creates the uncommitted change; committing it with your work keeps the tree clean.

<!-- END:nextjs-agent-rules -->

# Toleman Platform - Frontend & UI Agent Directives

Refer to [`DESIGN_SYSTEM.md`](DESIGN_SYSTEM.md), [`COMPONENTS.md`](COMPONENTS.md), and [`REFACTORING_PROGRESS.md`](REFACTORING_PROGRESS.md) for full specifications and current migration status.

## 1. AI Implementation Directive
When modifying or creating any Toleman UI:
1. **Inspect before creating**: Reuse Layer 1 primitives (`Button`, `Card`, `Badge`, `Input`, `Tooltip`) and Layer 2 patterns (`PageHeader`, `SeverityChip`, `StatusBadge`, `AlertBanner`, `StatCard`, `StatGrid`, `FilterBar`, `ProgressBar`, `AsyncContent`).
2. **Never hardcode raw colors or spacing**: Always consume CSS custom property tokens from `@theme inline` in `globals.css`.
3. **Domain Visual Language**:
   - **Severity** (`Critical`, `High`, `Medium`, `Low`, `Informational`) uses `<SeverityChip />` with semantic severity palette.
   - **Risk** (Contextual priority) appears as a tabular monospace score (`Risk 94`).
   - **Status** communicates workflow (neutral for open/closed, accent for in-progress, positive for fixed). Do NOT create rainbow status badges.
   - **Exploitability** (`[KEV]`, `[Exploit Available]`) appears as compact micro-tags.
4. **Unknown vs Zero vs Empty**:
   - `0 Critical` = Scanned and found 0.
   - `— Never scanned` = Unknown posture (use `unknown={true}`).
   - `No results` = Filter matched nothing.
5. **Full State Matrix**: Always account for loading, background refresh, populated, empty, unknown, error, and partial failure states.

## 2. Anti-Patterns
- Never generate dashboard pages made entirely of floating cards.
- Never use arbitrary gradients, glowing borders, glassmorphism, or excessive drop shadows.
- Never transform enterprise data tables into oversized mobile cards.
- Never import client-value exports into Server Components.
- Never render confident `0` for unmeasured data.

