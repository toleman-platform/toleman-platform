# Toleman Design System & Enterprise UX Standard

The authoritative specification for design tokens, typography, spatial geometry, domain visual language, page composition, and interaction standards across the **Toleman Platform**.

Live interactive specimens are available at [`/design-system`](http://localhost:3000/design-system).

---

## 1. Design Philosophy

- **Density-First**: Built specifically for enterprise security teams triaging thousands of vulnerabilities, repositories, and PR logs daily.
- **True Neutral Canvases**: Surface palettes in Dark mode (`#16181b`) and Light mode (`#f5f7fa`) avoid distracting chromatic slate/blue biases. Saturation is reserved strictly for brand cyan accents and 5-tier semantic severity indicators.
- **Zero Raw Literals**: Components consume CSS custom property tokens via `@theme inline` in [`globals.css`](src/app/globals.css); arbitrary hex or raw Tailwind color scales (`bg-slate-900`, `text-emerald-500`) are prohibited.

---

## 2. Color Architecture & Surface Hierarchy

Toleman implements a dual-palette architecture where Light mode is an individually designed palette, not a mechanical inversion of Dark mode.

```
   Dark Theme (#16181b Canvas)             Light Theme (#f5f7fa Canvas)
   ┌───────────────────────────────┐       ┌───────────────────────────────┐
   │ Canvas: #16181b               │       │ Canvas: #f5f7fa               │
   │ ┌───────────────────────────┐ │       │ ┌───────────────────────────┐ │
   │ │ Card / Panel: #1d2023     │ │       │ │ Card / Panel: #ffffff     │ │
   │ │ ┌───────────────────────┐ │ │       │ │ ┌───────────────────────┐ │ │
   │ │ │ Sunken/Muted: #24272b │ │ │       │ │ │ Sunken/Muted: #eef1f6 │ │ │
   │ │ └───────────────────────┘ │ │       │ │ └───────────────────────┘ │ │
   │ └───────────────────────────┘ │       │ └───────────────────────────┘ │
   └───────────────────────────────┘       └───────────────────────────────┘
```

### Core Token Reference

| Token Name | Dark Mode (`:root`) | Light Mode (`[data-theme="light"]`) | Usage / Semantic Role |
| :--- | :--- | :--- | :--- |
| `--background` | `#16181b` | `#f5f7fa` | Base application canvas |
| `--foreground` | `#e9eaec` | `#161c2b` | Primary text and headings |
| `--card` | `#1d2023` | `#ffffff` | Elevated surface for cards, panels, and tables |
| `--card-foreground` | `#e9eaec` | `#161c2b` | Text on card surfaces |
| `--secondary` | `#24272b` | `#eef1f6` | Sunken inputs, secondary badges, icon tiles |
| `--muted-foreground`| `#9aa0a8` | `#5b6472` | Secondary text, timestamps, labels |
| `--border` | `#2b2e33` | `#dde2ea` | Structural dividers, container outlines |
| `--primary` | `#22c1d9` | `#22c1d9` | Brand cyan button fill (paired with `#0d1b1e` text) |
| `--accent-strong` | `#22c1d9` | `#0a7490` | Deepened cyan for bare text, active links, and nav pills |
| `--ring` | `#22c1d9` | `#0a7490` | Focus outlines (meets WCAG 3:1 contrast against canvas) |

### 5-Tier Semantic Severity Matrix

| Severity Tier | Dark Token & Value | Light Token & Value | WCAG Contrast | Component Usage |
| :--- | :--- | :--- | :---: | :--- |
| **Critical** | `--destructive: #f87171` | `--destructive: #c0193f` | **6.4:1 (AA)** | `<SeverityChip severity="Critical">`, destructive banners |
| **High** | `--chart-3: #f2924a` | `--warning: #8a6200` | **5.2:1 (AA)** | `<SeverityChip severity="High">`, SLA warning alerts |
| **Medium** | `--chart-1: #22c1d9` | `--chart-1: #0a7490` | **5.4:1 (AA)** | `<SeverityChip severity="Medium">` |
| **Low / Info** | `--chart-2: #4fc3d9` | `--chart-2: #0e6ba8` | **5.5:1 (AA)** | `<SeverityChip severity="Low">`, tool discovery badges |
| **Success** | `--chart-5: #34b774` | `--success: #047857` | **5.8:1 (AA)** | `<SeverityChip severity="Passed">`, fixed findings, passed PRs |

---

## 3. Scalable Typography & Type Scale

- **Primary Sans**: `Plus Jakarta Sans` (`--font-sans`) — Geometric grotesque with open counters for clean readability at dense sizes.
- **Monospace**: `Geist Mono` (`--font-mono`) — Precision tabular numerals and code identifiers.

### Type Scale Classes

| Class | Font Size | Weight | Line Height | Tracking | Application |
| :--- | :--- | :---: | :---: | :---: | :--- |
| `.text-display` | `clamp(1.75rem, 1.5rem + 1vw, 2.25rem)` *(28–36px)* | 800 | 1.15 | `-0.025em` | Hero titles, landing overviews |
| `.text-title` | `clamp(1.25rem, 1.125rem + 0.5vw, 1.5rem)` *(20–24px)* | 700 | 1.25 | `-0.02em` | Page headers (`<PageHeader>`) |
| `.text-heading` | `1.125rem` *(18px)* | 600 | 1.35 | `-0.015em` | Card titles (`<CardTitle>`) |
| `.text-subheading`| `0.9375rem` *(15px)* | 600 | 1.4 | `-0.01em` | Widget headers, modal sections |
| `.text-body` | `0.875rem` *(14px)* | 400 | 1.5 | normal | Paragraphs, documentation text |
| `.text-body-sm` | `0.8125rem` *(13px)* | 400 | 1.45 | normal | Page subtitle descriptions, help copy |
| `.text-caption` | `0.75rem` *(12px)* | 500 | 1.4 | normal | Table metadata, line coordinates |
| `.text-meta` | `0.6875rem` *(11px)* | 500 | `0.875rem` | `+0.01em` | SLA countdowns, timestamp labels |
| `.text-micro` | `0.625rem` *(10px)* | 600 | `0.75rem` | `+0.04em` | Uppercase pill tags (`ADMIN`, `VERIFIED`) |
| `.text-code` | `0.8125rem` *(13px)* | 400 | 1.4 | `-0.01em` | Monospace CVEs, hashes, and rule IDs |

### Tabular Numeral Figures
Always enforce tabular numerals on dynamic figures, counts, and countdowns to eliminate visual horizontal jitter:
- `.font-tabular`: `font-variant-numeric: tabular-nums`
- `.text-metric-xl`: 30px / 700 Wt / tabular (Primary KPI metrics)
- `.text-metric-lg`: 24px / 700 Wt / tabular (Card stat numbers)
- `.text-metric-md`: 18px / 700 Wt / tabular (Compact table metrics)

---

## 4. Spacing, Grid & "The Rules of Thumb"

### The 4px / 8px Base Spatial Grid

```
┌──────┬────────┬──────────┬────────────────────────────────────────────────────────┐
│ Token│ Value  │ Tailwind │ Semantic Application                                   │
├──────┼────────┼──────────┼────────────────────────────────────────────────────────┤
│ 3xs  │ 2px    │ gap-0.5  │ Micro dividers, border offsets, tagline leading gaps   │
│ 2xs  │ 4px    │ gap-1    │ Icon + text inline gaps, badge internal spacing        │
│ xs   │ 8px    │ gap-2    │ Input internal padding, chip lists, button icon gaps   │
│ sm   │ 12px   │ gap-3    │ Compact row padding, stat card item gaps               │
│ md   │ 16px   │ gap-4    │ Standard card padding, grid gutters                    │
│ lg   │ 20px   │ gap-5    │ Section dividers, comfortable card headers             │
│ xl   │ 24px   │ gap-6    │ Page section gaps, comfortable container padding       │
│ 2xl  │ 32px   │ gap-8    │ Major dashboard zone breaks                            │
│ 3xl  │ 48px   │ gap-12   │ Landing / Hero structural breathing room               │
└──────┴────────┴──────────┴────────────────────────────────────────────────────────┘
```

### The Concentric Radius Rule
Nested corners must satisfy:
$$\mathbf{R_{outer} = R_{inner} + \text{Padding}}$$

- `--radius-xs: 0.25rem;` (4px) — micro badges, status chips
- `--radius-sm: 0.375rem;` (6px) — button controls, text inputs
- `--radius-md: 0.5rem;` (8px) — inner icon tiles, embedded pills
- `--radius-lg: 0.75rem;` (12px) — standard card containers (`<Card>`)
- `--radius-xl: 1rem;` (16px) — outer shells, modal dialogs, drawers

### Proximity Stack & Flow Utilities
- `.stack-tight`: `gap: 4px` (Title + subtitle)
- `.stack-item`: `gap: 8px` (Label + input)
- `.stack-card`: `gap: 16px` (Card sections)
- `.stack-section`: `gap: 24px` (Page major zones)
- `.inline-tight`: `gap: 4px` (Icon + text)
- `.inline-item`: `gap: 8px` (Tag arrays)
- `.inline-group`: `gap: 16px` (Action button groups)

---

## 5. Reusable Component Catalog

All standardized components live in [`src/components/ui/`](src/components/ui/):
- `<PageHeader title="..." description="..." badge={...} actions={...} />`
- `<SeverityChip severity="Critical|High|Medium|Low|Info" variant="subtle|dot" count={...} />`
- `<StatusBadge status="running|completed|failed|blocked|queued|pending" />`
- `<AlertBanner tone="info|warning|critical|positive" title="...">...</AlertBanner>`
- `<StatCard label="..." value={...} tone="default|attention|critical|positive" unknown={...} />`
- `<StatGrid columns={2|3|4}>...</StatGrid>`
- `<ProgressBar value={...} size="sm|md|lg" />`
- `<FilterBar searchValue={...} activePills={...} />`
- `<AsyncContent state={...} itemNoun="findings">{(data) => ...}</AsyncContent>`

---

## 6. Density Duality (`comfortable` vs `compact`)

Toleman supports two density modes toggled via `data-density="compact|comfortable"` on `<html>`:
1. **Comfortable** (Default, executive-friendly): 16px/24px padding, 24px section gaps.
2. **Compact** (Power-user triage): 8px/12px padding, 12px gaps, and collapsed secondary lines via `.density-stack` and `.density-compact-only`.

---

## 7. Information Density & Page Composition

Toleman is a high-density enterprise security product. Optimize for rapid scanning, comparison, filtering, and investigation rather than decorative presentation.

### Default Page Anatomy
Most entity and workflow pages SHOULD follow this structure:

```
┌──────────────────────────────────────────────────────────────┐
│ Breadcrumb / Context                                        │
│ Page Header                                      Actions     │
│ Short description / contextual metadata                     │
├──────────────────────────────────────────────────────────────┤
│ Optional: alert / contextual status                         │
├──────────────────────────────────────────────────────────────┤
│ Summary / high-value metrics                                │
├──────────────────────────────────────────────────────────────┤
│ Toolbar: Search · Filters · Views · Columns · Export         │
├──────────────────────────────────────────────────────────────┤
│ Primary content: table / investigation view / details       │
└──────────────────────────────────────────────────────────────┘
```

- **Do NOT place every section inside an independent floating Card.** Use cards when the content represents a meaningful bounded unit.
- Tables, page-level filters, navigation, breadcrumbs, and primary work surfaces SHOULD usually sit directly within the page hierarchy rather than becoming cards-within-cards.

### Vertical Density Rules
Prefer compact enterprise layouts:
- **Page header**: 24–32px bottom spacing (`gap-6`)
- **Toolbar**: 12–16px from primary content (`gap-3` / `gap-4`)
- **Table rows**: approximately 40–48px
- **Compact metadata rows**: approximately 32–40px
- Avoid excessive vertical padding such as `py-8` inside routine operational components. Users should see useful information without excessive scrolling.

---

## 8. Domain Visual Language

The following concepts have distinct meanings and **MUST NOT** be visually conflated.

### Severity
Represents technical severity of the underlying finding.
- **Values**: `Critical`, `High`, `Medium`, `Low`, `Informational`
- **Use**: `<SeverityChip severity="Critical" />`
- **Rule**: Severity colors MUST use the semantic severity palette.

### Risk
Represents contextual business/security prioritization (CVSS, exploitability, KEV status, EPSS, asset criticality, production/internet exposure).
- **Format**: Monospace tabular score (e.g., `94 HIGH RISK`).
- **Rule**: Do NOT use the exact same visual treatment for Risk and Severity.
  - Severity: `Critical` (technical rating)
  - Risk: `Risk 94` (contextual priority)

### Status
Status communicates workflow, not severity.
- **Values**: `Open`, `Assigned`, `In Progress`, `Fixed`, `Verified`, `Closed`, `Suppressed`, `Risk Accepted`, `False Positive`, `Reopened`
- **Color Mapping**:
  - Neutral statuses (`Open`, `Closed`, `Assigned`) → Neutral badges (`bg-secondary text-muted-foreground`)
  - Active / in-progress (`In Progress`, `Investigating`) → Brand Accent (`text-primary bg-primary/10`)
  - Successful terminal (`Fixed`, `Verified`) → Positive (`text-chart-5 bg-chart-5/10`)
  - Problem / exceptional states (`Blocked`, `Reopened`) → Warning / Destructive
- **Rule**: Do NOT map every status to a unique saturated rainbow color.

### Exploitability
Contextual signals such as Known Exploited Vulnerabilities (KEV), public exploit availability, or internet exposure.
- **Indicators**: `[KEV]`, `[Exploit Available]`, `[Internet Exposed]`
- **Rule**: Represent as compact metadata tags (`.text-micro` / `.text-meta`). These SHOULD NOT visually overpower Severity or Risk.

---

## 9. Vulnerability Table Standard

The vulnerability table is a primary Toleman work surface.

### Default Column Layout
`Severity | Vulnerability | Risk | Affected Asset | Owner | Status | SLA`

```
● CRIT   CVE-2026-1842                       94   payments-api   Platform   Open      2d
         Remote Code Execution
```

### Table Rules
- Tables MUST support: server-side sorting, server-side filtering, pagination, persistent column configuration, row selection, keyboard-accessible selection, contextual row actions, sticky header, and optional sticky first column.
- Avoid horizontal scrolling for the default column configuration at 1280px whenever practical.
- Secondary metadata MAY appear underneath primary cell content (e.g. `CVE-2026-1842` on line 1, `lodash · 4.17.19` on line 2) rather than adding separate columns for every attribute.

### Cell Typography Hierarchy
- **Primary information**: `.text-body-sm` `font-medium`
- **Secondary metadata**: `.text-caption` `text-muted-foreground`
- **Identifiers**: `.text-code`
- **Numbers / Metrics**: `font-mono tabular-nums`

---

## 10. Filtering System

Filtering is a first-class interaction model. Use `<FilterBar />` for common filters.

### Filter Representation
- Applied filters SHOULD appear as removable pills (e.g., `[Severity: Critical ×]`, `[Environment: Production ×]`, `[KEV: Yes ×]`).
- Do NOT permanently display dozens of filter controls. The default toolbar should expose: `Search`, `Filter`, `Saved View`, `Columns`.
- Advanced filters should appear through a popover, drawer, or query-builder surface.

### URL Persistence
Important list state SHOULD be URL-addressable: `filters`, `search query`, `sorting`, `pagination`, `saved view`. Refreshing or sharing the URL reproduces the exact same investigation context.

---

## 11. Saved Views

Users may save combinations of filters, search, sorting, visible columns, column order, and grouping (e.g. *Critical Production*, *My Team*, *SLA Breaches*, *KEV + Internet Exposed*).
- Saved views may be **Personal**, **Team**, or **Organization**.
- **Rule**: Do NOT implement saved views as visually distinct pages. They are configurations over the same underlying work surface.

---

## 12. Entity Navigation Model

Toleman contains highly connected security entities (`Application → Service → Repository → Artifact → Container → Deployment → Environment` and `Vulnerability → Finding → Affected Asset`).
- Users MUST be able to move between related entities without losing investigation context using: **breadcrumbs**, **contextual links**, **side panels**, and **detail pages**.
- **Rule**: Do NOT open every related entity inside a modal. Modals are reserved for short transactional actions.

---

## 13. Detail Page Standard

Entity details SHOULD prioritize context before raw metadata. A vulnerability detail page MUST answer in this order:
1. What is wrong?
2. How dangerous is it?
3. Where does it exist?
4. Why does Toleman consider it important?
5. Who owns remediation?
6. How can it be fixed?
7. What happened previously?

### Composition Layout
```
Vulnerability Header
─────────────────────────────────────────────
Critical     Risk 94      Open      SLA 2d
CVE-2026-1842
Remote Code Execution in Example Library
Affected: payments-api / production
Owner: Platform Security
─────────────────────────────────────────────
Overview | Affected Assets | Evidence | Remediation | Activity
```
- **Rule**: Tabs SHOULD represent genuinely distinct information domains. Do NOT create tabs merely to avoid designing a coherent page.

---

## 14. Master-Detail Interactions

For investigation-heavy workflows, prefer master-detail interaction where useful:

```
┌───────────────────────────────┬─────────────────────────────┐
│ Vulnerabilities               │ Finding Preview (Drawer)    │
│                               │                             │
│ CVE-2026-1842                 │ Critical                    │
│ CVE-2026-9121                 │ Risk 94                     │
│ CVE-2026-4429                 │ payments-api                │
│                               │                             │
│                               │ View full details →         │
└───────────────────────────────┴─────────────────────────────┘
```
- Use a **side panel / drawer** for quick inspection allowing users to inspect several findings without losing table context.
- Use a **full page** when investigation is complex, multiple tabs are required, evidence is substantial, or actions affect workflow.

---

## 15. Metric Card Rules

Metrics should communicate actionable security state.
- **Good**: `Critical: 23` (`↑ 4 since last scan`, `Requires 24h SLA fix`)
- **Bad**: `Total Vulnerabilities: 12,483` (without context)
- Every metric SHOULD answer: *Is something getting better or worse? Is action required? What changed? What should I investigate?*
- A metric SHOULD be clickable when a corresponding filtered dataset exists (e.g., clicking `Critical: 23` navigates to `/findings?severity=critical`).

---

## 16. Chart Rules

Charts must support decisions rather than decorate dashboards.
- Use charts primarily for: **trends**, **distributions**, **comparisons**, and **remediation progress**.
- **Avoid**: unnecessary pie charts, 3D charts, gauges without operational meaning, rainbow category palettes, or charts containing more categories than users can reasonably compare.
- Use semantic colors only where semantic meaning exists; otherwise use neutral/accent chart tokens.
- Charts MUST provide accessible labels, tooltip values, and textual summaries.

---

## 17. Loading Behavior

Never blank useful existing data during background refresh. Distinguish:
1. **Initial Load**: Use skeleton shapes matching the final content geometry.
2. **Background Refresh**: Keep existing content visible; optionally show subtle spinner/indicator.
3. **Pagination / Filtering**: Retain previous data where appropriate while the next result loads.
4. **Mutation Pending**: Disable only the affected action rather than freezing the entire page (e.g. `Assigning...` on button instead of a full-screen spinner).

---

## 18. Unknown vs Zero vs Empty

These states MUST remain semantically distinct and **NEVER** interchanged:
- **`0 Critical`**: Scanning occurred and zero critical vulnerabilities were found.
- **`— Never scanned`**: No reliable data exists (posture unknown).
- **`No results`**: The current search/filter combination matched nothing.

---

## 19. Empty States

Empty states MUST explain why the content is empty and provide the most likely next action:
- **Filtered Empty**: `"No vulnerabilities match these filters."` → `[Clear Filters]`
- **First-Run Empty**: `"No scan results yet. Run a dependency scan to populate this repository."` → `[Run Scan]`

---

## 20. Error States

Avoid generic `"Something went wrong."` Prefer contextual errors:
- **Contextual Error**: `"Findings couldn't be refreshed. Showing results from 14 minutes ago."` → `[Retry]`
- **Partial Failure**: `"3 of 4 scanner sources loaded. Snyk data is temporarily unavailable."` Do NOT discard successfully loaded information because one secondary request failed.

---

## 21. Action Hierarchy

Each view should have one obvious primary action at most:
- `Primary Button` → `Secondary Button` → `Ghost / Menu actions`
- Example vulnerability header: `[Assign] [Create Ticket] [•••]` (destructive or exceptional workflow actions live in contextual menus).

---

## 22. Drawer vs Modal vs Page

- **Popover**: Filters, lightweight selection, contextual column configuration.
- **Drawer / Side Panel**: Quick inspection, contextual editing, previewing an entity without losing list context.
- **Modal**: Confirmations, small transactional forms, destructive actions.
- **Page**: Deep investigation, workflows containing substantial context, entities with multiple information sections.
- *Never use a modal as a substitute for proper navigation.*

---

## 23. Tooltip Rules

Tooltips explain unfamiliar UI concepts, not obvious labels:
- **Good**: `EPSS` → *"Predicted probability of exploitation within the next 30 days."*
- **Bad**: `Delete` → *"Deletes this item."*
- Critical information MUST NOT exist only inside tooltips.

---

## 24. Security-First Content Writing

Use precise terminology:
- Prefer `"12 vulnerabilities detected"` over `"12 security problems"`.
- Prefer `"Risk accepted until 14 Dec 2026"` over `"Ignored"`.
- Prefer `"Last scanned 8 minutes ago"` over `"Updated recently"`.

---

## 25. Responsive Behavior

Toleman is desktop-first (targets: 1440px+, 1280px, 1024px).
At narrower widths:
1. Preserve primary workflow.
2. Hide optional table columns.
3. Collapse secondary navigation into sidebar rail.
4. Move secondary actions into overflow menus.
5. Retain search/filter access.
*Do NOT transform enterprise tables into oversized mobile cards merely to claim responsive support.*

---

## 26. Accessibility Contract

Every interaction MUST support keyboard operation:
- Visible focus indication (`outline-ring`).
- Semantic heading hierarchy (`h1`, `h2`, `h3`).
- Accessible checkbox labels (`selectLabel="Select <item>"`).
- Sortable table header semantics (`aria-sort`).
- Non-color severity indicators (always include text like `● Critical`, never color alone).
- Accessible modal dialogs with focus trapping and restoration.
- Minimum WCAG AA contrast (≥ 4.5:1 for body text, ≥ 3:1 for graphical UI elements).

---

## 27. Page Creation Checklist

Before implementing any page, verify:
- [ ] **User Goal**: What decision or action is the user trying to make?
- [ ] **Primary Entity**: What entity is this page centered around?
- [ ] **Primary Action**: What is the single most important action?
- [ ] **Information Hierarchy**: What must be understood in 3 seconds vs 10 seconds vs deep investigation?
- [ ] **Dataset Scale**: Designed for 10 items, 1,000 items, or 1,000,000 items?
- [ ] **State Matrix**: Handled all 9 states: *loading, populated, empty, unknown, filtered-empty, error, stale, partial failure, permission restricted*?

---

## 28. AI Implementation Directive

When asked to create or modify a Toleman UI:
1. **Inspect before creating**: Inspect existing Toleman components before writing new ones.
2. **Reuse Layer 1 Primitives**: Use `<Button>`, `<Card>`, `<Badge>`, `<Input>`, `<Tooltip>`.
3. **Reuse Layer 2 Patterns**: Use `<PageHeader>`, `<SeverityChip>`, `<StatusBadge>`, `<AlertBanner>`, `<StatCard>`, `<StatGrid>`, `<FilterBar>`, `<AsyncContent>`, `<ListRow>`.
4. **No Page-Local Re-creations**: Never recreate existing primitives with page-local markup.
5. **Strict Token Adherence**: Never introduce arbitrary spacing, radius, typography, shadow, or color values.
6. **Preserve Navigation & Density**: Maintain existing density, proximity stacks, and breadcrumb conventions.
7. **Handle Full State Matrix**: Account for loading, empty, unknown, error, and partial states.
8. **Realistic Security Content**: Use realistic CVEs, CWEs, packages, and SLA terminology rather than lorem ipsum.
9. **Optimize for Triage**: Prioritize scanning speed and investigation depth over visual novelty.

---

## 29. Anti-Patterns

**Never generate:**
- Dashboard pages made entirely from floating cards.
- Arbitrary gradients, glowing neon borders, or glassmorphism.
- Excessive drop shadows or oversized marketing hero text.
- Massive whitespace in operational workflows.
- Rainbow status colors across routine table badges.
- Unnecessary pie charts, 3D charts, or non-operational gauges.
- Consumer-mobile card transformations inside desktop data tables.
- Deeply nested cards-within-cards.
- Client-side filtering of massive server datasets.
- Tables where every single entity property becomes a separate column.
- Modal-based navigation for connected entities.
- Zero values (`0`) rendered for unmeasured / unknown scanner states.

*The design should feel like a professional, high-trust operational security tool, not a marketing website.*
