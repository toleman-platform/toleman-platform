# Component architecture

How UI is composed in this app, and where new code belongs.

> **Design Tokens & Visual Foundations**: For colors, typography scales, 4px/8px spatial grid, and accessibility standards, refer to [**`DESIGN_SYSTEM.md`**](DESIGN_SYSTEM.md). Live interactive specimens are available at [`/design-system`](http://localhost:3000/design-system).

## The three layers

```
L1  components/ui/*                primitives   Button, Card, Badge, Input, EmptyState,
                                                ErrorState, Skeleton, Tooltip, ConfirmDialog

L2  hooks/* + components/ui/*      patterns     useAsyncData, useSelection, AsyncContent,
                                                ListRow, StatCard, BulkActionBar

L3  components/* + app/*           features     FindingsList, TargetsList, AiBomPanel, ...
```

**L1** is styling and a11y for a single element. It knows nothing about the domain.

**L2** is the shape of a recurring *interaction*, fetching, selecting, rendering the four
states of a request. It knows nothing about findings, targets or scans.

**L3** is where the domain lives. A feature composes L2 and L1 and adds meaning.

**Foundations & Data Layer**:
- `tokens/*`: Single source of truth for visual tokens (`fonts`, `spacing`, `theme`).
- `types/*`: Pure TypeScript domain and DTO definitions.
- `lib/api/*`: Modular, domain-driven API endpoints with tree-shakable exports and legacy `api` facade.
- `lib/*`: Testable, domain-agnostic utilities (`cn`, `safeHref`, `settleOrNull`, `pollUntilSettled`).

The rule that keeps this honest: **a layer may only import downward.** If an L2 component
needs to know what a finding is, it is an L3 component wearing the wrong hat.

### Why L2 exists

It was extracted (#210) from measured duplication, not from taste:

| Duplicated pattern | Files before |
|---|---|
| Hand-rolled `useEffect` fetch + `loading`/`error` state | 16 |
| The skeleton → error → empty → data ladder | 4 |
| Selection state (`Set`, `toggleOne`, `toggleAll`, `allSelected`) | 3 |
| Density row boilerplate (`py-0` + `--density-row-py`) | 4 |

Each copy drifted, and the drift caused real bugs: cancellation guards present in some
fetches and missing in others, `allSelected` computed against an unpaginated list (#204),
and the density fix in #172 applied file by file.

**A pattern layer earns its place by deleting more code than it adds.** If a proposed L2
component has one caller, it is not a pattern; it is that caller's implementation detail.
Wait for the third occurrence.

---

## L2 API reference

### `useAsyncData<T>(fetcher, options?)`

One fetch, one state machine. The transitions live in `hooks/async-state.ts` as a pure
reducer so they can be tested exhaustively without a DOM.

```tsx
const state = useAsyncData<AiBomView>(() => api.aibom(targetId), { deps: [targetId] });
```

| Option | Type | Default | Notes |
|---|---|---|---|
| `enabled` | `boolean` | `true` | `false` keeps the state `idle`, no spinner for something nobody requested |
| `deps` | `readonly unknown[]` | `[]` | Refetch triggers. Explicit, because an inline fetcher is a new identity every render |

Returns `status`, `data`, `error`, `isRefreshing`, `isInitialLoading`, `refetch`.

Two behaviours worth knowing, because they are what make refresh feel right:

- **`data` survives a refetch.** A list that blanks to a skeleton every time it revalidates
  reads as broken. Drive skeletons from `isInitialLoading`, never from `status === "loading"`.
- **`data` survives an error.** Stale rows beside an error banner beat an empty screen.

Out-of-order responses are discarded by request id, and the in-flight request is aborted on
unmount and on refetch.

### `<AsyncContent state={...}>{(data) => ...}</AsyncContent>`

Renders the four states, once, correctly; and is where the accessibility work lives.

```tsx
<AsyncContent
  state={state}
  itemNoun="findings"
  isFiltered={hasFilters}
  onClearFilters={clearFilters}
>
  {(findings) => <FindingsList findings={findings} />}
</AsyncContent>
```

| Prop | Type | Notes |
|---|---|---|
| `state` | `UseAsyncDataResult<T>` | Passed whole, so `isRefreshing` cannot be miswired to the skeleton |
| `isEmpty` | `(data: T) => boolean` | Defaults to "array with no items" |
| `isFiltered` | `boolean` | Changes the empty copy and CTA. **Explicit**; see below |
| `onClearFilters` | `() => void` | Renders the *Clear filters* exit |
| `itemNoun` | `string` | Used in announcements: "Loaded 25 findings" |
| `skeletonCount` | `number` | Match your expected row count so the layout does not jump |
| `loadingFallback` | `ReactNode` | For non-list shapes |

What it contributes:

- **Status is announced.** Swapping a skeleton for a list is invisible to a screen reader.
  A polite live region reports "Loading findings", "Loaded 25 findings", "Failed to load".
  Polite, not assertive; loading a list should not interrupt what the user is reading.
- **`aria-busy` during refresh**, because a background refetch keeps old rows on screen with
  nothing visual signalling staleness.
- **Filtered-empty ≠ never-had-data.** "No findings match these filters" wants *clear filters*;
  "no findings yet" wants *run a scan*. Collapsing them produces the classic dead end where a
  new user is told to clear filters they never set. The component cannot infer which it is, so
  `isFiltered` is required rather than guessed.

### `useSelection(visibleIds)`

Multi-select for a paginated list.

```tsx
const visibleIds = useMemo(() => findings.map((f) => f.id), [findings]);
const selection = useSelection(visibleIds);
```

Returns `selected`, `selectedIds`, `count`, `isSelected`, `toggle`, `toggleAllVisible`,
`clear`, `allVisibleSelected`, `someVisibleSelected`.

**`visibleIds` is the page, and select-all acts on the page.** A control the user can see must
only act on rows the user can see. Bulk-acting on 1,300 unseen rows because a header checkbox
was ticked is how someone's afternoon gets ruined; and it was a real bug (#204) before this
was structural. Selections on other pages are preserved, so paging away and back does not
silently drop them.

### `<ListRow>` / `<ListRows>` / `<SelectAllVisible>`

```tsx
<ListRows>
  {items.map((item) => (
    <ListRow key={item.id} selectable selectLabel={`Select ${item.name}`}
             selected={selection.isSelected(item.id)}
             onSelectChange={(c) => selection.toggle(item.id, c)}>
      {/* row content */}
    </ListRow>
  ))}
</ListRows>
```

`ListRow` applies `py-0` to cancel the base Card's `py-6`; 48px that no density token can
reach. That was the actual cause of "Compact only saves 7%" in #172, and it had to be fixed
file by file. Here it is applied once.

`selectLabel` is required whenever `selectable` is set; a column of unlabelled checkboxes
announces as "checkbox, checkbox, checkbox". Omitting it warns in development.

`SelectAllVisible` handles `indeterminate`, which is a DOM property with no JSX attribute;
the detail every hand-rolled copy skipped, leaving a half-selected page showing an empty box.

### `<StatCard>` / `<StatGrid>`

```tsx
<StatGrid columns={4}>
  <StatCard label="Open findings" value={String(count)} icon={AlertTriangle}
            unknown={!lastScan} unknownHint="never scanned, posture unknown" />
</StatGrid>
```

`unknown` is a first-class variant, not decoration. Across this codebase the distinction
between *measured zero* and *not measured* keeps mattering; an unscanned repository is not a
clean one (#174), an ungenerated AIBOM is not an absence of models (#190). A stat card that
renders a confident `0` for missing data actively misinforms, so `unknown` renders an em dash
and a reason instead.

`value` is a `ReactNode`: a count with a severity breakdown beside it is a legitimate value,
and forcing callers to stringify pushed them back to hand-rolling the card.

### `<BulkActionBar>`

```tsx
<BulkActionBar count={selection.count} itemNoun="finding" onClear={selection.clear}
               actions={[{ label: "False Positive", onClick: ... }]}>
  <Input aria-label="Reason, applied to every selected finding" ... />
</BulkActionBar>
```

The count is wrapped in `role="status"`: selecting rows by keyboard changes a number a
screen-reader user otherwise never hears, so they cannot tell how many rows the next click
affects.

`destructive` marks a *specific* action, never the whole bar; #171 established that
over-using the destructive colour drains it of meaning.

---

## Best practices

**Drive skeletons from `isInitialLoading`, not `status`.** Otherwise every refetch blanks the
screen.

**Never render a confident zero for data you do not have.** Use `unknown` on `StatCard`, and
keep "never generated" separate from "generated and empty". This recurs throughout the app for
a reason: it is a security tool, and a false all-clear is the worst output it can produce.

**Give every checkbox an accessible name.** `selectLabel` on `ListRow` exists because this is
the single most commonly skipped a11y detail in list UIs.

**Pass `isFiltered` honestly.** A filtered-empty state offering no way back to the unfiltered
list is a dead end.

**Prefer URL state to component state** for anything a user might link to, tabs, page, page
size, filters. See `target-tabs.tsx`; the Admin page's `useState` tabs are the counter-example
that cannot be linked to.

**Shared values used by Server Components go in a plain module.** Never export a constant or
function from a `"use client"` file and import it server-side; it becomes a client reference
stub, and for a constant it fails *silently*. This bit twice (#196, #204) and is now enforced
by a lint rule (`toleman/no-client-value-import-in-server`).

### When not to reach for L2

- **A one-off.** Wait for the third occurrence; two is a coincidence.
- **Server Components.** `useAsyncData` is client-side. A Server Component should fetch
  directly and render; see `targets/[id]/page.tsx`.
- **Anything domain-aware.** If it needs to know what a finding is, it belongs in L3.

---

## Testing

```bash
npm test                 # vitest, jsdom
npm run test:lint-rules  # the custom ESLint rule's own tests
npm run lint:boundary    # client/server import boundary gate
```

Pure logic (`async-state.ts`) is tested as a reducer, exhaustively, no DOM. Components are
tested with Testing Library, and **accessibility is asserted rather than described**: live
region text, `aria-busy`, `indeterminate`, accessible names, and keyboard operability all have
tests. A component whose docblock claims it is accessible, with nothing asserting it, is not.
