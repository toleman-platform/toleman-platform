"use client";

import { useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Group, Target } from "@/lib/api";
import { OPEN_FINDING_STATES, RESOLVED_FINDING_STATES, SEVERITY_ORDER } from "@/lib/severity";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { GroupFilter } from "@/components/features/targets";
import { MultiSelectFilter } from "@/components/multi-select-filter";

// Open-view and Resolved-view offer different states to filter within
// (see findings/page.tsx's Open/Resolved tabs): picking "Mitigated" while
// looking at Open findings would be a dead end, so the option isn't shown
// there at all rather than silently doing nothing. The two halves come from
// lib/severity.ts, which mirrors the backend's own split, rather than being
// spelled out again here.
const OPEN_STATES = OPEN_FINDING_STATES;
const RESOLVED_STATES = RESOLVED_FINDING_STATES;

// Ordering the list offers. `blast_radius` ("how many findings does this one
// decision close") is grouped-only: on a row that is a single detection the
// answer is always one, so offering it there would be a control that does
// nothing. `exploitability` leads because it is the existing default.
const SORTS: { value: string; label: string; groupedOnly?: boolean }[] = [
  { value: "exploitability", label: "Exploitability" },
  { value: "severity", label: "Severity" },
  { value: "blast_radius", label: "Blast radius", groupedOnly: true },
  { value: "age", label: "Oldest first" },
  { value: "recent", label: "Newest first" },
];

const NEW_SINCE_DAYS = "7";

export function FindingsFilterBar({
  targets,
  tools,
  groups,
  resolved,
  grouped = true,
  sort = "exploitability",
}: {
  targets: Target[];
  tools: string[];
  groups: Group[];
  // Which Findings page tab is active: false = Open, true = Resolved.
  // Narrows the State filter's own options to match (see OPEN_STATES /
  // RESOLVED_STATES above).
  resolved: boolean;
  /** True when the list shows one row per decision rather than per detection. */
  grouped?: boolean;
  sort?: string;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const [search, setSearch] = useState(searchParams.get("search") ?? "");

  function updateParam(key: string, value: string) {
    const params = new URLSearchParams(searchParams.toString());
    if (value) params.set(key, value);
    else params.delete(key);
    params.delete("page");
    router.push(`${pathname}?${params.toString()}`);
  }

  function submitSearch(e: React.FormEvent) {
    e.preventDefault();
    updateParam("search", search);
  }

  const hasFilters = [
    "severity",
    "tool",
    "state",
    "target_id",
    "group_id",
    "search",
    "fixability",
    "new_since_days",
  ].some((k) => searchParams.getAll(k).length > 0);
  const newOnly = searchParams.get("new_since_days") !== null;

  function toggleParam(key: string, value: string) {
    updateParam(key, searchParams.get(key) === value ? "" : value);
  }
  const stateOptions = (resolved ? RESOLVED_STATES : OPEN_STATES).map((s) => ({ value: s, label: s }));

  // "category" and "resolved" are deliberately not part of hasFilters/
  // clearAll: both are active tabs (FindingsCategoryTabs, the Open/
  // Resolved split), locations rather than filters, so clearing filters
  // refines within the current tab/view instead of navigating away from it.
  function clearAll() {
    setSearch("");
    const params = new URLSearchParams();
    // `queue`, `view`, `category` and `sort` are all locations or
    // presentation, not filters: clearing filters refines within the view the
    // reader is looking at rather than navigating them out of it.
    for (const key of ["category", "queue", "view", "sort"]) {
      const value = searchParams.get(key);
      if (value) params.set(key, value);
    }
    const qs = params.toString();
    router.push(qs ? `${pathname}?${qs}` : pathname);
  }

  return (
    <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-card p-3">
      <form onSubmit={submitSearch} className="flex min-w-[220px] flex-1 items-center gap-2">
        <Input
          className="h-8 bg-secondary text-xs"
          placeholder="Search title, file path, rule id..."
          aria-label="Search findings"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <Button type="submit" size="sm" variant="outline" className="h-8 text-xs">
          Search
        </Button>
      </form>

      {/* Grouping and ordering sit with the filters rather than above the
          list: all three change which rows appear and in what order, and
          splitting them across two bars makes the page feel like it has two
          unrelated sets of controls. */}
      <button
        type="button"
        onClick={() => updateParam("view", grouped ? "flat" : "")}
        aria-pressed={grouped}
        title={
          grouped
            ? "Showing one row per decision. Switch to one row per detection."
            : "Showing one row per detection. Switch to one row per decision."
        }
        className={`h-8 rounded-md border px-2.5 text-xs font-medium transition-colors ${
          grouped
            ? "border-primary/40 bg-primary/10 text-primary"
            : "border-border bg-secondary text-muted-foreground hover:text-foreground"
        }`}
      >
        {grouped ? "Grouped" : "Ungrouped"}
      </button>

      <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
        <span className="sr-only sm:not-sr-only">Sort</span>
        <select
          aria-label="Sort findings"
          value={sort}
          onChange={(e) => updateParam("sort", e.target.value === "exploitability" ? "" : e.target.value)}
          className="h-8 rounded-md border border-border bg-secondary px-2 text-xs text-foreground"
        >
          {SORTS.filter((s) => grouped || !s.groupedOnly).map((s) => (
            <option key={s.value} value={s.value}>
              {s.label}
            </option>
          ))}
        </select>
      </label>

      {/* first_seen has been on every finding since the beginning and nothing
          in the UI ever asked about it. "What landed since I last looked" is
          the question that turns a 150-item backlog into a morning routine. */}
      <button
        type="button"
        onClick={() => toggleParam("new_since_days", NEW_SINCE_DAYS)}
        aria-pressed={newOnly}
        className={`h-8 rounded-md border px-2.5 text-xs font-medium transition-colors ${
          newOnly
            ? "border-primary/40 bg-primary/10 text-primary"
            : "border-border bg-secondary text-muted-foreground hover:text-foreground"
        }`}
      >
        New this week
      </button>

      <MultiSelectFilter
        label="All severities"
        paramKey="severity"
        options={SEVERITY_ORDER.map((s) => ({ value: s, label: s }))}
      />

      {/* (#246) "Which of these can I close today?", the question severity
          cannot answer. "Unknown" is offered as its own choice rather than
          folded into "No known fix": for most SAST and secrets findings we
          have no advisory to look up, and claiming there is no fix for a
          hardcoded secret would be plainly wrong. */}
      <MultiSelectFilter
        label="Any fixability"
        paramKey="fixability"
        options={[
          { value: "fixable", label: "Fix available" },
          { value: "no_known_fix", label: "No known fix" },
          { value: "unknown", label: "Fixability unknown" },
        ]}
      />

      <MultiSelectFilter label="All tools" paramKey="tool" options={tools.map((t) => ({ value: t, label: t }))} />

      <MultiSelectFilter label="All states" paramKey="state" options={stateOptions} />

      <MultiSelectFilter
        label="All targets"
        paramKey="target_id"
        options={targets.map((t) => ({ value: String(t.id), label: t.name }))}
      />

      {groups.length > 0 && <GroupFilter groups={groups} />}

      {hasFilters && (
        <button onClick={clearAll} className="text-xs text-muted-foreground underline hover:text-foreground">
          Clear filters
        </button>
      )}
    </div>
  );
}
