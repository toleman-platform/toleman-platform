"use client";

import { useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { FacetCount, FindingFacets, FindingFilterOptions, Group, Target } from "@/lib/api";
import { SEVERITY_ORDER } from "@/lib/severity";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { GroupFilter } from "@/components/features/targets";
import { MultiSelectFilter } from "@/components/multi-select-filter";
import { FacetFilter, type FacetOption } from "@/components/facet-filter";

// Open queues and the Resolved queue offer different states to filter
// within (see findings/page.tsx's queue tabs): picking "Mitigated" while
// looking at open findings would be a dead end, so the option isn't shown
// there at all rather than silently doing nothing.
const OPEN_STATES = ["Open", "Reopened"];
const RESOLVED_STATES = ["Accepted Risk", "False Positive", "Won't Fix", "Mitigated"];

// (#246) "Which of these can I close today?", the question severity cannot
// answer. "Unknown" is offered as its own choice rather than folded into
// "No known fix": for most SAST and secrets findings we have no advisory to
// look up, and claiming there is no fix for a hardcoded secret would be
// plainly wrong.
const FIXABILITY_LABELS: Record<string, string> = {
  fixable: "Fix available",
  no_known_fix: "No known fix",
  unknown: "Fixability unknown",
};

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

// Every filter param the bar drives, for "Clear filters". `category`,
// `queue`, `view` and `sort` are deliberately absent: the first two are
// locations (the queue tabs, the category tabs) and the last two are
// presentation, so clearing filters refines within the view the reader is
// looking at rather than navigating them out of it.
const FILTER_PARAMS = [
  "severity",
  "state",
  "tool",
  "fixability",
  "environment",
  "owner",
  "target_id",
  "group_id",
  "search",
  "new_since_days",
];

// Turns the API's `[{ value, count }]` into the pill list, in the order
// given, with any value the API didn't count treated as a real zero rather
// than dropped -- "nothing matches this right now" is information, and it
// is not the same as the dimension being absent (#270).
function facetOptions(
  counts: FacetCount[] | null,
  values: string[] | null,
  labelFor: (value: string) => string = (v) => v,
): FacetOption[] {
  // `counts === null` is the degraded path: the facets call failed, so the
  // options come from elsewhere and carry no numbers. Every count is then
  // null rather than 0 -- "we could not count" is not "nothing matches".
  const rows = counts ?? [];
  const byValue = new Map(rows.map((row) => [row.value, row.count]));
  // `values === null` means "whatever the API found" (tools, owners,
  // environments: open-ended sets the backend enumerates from real data).
  // A fixed list means the dimension is a closed enum the UI knows up
  // front, and every rung of it should be visible even at zero.
  const ordered = values ?? rows.map((row) => row.value);
  return ordered.map((value) => ({
    value,
    label: labelFor(value),
    count: counts === null ? null : (byValue.get(value) ?? 0),
  }));
}

export function FindingsFilterBar({
  targets,
  groups,
  facets,
  fallbackOptions,
  resolved,
  grouped = true,
  sort = "exploitability",
}: {
  targets: Target[];
  groups: Group[];
  // (#270) Live per-value counts for every dimension, already scoped by the
  // other active filters (see app/api/findings.py::list_finding_facets).
  // Supplied by the Findings page rather than fetched here so the page
  // stays a Server Component and the counts arrive with the list they
  // describe, not one render later.
  //
  // `null` when that one call failed. Before #270 these were several
  // independent calls with independent catches, so losing one lost one
  // control; folding them into a single request must not turn that into
  // losing the Tool, Environment and Owner controls at once -- so the bar
  // falls back to the plain option lists and renders the same controls
  // without their numbers.
  facets: FindingFacets | null;
  fallbackOptions: FindingFilterOptions | null;
  // Which findings the active queue is showing: false = open, true =
  // resolved. Narrows the State filter's own options to match (see
  // OPEN_STATES / RESOLVED_STATES above).
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

  function toggleParam(key: string, value: string) {
    updateParam(key, searchParams.get(key) === value ? "" : value);
  }

  const hasFilters = FILTER_PARAMS.some((k) => searchParams.getAll(k).length > 0);
  const newOnly = searchParams.get("new_since_days") !== null;

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
    <div className="flex flex-col gap-3 rounded-md border border-border bg-card p-3">
      <div className="flex flex-wrap items-center gap-2">
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

        {/* Targets and groups stay dropdowns: a real instance has 35 repos,
            and 35 pills would be a scrolling wall rather than a summary.
            The dimensions #270 turns into counted pills are the ones whose
            option sets are small and bounded enough to read at a glance. */}
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

      {/* Every counted dimension, laid out uniformly. Doing this to one
          facet and leaving the rest as dropdowns would be worse than not
          doing it at all: the bar would read as two unrelated controls
          stacked together, and you would still have to open something to
          learn what is in it. */}
      <div className="grid gap-x-6 gap-y-3 border-t border-border pt-3 sm:grid-cols-2 lg:grid-cols-3">
        <FacetFilter
          label="Severity"
          paramKey="severity"
          options={facetOptions(facets && facets.severity, SEVERITY_ORDER)}
        />
        <FacetFilter
          label="Fixability"
          paramKey="fixability"
          options={facetOptions(
            facets && facets.fixability,
            ["fixable", "no_known_fix", "unknown"],
            (value) => FIXABILITY_LABELS[value] ?? value,
          )}
        />
        <FacetFilter
          label="State"
          paramKey="state"
          options={facetOptions(facets && facets.state, resolved ? RESOLVED_STATES : OPEN_STATES)}
        />
        {/* The three open-ended dimensions: their option sets come from real
            data, so when the counts are gone the options have to come from
            somewhere -- the plain per-dimension endpoints -- or the control
            disappears along with any active filter it holds. */}
        <FacetFilter
          label="Tool"
          paramKey="tool"
          options={facetOptions(facets && facets.tool, facets ? null : (fallbackOptions?.tool ?? []))}
        />
        <FacetFilter
          label="Environment"
          paramKey="environment"
          options={facetOptions(
            facets && facets.environment,
            facets ? null : (fallbackOptions?.environment ?? []),
          )}
        />
        <FacetFilter
          label="Owner"
          paramKey="owner"
          options={facetOptions(facets && facets.owner, facets ? null : (fallbackOptions?.owner ?? []))}
        />
      </div>
    </div>
  );
}
