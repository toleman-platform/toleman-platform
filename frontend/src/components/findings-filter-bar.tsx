"use client";

import { useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Group, Target } from "@/lib/api";
import { SEVERITY_ORDER } from "@/lib/severity";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { GroupFilter } from "@/components/group-filter";
import { MultiSelectFilter } from "@/components/multi-select-filter";

// Open-view and Resolved-view offer different states to filter within
// (see findings/page.tsx's Open/Resolved tabs): picking "Mitigated" while
// looking at Open findings would be a dead end, so the option isn't shown
// there at all rather than silently doing nothing.
const OPEN_STATES = ["Open", "Reopened"];
const RESOLVED_STATES = ["Accepted Risk", "False Positive", "Won't Fix", "Mitigated"];

export function FindingsFilterBar({
  targets,
  tools,
  groups,
  resolved,
}: {
  targets: Target[];
  tools: string[];
  groups: Group[];
  // Which Findings page tab is active: false = Open, true = Resolved.
  // Narrows the State filter's own options to match (see OPEN_STATES /
  // RESOLVED_STATES above).
  resolved: boolean;
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

  const hasFilters = ["severity", "tool", "state", "target_id", "group_id", "search", "fixability"].some(
    (k) => searchParams.getAll(k).length > 0
  );
  const stateOptions = (resolved ? RESOLVED_STATES : OPEN_STATES).map((s) => ({ value: s, label: s }));

  // "category" and "resolved" are deliberately not part of hasFilters/
  // clearAll: both are active tabs (FindingsCategoryTabs, the Open/
  // Resolved split), locations rather than filters, so clearing filters
  // refines within the current tab/view instead of navigating away from it.
  function clearAll() {
    setSearch("");
    const params = new URLSearchParams();
    const category = searchParams.get("category");
    const resolvedParam = searchParams.get("resolved");
    if (category) params.set("category", category);
    if (resolvedParam) params.set("resolved", resolvedParam);
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
