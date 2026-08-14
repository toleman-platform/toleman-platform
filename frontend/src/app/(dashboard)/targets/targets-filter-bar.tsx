"use client";

import { useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

const CRITICALITY_OPTIONS = ["Prod", "Internal", "Dev"];

const SELECT_CLASS =
  "h-8 rounded-md border border-input bg-secondary px-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring";

// Issue #125: same search + facet-select convention as Scans'
// scans-filter-bar.tsx -- driving URL search params rather than a bespoke
// widget for this page. `search` filters client-side in targets-list.tsx
// (name/repo_url), `criticality` filters on Target.label. `group_id`
// (repo-group filter) stays a separate server-refetching control
// (components/group-filter.tsx, issue #61) since it changes which targets
// the server returns, not just which of the already-fetched ones display.
export function TargetsFilterBar() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const [search, setSearch] = useState(searchParams.get("search") ?? "");

  function updateParam(key: string, value: string) {
    const params = new URLSearchParams(searchParams.toString());
    if (value) params.set(key, value);
    else params.delete(key);
    router.push(`${pathname}?${params.toString()}`);
  }

  function submitSearch(e: React.FormEvent) {
    e.preventDefault();
    updateParam("search", search);
  }

  const hasFilters = ["criticality", "search"].some((k) => searchParams.get(k));

  function clearAll() {
    setSearch("");
    const params = new URLSearchParams(searchParams.toString());
    params.delete("search");
    params.delete("criticality");
    router.push(`${pathname}?${params.toString()}`);
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <form onSubmit={submitSearch} className="flex min-w-[220px] flex-1 items-center gap-2">
        <Input
          className="h-8 bg-secondary text-xs"
          placeholder="Search target name, repo..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <Button type="submit" size="sm" variant="outline" className="h-8 text-xs">
          Search
        </Button>
      </form>

      <select
        aria-label="Filter by criticality"
        className={SELECT_CLASS}
        value={searchParams.get("criticality") ?? ""}
        onChange={(e) => updateParam("criticality", e.target.value)}
      >
        <option value="">All criticality</option>
        {CRITICALITY_OPTIONS.map((c) => (
          <option key={c} value={c}>
            {c}
          </option>
        ))}
      </select>

      {hasFilters && (
        <button onClick={clearAll} className="text-xs text-muted-foreground underline hover:text-foreground">
          Clear filters
        </button>
      )}
    </div>
  );
}
