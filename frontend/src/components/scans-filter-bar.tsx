"use client";

import { useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

const CRITICALITY_OPTIONS = ["Prod", "Internal", "Dev"];

// "Last scanned" buckets computed client-side against each target's real
// scan-summary timestamp (GET /api/scans/summary) -- see scans-list.tsx.
export const LAST_SCANNED_OPTIONS = [
  { value: "24h", label: "Last 24h" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
  { value: "older", label: "Older than 30 days" },
  { value: "never", label: "Never scanned" },
];

const SELECT_CLASS =
  "h-8 rounded-md border border-input bg-secondary px-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring";

// Issue #120: same filter-bar convention as Findings
// (components/findings-filter-bar.tsx) -- search + a row of `<select>`
// facets driving URL search params, not a bespoke widget for this one page.
// Scans additionally filters by criticality (the whole point of this
// rebuild -- surfacing Prod vs Internal vs Dev) and last-scanned, instead of
// Findings' severity/state.
export function ScansFilterBar({ tools }: { tools: string[] }) {
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

  const hasFilters = ["criticality", "tool", "last_scanned", "search"].some((k) => searchParams.get(k));

  function clearAll() {
    setSearch("");
    router.push(pathname);
  }

  return (
    <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-card p-3">
      <form onSubmit={submitSearch} className="flex min-w-[220px] flex-1 items-center gap-2">
        <Input
          className="h-8 bg-secondary text-xs"
          placeholder="Search target name, repo, tag..."
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

      <select
        aria-label="Filter by tool"
        className={SELECT_CLASS}
        value={searchParams.get("tool") ?? ""}
        onChange={(e) => updateParam("tool", e.target.value)}
      >
        <option value="">All tools</option>
        {tools.map((t) => (
          <option key={t} value={t}>
            {t}
          </option>
        ))}
      </select>

      <select
        aria-label="Filter by last scanned"
        className={SELECT_CLASS}
        value={searchParams.get("last_scanned") ?? ""}
        onChange={(e) => updateParam("last_scanned", e.target.value)}
      >
        <option value="">Last scanned</option>
        {LAST_SCANNED_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
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
