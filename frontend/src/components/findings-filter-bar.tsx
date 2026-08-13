"use client";

import { useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Group, Target } from "@/lib/api";
import { SEVERITY_ORDER } from "@/lib/severity";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { GroupFilter } from "@/components/group-filter";

const STATES = ["Open", "Accepted Risk", "False Positive", "Won't Fix", "Mitigated", "Reopened"];

const SELECT_CLASS =
  "h-8 rounded-md border border-input bg-secondary px-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring";

export function FindingsFilterBar({ targets, tools, groups }: { targets: Target[]; tools: string[]; groups: Group[] }) {
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

  const hasFilters = ["severity", "tool", "state", "target_id", "group_id", "search"].some((k) => searchParams.get(k));

  function clearAll() {
    setSearch("");
    router.push(pathname);
  }

  return (
    <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-card p-3">
      <form onSubmit={submitSearch} className="flex min-w-[220px] flex-1 items-center gap-2">
        <Input
          className="h-8 bg-secondary text-xs"
          placeholder="Search title, file path, rule id..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <Button type="submit" size="sm" variant="outline" className="h-8 text-xs">
          Search
        </Button>
      </form>

      <select
        aria-label="Filter by severity"
        className={SELECT_CLASS}
        value={searchParams.get("severity") ?? ""}
        onChange={(e) => updateParam("severity", e.target.value)}
      >
        <option value="">All severities</option>
        {SEVERITY_ORDER.map((s) => (
          <option key={s} value={s}>
            {s}
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
        aria-label="Filter by state"
        className={SELECT_CLASS}
        value={searchParams.get("state") ?? ""}
        onChange={(e) => updateParam("state", e.target.value)}
      >
        <option value="">All states</option>
        {STATES.map((s) => (
          <option key={s} value={s}>
            {s}
          </option>
        ))}
      </select>

      <select
        aria-label="Filter by target"
        className={SELECT_CLASS}
        value={searchParams.get("target_id") ?? ""}
        onChange={(e) => updateParam("target_id", e.target.value)}
      >
        <option value="">All targets</option>
        {targets.map((t) => (
          <option key={t.id} value={t.id}>
            {t.name}
          </option>
        ))}
      </select>

      {groups.length > 0 && <GroupFilter groups={groups} />}

      {hasFilters && (
        <button onClick={clearAll} className="text-xs text-muted-foreground underline hover:text-foreground">
          Clear filters
        </button>
      )}
    </div>
  );
}
