"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { DateRangeFilter } from "@/components/date-range-filter";

const SELECT_CLASS =
  "h-8 rounded-md border border-input bg-secondary px-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring";

export function AuditLogFilterBar({ actors }: { actors: string[] }) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  function updateParam(key: string, value: string) {
    const params = new URLSearchParams(searchParams.toString());
    if (value) params.set(key, value);
    else params.delete(key);
    params.delete("page");
    router.push(`${pathname}?${params.toString()}`);
  }

  const hasFilters = ["event_type", "actor", "date_from", "date_to"].some((k) => searchParams.get(k));

  return (
    <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-card p-3">
      <select
        aria-label="Filter by event type"
        className={SELECT_CLASS}
        value={searchParams.get("event_type") ?? ""}
        onChange={(e) => updateParam("event_type", e.target.value)}
      >
        <option value="">All event types</option>
        <option value="triage">Triage</option>
        <option value="scan">Scan</option>
      </select>

      <select
        aria-label="Filter by actor"
        className={SELECT_CLASS}
        value={searchParams.get("actor") ?? ""}
        onChange={(e) => updateParam("actor", e.target.value)}
      >
        <option value="">All actors</option>
        {actors.map((a) => (
          <option key={a} value={a}>
            {a}
          </option>
        ))}
      </select>

      <DateRangeFilter />

      {hasFilters && (
        <button onClick={() => router.push(pathname)} className="text-xs text-muted-foreground underline hover:text-foreground">
          Clear filters
        </button>
      )}
    </div>
  );
}
